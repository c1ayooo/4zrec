package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// testConnectionsDB 打开真实库(不可用则 skip),登记一个测试项目并在结束时清理。
func testConnectionsDB(t *testing.T) (*DB, int64) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	p, err := d.Projects().CreateProject(fmt.Sprintf("连接台账测试%d", time.Now().UnixNano()), nil, "")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM connections WHERE project_id=$1`, p.ID)
		_ = d.Projects().DeleteProject(p.ID)
	})
	return d, p.ID
}

// webshellConns 取项目下所有 webshell 行,以落点 URL 为键。
func webshellConns(t *testing.T, d *DB, projectID int64) map[string]*Connection {
	t.Helper()
	rows, err := d.ListConnections(context.Background(), projectID, "webshell", 500)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	out := map[string]*Connection{}
	for _, c := range rows {
		if u := WebshellURLOf(c); u != "" {
			out[u] = c
		}
	}
	return out
}

// TestUpsertConnectionKindNormalization kind 归一化 + 缺省 source/status/端口,
// 与 handler 和自动捕获路径的契约对齐。
func TestUpsertConnectionKindNormalization(t *testing.T) {
	d, projectID := testConnectionsDB(t)
	id, created, err := d.UpsertConnection(context.Background(), &Connection{
		ProjectID: projectID, Kind: "SSH", Host: "norm.internal", Username: "root", Secret: "pw",
	})
	if err != nil || !created {
		t.Fatalf("upsert: created=%v err=%v", created, err)
	}
	rows, err := d.ListConnections(context.Background(), projectID, "", 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list: %d %v", len(rows), err)
	}
	got := rows[0]
	if got.ID != id || got.Kind != "ssh" || got.Source != "manual" || got.Status != "unknown" || got.Port != 22 {
		t.Fatalf("normalization wrong: %+v", got)
	}
}

// TestUpsertWebshellKeyedByURL 同一台机器同一端口上的多个 shell 必须各占一行,
// 落点相同则合并(口令覆盖、空口令不覆盖)。
func TestUpsertWebshellKeyedByURL(t *testing.T) {
	d, projectID := testConnectionsDB(t)
	ctx := context.Background()
	shell := func(rawURL, secret, status string) *Connection {
		return &Connection{
			ProjectID: projectID, Kind: "webshell", Host: "10.0.0.1", Port: 8080,
			Secret: secret, Source: "discovered", Status: status,
			Extra: json.RawMessage(fmt.Sprintf(`{"url":%q,"cmd_param":"c","pass_param":"k"}`, rawURL)),
		}
	}

	// 两个不同落点 → 两行(旧的整体唯一键会把它们合并成一条)。
	if _, _, err := d.UpsertConnection(ctx, shell("http://10.0.0.1:8080/a.jsp", "k1", "alive")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.UpsertConnection(ctx, shell("http://10.0.0.1:8080/b.jsp", "k2", "alive")); err != nil {
		t.Fatal(err)
	}
	byURL := webshellConns(t, d, projectID)
	if len(byURL) != 2 {
		t.Fatalf("want 2 webshell rows, got %d", len(byURL))
	}
	if byURL["http://10.0.0.1:8080/a.jsp"].Secret != "k1" {
		t.Fatalf("first shell secret lost")
	}

	// 同一落点重录(新口令)→ 合并成一行,口令更新。
	if _, created, err := d.UpsertConnection(ctx, shell("http://10.0.0.1:8080/a.jsp", "k1-new", "alive")); err != nil || created {
		t.Fatalf("re-record must merge: created=%v err=%v", created, err)
	}
	byURL = webshellConns(t, d, projectID)
	if len(byURL) != 2 || byURL["http://10.0.0.1:8080/a.jsp"].Secret != "k1-new" {
		t.Fatalf("secret not updated: %+v", byURL["http://10.0.0.1:8080/a.jsp"])
	}

	// 空口令 + unknown 状态重录 → 保留原口令与 alive。
	if _, _, err := d.UpsertConnection(ctx, shell("http://10.0.0.1:8080/a.jsp", "", "unknown")); err != nil {
		t.Fatal(err)
	}
	if got := webshellConns(t, d, projectID)["http://10.0.0.1:8080/a.jsp"]; got.Secret != "k1-new" || got.Status != "alive" {
		t.Fatalf("blank secret must not overwrite: %+v", got)
	}
}

// TestNormalizeWebshellURL scheme/大小写/fragment 归一化:同一落点的不同写法
// 必须命中同一行,否则台账会重复。
func TestNormalizeWebshellURL(t *testing.T) {
	cases := map[string]string{
		"http://Host.COM:8080/a.jsp": "http://host.com:8080/a.jsp",
		"10.0.0.1/a.jsp":             "http://10.0.0.1/a.jsp",
		"HTTP://10.0.0.1/a.jsp#frag": "http://10.0.0.1/a.jsp",
		"  http://10.0.0.1/a.jsp  ":  "http://10.0.0.1/a.jsp",
		"":                           "",
	}
	for in, want := range cases {
		if got := NormalizeWebshellURL(in); got != want {
			t.Errorf("NormalizeWebshellURL(%q) = %q, want %q", in, got, want)
		}
	}

	d, projectID := testConnectionsDB(t)
	ctx := context.Background()
	first := &Connection{ProjectID: projectID, Kind: "webshell", Host: "h", Secret: "s1",
		Extra: json.RawMessage(`{"url":"http://Target.LOCAL/a.php"}`)}
	if _, _, err := d.UpsertConnection(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := &Connection{ProjectID: projectID, Kind: "webshell", Host: "target.local", Secret: "s2",
		Extra: json.RawMessage(`{"url":"TARGET.local/a.php"}`)}
	if _, created, err := d.UpsertConnection(ctx, second); err != nil || created {
		t.Fatalf("same shell written twice: created=%v err=%v", created, err)
	}
	rows, err := d.ListConnections(ctx, projectID, "webshell", 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("want 1 row, got %d: %v", len(rows), err)
	}
	if rows[0].Secret != "s2" {
		t.Fatalf("secret not merged: %+v", rows[0])
	}
	if got := WebshellURLOf(rows[0]); got != "http://target.local/a.php" {
		t.Fatalf("stored url = %q", got)
	}
}

// TestUpsertConnectionNonShellUnaffected 普通凭据的唯一键语义不受 webshell
// 分叉影响:同键合并、跨端口不合并。
func TestUpsertConnectionNonShellUnaffected(t *testing.T) {
	d, projectID := testConnectionsDB(t)
	ctx := context.Background()
	base := &Connection{ProjectID: projectID, Kind: "ssh", Host: "10.0.0.2", Port: 22, Username: "root", Secret: "pw"}
	if _, created, err := d.UpsertConnection(ctx, base); err != nil || !created {
		t.Fatalf("first: created=%v err=%v", created, err)
	}
	if _, created, err := d.UpsertConnection(ctx, &Connection{
		ProjectID: projectID, Kind: "ssh", Host: "10.0.0.2", Port: 22, Username: "root", Secret: "pw2",
	}); err != nil || created {
		t.Fatalf("same key must merge: created=%v err=%v", created, err)
	}
	// 不同端口 → 不同行(一台主机两个 sshd)。
	if _, created, err := d.UpsertConnection(ctx, &Connection{
		ProjectID: projectID, Kind: "ssh", Host: "10.0.0.2", Port: 2222, Username: "root", Secret: "pw",
	}); err != nil || !created {
		t.Fatalf("other port must be a new row: created=%v err=%v", created, err)
	}
	rows, err := d.ListConnections(ctx, projectID, "ssh", 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d: %v", len(rows), err)
	}
	byPort := map[int]string{}
	for _, c := range rows {
		byPort[c.Port] = c.Secret
	}
	if byPort[22] != "pw2" || byPort[2222] != "pw" {
		t.Fatalf("merge semantics wrong: %v", byPort)
	}
}
