package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// 纯映射测试:台账行 → session_open 入参。WebShell 是 URL 型目标,端口/用户名
// 都不该传给会话;数据库的库名走 options。
func TestSessionOpenInputFromLedgerRow(t *testing.T) {
	shell := &db.Connection{
		Kind: "webshell", Host: "127.0.0.1", Port: 18080, Secret: "capkit",
		Extra: json.RawMessage(`{"url":"http://127.0.0.1:18080/lab.php","cmd_param":"exec","pass_param":"pw","method":"POST","shell_type":"php"}`),
	}
	raw, err := sessionOpenInputFor(shell)
	if err != nil {
		t.Fatalf("webshell 映射失败: %v", err)
	}
	var in struct {
		Kind    string            `json:"kind"`
		Host    string            `json:"host"`
		Port    int               `json:"port"`
		User    string            `json:"user"`
		Secret  string            `json:"secret"`
		Options map[string]string `json:"options"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if in.Host != "http://127.0.0.1:18080/lab.php" {
		t.Fatalf("webshell 的 host 应是落点 URL, got %q", in.Host)
	}
	if in.Port != 0 || in.User != "" {
		t.Fatalf("URL 型目标不应带端口/用户名: %+v", in)
	}
	if in.Options["cmd_param"] != "exec" || in.Options["pass_param"] != "pw" || in.Options["method"] != "POST" {
		t.Fatalf("协议参数未透传: %+v", in.Options)
	}

	// 缺 URL 必须报错而不是拿 host/port 硬开。
	if _, err := sessionOpenInputFor(&db.Connection{Kind: "webshell", Host: "127.0.0.1"}); err == nil {
		t.Fatalf("缺 extra.url 应报错")
	}

	pg := &db.Connection{
		Kind: "postgres", Host: "127.0.0.1", Port: 15432, Username: "capkit", Secret: "capkit",
		Extra: json.RawMessage(`{"database":"app"}`),
	}
	raw, err = sessionOpenInputFor(pg)
	if err != nil {
		t.Fatalf("postgres 映射失败: %v", err)
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if in.Options["database"] != "app" || in.Port != 15432 || in.Host != "127.0.0.1" {
		t.Fatalf("数据库映射不符: %+v", in)
	}
}

// 端到端(需库):登记一条 WebShell 台账 → 从台账开会话 → 归属跟着台账项目走,
// 重复调用复用同一个会话。
func TestSessionFromLedgerConnectionOpensAndReuses(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	stamp := time.Now().UnixNano()
	// 目标要落在测试桥接放行的 scope(127.0.0.1)内;端口取随机值保证唯一键不撞。
	host := "127.0.0.1"
	port := 18000 + int(stamp%1000)
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("台账开会话%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)

	connID, _, err := m.pg.UpsertConnection(context.Background(), &db.Connection{
		ProjectID: p.ID, Kind: "webshell", Host: host, Port: port, Secret: "capkit",
		Source: "manual", Status: "unknown",
		Extra: json.RawMessage(fmt.Sprintf(`{"url":"http://%s:%d/lab.php","cmd_param":"cmd"}`, host, port)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM connections WHERE id=$1`, connID) }()

	s := &Server{m: m, capkitBridge: apitestBridge(t)}
	body := fmt.Sprintf(`{"connection_id":%d}`, connID)

	open := func() map[string]any {
		r := httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/from-connection", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.capkitSessionFromConnection(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("from-connection: %d %s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	first := open()
	if first["reused"] == true {
		t.Fatalf("首次应新开会话: %+v", first)
	}
	sid, _ := first["id"].(string)
	if sid == "" {
		t.Fatalf("未返回 session_id: %+v", first)
	}
	// 会话归属必须是台账行所属项目,不是调用者的 scope。
	if owner, ok := s.capkitBridge.SessionProject(sid); !ok || owner != p.ID {
		t.Fatalf("会话应归属项目 %d, got %d (ok=%v)", p.ID, owner, ok)
	}

	second := open()
	if second["reused"] != true || second["id"] != sid {
		t.Fatalf("重复调用应复用同一会话: %+v vs %s", second, sid)
	}
}
