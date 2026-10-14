package db

import (
	"context"
	"strings"
	"testing"
)

// 本文件用例真连 PostgreSQL（无库时跳过），覆盖：
//   - sync_state 水位只前进不后退（施工单变更1）
//   - agent_visibility 工具级授权 + 整服务器行语义（变更0）
//   - CompanyAssetSummary 摘要口径（变更3）

func syncStateTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestSyncStateWatermarkMonotonic(t *testing.T) {
	d := syncStateTestDB(t)
	ctx := context.Background()
	m := &MCPServer{Name: "测试同步源-" + t.Name(), Transport: "http", URL: "http://127.0.0.1:1", Enabled: true}
	id, err := d.SaveMCP(m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteMCP(id) })

	st, err := d.SyncStateFor(ctx, id, "subdomain")
	if err != nil || st.Watermark != "" {
		t.Fatalf("fresh state should be empty: st=%+v err=%v", st, err)
	}

	st.Watermark = "2026-10-14 12:00:00"
	st.LastResult = "inc +3 items"
	if err := d.SaveSyncState(ctx, st); err != nil {
		t.Fatal(err)
	}

	// 回写旧水位（空结果轮）不得倒退。
	st.Watermark = "2026-10-13 00:00:00"
	st.LastResult = "inc +0 items"
	if err := d.SaveSyncState(ctx, st); err != nil {
		t.Fatal(err)
	}
	got, err := d.SyncStateFor(ctx, id, "subdomain")
	if err != nil {
		t.Fatal(err)
	}
	if got.Watermark != "2026-10-14 12:00:00" {
		t.Fatalf("watermark regressed: %q", got.Watermark)
	}
	if got.LastResult != "inc +0 items" || got.LastRunAt == nil {
		t.Fatalf("last_run not recorded: %+v", got)
	}

	if _, err := d.LatestSyncRun(ctx); err != nil {
		t.Fatalf("LatestSyncRun: %v", err)
	}
}

// 工具级行限制可见集合；整服务器行（mcp_tool_name 留空）恢复全量。DO NOTHING 冲突
// 语义：已有行（含被关掉的）不被播种翻动。
func TestAgentVisibleMCPToolGrants(t *testing.T) {
	d := syncStateTestDB(t)
	m := &MCPServer{Name: "测试授权源-" + t.Name(), Transport: "http", Enabled: true}
	id, err := d.SaveMCP(m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteMCP(id) })
	a, err := d.GetAgentByKey("planner")
	if err != nil || a == nil {
		t.Skipf("planner agent missing: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM agent_visibility WHERE agent_id=$1 AND resource_kind='mcp' AND resource_id=$2`, a.ID, id)
	})

	// 1) 只授两个工具。
	if err := d.GrantMCPTools(a.ID, id, []string{"list_assets", "count_assets"}); err != nil {
		t.Fatal(err)
	}
	tools, whole, err := d.AgentVisibleMCP(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if whole[id] {
		t.Fatal("no whole-server row should exist")
	}
	if len(tools[id]) != 2 || !tools[id]["list_assets"] || !tools[id]["count_assets"] {
		t.Fatalf("tool grants = %v", tools[id])
	}

	// 2) 再播一遍（幂等，不翻动已有行）。
	if err := d.GrantMCPTools(a.ID, id, []string{"list_assets"}); err != nil {
		t.Fatal(err)
	}
	tools, _, _ = d.AgentVisibleMCP(a.ID)
	if len(tools[id]) != 2 {
		t.Fatalf("re-grant should be idempotent, got %v", tools[id])
	}

	// 3) 加一条整服务器行 → 全量语义（wholeServers 命中）。
	if err := d.ToggleVisibility(a.ID, "mcp", id, true); err != nil {
		t.Fatal(err)
	}
	tools, whole, err = d.AgentVisibleMCP(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !whole[id] {
		t.Fatal("whole-server row must win over tool rows")
	}
	if len(tools[id]) != 2 {
		t.Fatalf("tool rows should still be readable, got %v", tools[id])
	}

	// 4) UI 关掉 → 行全删（含工具行）。
	if err := d.ToggleVisibility(a.ID, "mcp", id, false); err != nil {
		t.Fatal(err)
	}
	tools, whole, err = d.AgentVisibleMCP(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if whole[id] || len(tools[id]) != 0 {
		t.Fatalf("visibility off should clear everything: whole=%v tools=%v", whole[id], tools[id])
	}
}

func TestCompanyAssetSummary(t *testing.T) {
	d := syncStateTestDB(t)
	ctx := context.Background()
	cs := d.Companies()
	cid, err := cs.UpsertByName("摘要测试公司-" + strings.ReplaceAll(t.Name(), "/", "_"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM companies WHERE id=$1`, cid) })
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE company_id=$1`, cid) })

	// 白盒直插资产（走真实 upsert 需要公司 scope 归因链，此处只验证摘要口径）。
	seed := []string{
		`INSERT INTO assets(type, company_id, domain) VALUES ('root_domain', $1, 'summary-test.example')`,
		`INSERT INTO assets(type, company_id, domain) VALUES ('subdomain', $1, 'a.summary-test.example')`,
		`INSERT INTO assets(type, company_id, url, service_type, status_code, page_title, technologies)
		 VALUES ('service', $1, 'https://a.summary-test.example', 'http', 200, '门户', '{"Nginx","jQuery"}')`,
		`INSERT INTO assets(type, company_id, url, service_type, status_code)
		 VALUES ('service', $1, 'https://dead.summary-test.example', 'http', 503)`,
	}
	for _, q := range seed {
		if _, err := d.Exec(q, cid); err != nil {
			t.Fatalf("seed %s: %v", q, err)
		}
	}
	as := d.Assets()
	sum := as.CompanyAssetSummary(ctx, []int64{cid})
	for _, want := range []string{
		"摘要测试公司",
		"subdomain:1",
		"root_domain:1",
		"service:2",
		"https://a.summary-test.example [200] 门户",
		"summary-test.example",
		"Nginx:1",
		"source=4zrecon sync",
	} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary missing %q:\n%s", want, sum)
		}
	}
	if strings.Contains(sum, "dead.summary-test.example") {
		t.Errorf("dead site (503) should not appear in alive top:\n%s", sum)
	}

	// 空公司/无资产 → 空串（模板条件块吞掉）。
	if got := as.CompanyAssetSummary(ctx, nil); got != "" {
		t.Errorf("nil companies should yield empty summary, got %q", got)
	}
	if got := as.CompanyAssetSummary(ctx, []int64{-999}); got != "" {
		t.Errorf("no-asset company should yield empty summary, got %q", got)
	}
}

// 防呆：ListSyncState 在无行时返回空切片不报错。
func TestListSyncStateEmpty(t *testing.T) {
	d := syncStateTestDB(t)
	rows, err := d.ListSyncState(context.Background(), -1)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
}

// 对账计数回写与水位重置（施工单变更1兜底）。Reset 刻意绕开 Save 的只前进语义。
func TestSyncCountersAndWatermarkReset(t *testing.T) {
	d := syncStateTestDB(t)
	ctx := context.Background()
	m := &MCPServer{Name: "测试对账-" + t.Name(), Transport: "http", URL: "http://127.0.0.1:1", Enabled: true}
	id, err := d.SaveMCP(m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteMCP(id) })

	st, err := d.SyncStateFor(ctx, id, "subdomain")
	if err != nil {
		t.Fatal(err)
	}
	st.Watermark = "2026-10-14 12:00:00"
	st.UpstreamTotal = 1000
	st.IncTaken = 30
	if err := d.SaveSyncState(ctx, st); err != nil {
		t.Fatal(err)
	}
	got, err := d.SyncStateFor(ctx, id, "subdomain")
	if err != nil {
		t.Fatal(err)
	}
	if got.UpstreamTotal != 1000 || got.IncTaken != 30 {
		t.Fatalf("计数未落库: %+v", got)
	}

	// 对账回写：只动计数，不碰水位、不伪造 last_run_at 之外的状态
	if err := d.UpdateSyncCounters(ctx, id, "subdomain", 1500, 0); err != nil {
		t.Fatal(err)
	}
	got, _ = d.SyncStateFor(ctx, id, "subdomain")
	if got.UpstreamTotal != 1500 || got.IncTaken != 0 || got.Watermark != "2026-10-14 12:00:00" {
		t.Fatalf("对账回写失真: %+v", got)
	}

	// 水位重置必须能后退（绕开 Save 的只前进语义）
	if err := d.ResetSyncWatermark(ctx, id, "subdomain"); err != nil {
		t.Fatal(err)
	}
	got, _ = d.SyncStateFor(ctx, id, "subdomain")
	if got.Watermark != "" {
		t.Fatalf("水位应已清空: %q", got.Watermark)
	}
}
