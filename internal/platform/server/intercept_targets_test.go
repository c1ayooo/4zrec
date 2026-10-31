package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/toolface/intercept"
)

// targetsPayload 是审批响应里 targets/tool_targets 的形状。
type targetsPayload struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
}

// getJSON 取嵌套字段;测试响应形状用,失败时 t.Fatal。
func getJSON(t *testing.T, body string, field string) map[string]any {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal([]byte(body), &top); err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}
	v, ok := top[field].(map[string]any)
	if !ok {
		t.Fatalf("response has no object field %q: %s", field, body)
	}
	return v
}

// TestApprovalToolTargetsDisplay 规则/模型审批在所有读取出口都补出展示目标
// tool_targets(「命令打谁」),且不碰授权语义:targets 保持为空,围栏审批
// 的落库 targets 原样返回、不再覆盖 tool_targets。
func TestApprovalToolTargetsDisplay(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	m := &Manager{pg: d, interceptor: intercept.New(d)}
	s := &Server{m: m, jwtKey: []byte("approval-targets-test-signing-key")}
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	do := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 规则 ask:命令里有一个域名一个公网 IP。
	ruleID, err := m.pg.CreateInterceptPending(0, 0, "", "test", "Bash", []byte(`{"command":"nmap -sV example-corpo.com 203.0.113.7"}`), "规则命中:出口扫描")
	if err != nil {
		t.Fatal(err)
	}
	// 围栏 ask:落库结构化 targets(未授权子集)。
	fenceID, err := m.pg.CreateInterceptPending(0, 0, "", "test", "Bash", []byte(`{"command":"nmap -sV fence-target.example"}`), "【资产围栏】目标资产不在项目授权范围内")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetInterceptTargets(fenceID, []byte(`{"domains":["fence-target.example"]}`)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM intercept_pending WHERE id IN ($1,$2)`, ruleID, fenceID)
	})

	decodeTargets := func(raw json.RawMessage) targetsPayload {
		var p targetsPayload
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &p)
		}
		return p
	}

	// 待审批队列:规则 ask 补 tool_targets,targets 保持空。
	rec := do("/api/intercept/pending")
	if rec.Code != 200 {
		t.Fatalf("pending list: %d", rec.Code)
	}
	var list struct {
		Pending []db.InterceptPending `json:"pending"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	byID := map[int64]*db.InterceptPending{}
	for i := range list.Pending {
		byID[list.Pending[i].ID] = &list.Pending[i]
	}
	ruleRow, ok := byID[ruleID]
	if !ok {
		t.Fatalf("rule ask #%d missing from pending list", ruleID)
	}
	if got := decodeTargets(ruleRow.ToolTargets); len(got.Domains) != 1 || got.Domains[0] != "example-corpo.com" || len(got.IPs) != 1 || got.IPs[0] != "203.0.113.7" {
		t.Fatalf("rule ask tool_targets = %+v, want example-corpo.com + 203.0.113.7", got)
	}
	if len(ruleRow.Targets) != 0 {
		t.Fatalf("rule ask targets must stay empty (authorization semantics), got %s", ruleRow.Targets)
	}
	fenceRow, ok := byID[fenceID]
	if !ok {
		t.Fatalf("fence ask #%d missing from pending list", fenceID)
	}
	if got := decodeTargets(fenceRow.Targets); len(got.Domains) != 1 || got.Domains[0] != "fence-target.example" {
		t.Fatalf("fence ask targets = %+v, want fence-target.example", got)
	}
	if len(fenceRow.ToolTargets) != 0 {
		t.Fatalf("fence ask must not carry tool_targets (targets already answers it), got %s", fenceRow.ToolTargets)
	}

	// 单条 + 详情 + 历史分页三个出口同样补齐。
	for _, tc := range []struct {
		path  string
		field string
	}{
		{fmt.Sprintf("/api/intercept/pending/%d", ruleID), ""},
		{fmt.Sprintf("/api/intercept/history/%d", ruleID), ""},
		{"/api/intercept/history?page=1&size=100&status=pending", "items"},
	} {
		r := do(tc.path)
		if r.Code != 200 {
			t.Fatalf("%s: %d", tc.path, r.Code)
		}
		body := r.Body.String()
		if tc.field != "" {
			// 历史分页:在 items 数组里找该行。
			var page struct {
				Items []db.InterceptApprovalRow `json:"items"`
			}
			if err := json.Unmarshal([]byte(body), &page); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range page.Items {
				if row.ID == ruleID {
					found = true
					if got := decodeTargets(row.ToolTargets); len(got.Domains) != 1 || got.Domains[0] != "example-corpo.com" {
						t.Fatalf("%s: tool_targets = %+v", tc.path, got)
					}
				}
			}
			if !found {
				t.Fatalf("%s: rule ask #%d missing", tc.path, ruleID)
			}
			continue
		}
		raw, ok := getJSON(t, body, "tool_targets")["domains"]
		if !ok || !strings.Contains(fmt.Sprint(raw), "example-corpo.com") {
			t.Fatalf("%s: tool_targets.domains missing target, body=%s", tc.path, body)
		}
	}
}
