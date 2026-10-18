package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// TestDifferentialProbeToolShape 验证工具已装配出正确的 schema/措辞，不依赖 PG。
func TestDifferentialProbeToolShape(t *testing.T) {
	s := &Server{}
	tool := s.toolDifferentialProbe()
	if tool.Name() != "differential_probe" {
		t.Fatalf("name = %q, want differential_probe", tool.Name())
	}
	desc := tool.Description()
	for _, want := range []string{"基线", "变体", "相似度", "时延", "traffic_id", "不是漏洞结论"} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description missing %q: %s", want, desc)
		}
	}
	schema := tool.InputSchema()
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		t.Fatal("schema.properties missing")
	}
	for _, want := range []string{
		"baseline", "variants", "repeats", "similarity_threshold",
		"timing_delta_ms", "timing_tolerance_ms", "error_patterns",
		"marker", "proxy", "timeout_seconds", "random_fingerprint", "project_id",
	} {
		if _, ok := props[want]; !ok {
			t.Fatalf("schema missing %s; got %v", want, props)
		}
	}
	if len(s.diffProbeTools()) != 1 {
		t.Fatalf("diffProbeTools() = %d, want 1", len(s.diffProbeTools()))
	}
}

// TestDifferentialProbeToolEndToEnd 用本地 HTTP 靶标验证工具从参数解析、
// RoE（无项目上下文时放行）、真实请求到判定的整条链路。证据库未接（m=nil），
// 因此 traffic_id 为空，但测量与输出应正常。
func TestDifferentialProbeToolEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		switch r.URL.Query().Get("q") {
		case "1", "1'":
			fmt.Fprint(w, "hello world user list")
		default:
			fmt.Fprint(w, "database error occurred")
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &Server{}
	input, err := json.Marshal(map[string]any{
		"baseline": map[string]any{"url": srv.URL + "/?q=1"},
		"variants": []map[string]any{
			{"label": "true", "role": "true", "url": srv.URL + "/?q=" + url.QueryEscape("1'")},
			{"label": "false", "role": "false", "url": srv.URL + "/?q=" + url.QueryEscape("1''")},
		},
		"similarity_threshold": 0.8,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.toolDifferentialProbe().Call(context.Background(), input, &actool.ToolContext{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %s", res.Flatten())
	}
	out := res.Flatten()
	if !strings.Contains(out, "boolean_separation") {
		t.Fatalf("missing boolean signal:\n%s", out)
	}
	if !strings.Contains(out, "verdict=signal") {
		t.Fatalf("verdict not signal:\n%s", out)
	}
}
