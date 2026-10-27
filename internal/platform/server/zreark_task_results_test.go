package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSanitizeZrearkIP(t *testing.T) {
	tests := []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4/32", "1.2.3.4"}, // 4zreark 常见形态：带 /32 后缀
		{"2001:db8::1/128", "2001:db8::1"},
		{"1.2.3.0/24", ""}, // 网段不是主机地址，丢弃
		{"", ""},
		{"not-an-ip", ""},
		{"https://1.2.3.4/x", "1.2.3.4"},
	}
	for _, tt := range tests {
		if got := sanitizeZrearkIP(tt.in); got != tt.want {
			t.Fatalf("sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestJoinZrearkRouteURL(t *testing.T) {
	tests := []struct{ base, path, want string }{
		{"https://www.example.com", "/api/x", "https://www.example.com/api/x"},
		{"https://www.example.com/", "/api/x", "https://www.example.com/api/x"},
		{"https://www.example.com/app", "/api/x", "https://www.example.com/app/api/x"},
		{"https://www.example.com", "api/x", "https://www.example.com/api/x"},
		{"", "/api/x", ""},
		{"https://www.example.com", "", ""},
	}
	for _, tt := range tests {
		if got := joinZrearkRouteURL(tt.base, tt.path); got != tt.want {
			t.Fatalf("join(%q,%q) = %q, want %q", tt.base, tt.path, got, tt.want)
		}
	}
}

func TestBuildZrearkHostURL(t *testing.T) {
	tests := []struct {
		host string
		port int
		want string
	}{
		{"www.example.com", 0, "https://www.example.com"},
		{"www.example.com", 80, "http://www.example.com"},
		{"www.example.com", 8080, "https://www.example.com:8080"},
		{"", 80, ""},
	}
	for _, tt := range tests {
		if got := buildZrearkHostURL(tt.host, tt.port); got != tt.want {
			t.Fatalf("buildHostURL(%q,%d) = %q, want %q", tt.host, tt.port, got, tt.want)
		}
	}
}

// fakeMCPResultsServer 应答 get_task_results：crawler 一页 + service 一页，记录参数。
func fakeMCPResultsServer(t *testing.T) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var calls []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		if req.Method != "tools/call" || req.Params.Name != "get_task_results" {
			t.Errorf("unexpected: %s / %s", req.Method, req.Params.Name)
			return
		}
		calls = append(calls, map[string]any{"name": req.Params.Name, "args": req.Params.Arguments})
		typ, _ := req.Params.Arguments["result_type"].(string)
		var structured string
		switch typ {
		case "crawler":
			structured = `{"items":[
				{"type":"crawler","data":{"url":"https://www.example.com/login","method":"get","status_code":200}},
				{"type":"crawler","data":{"url":"not-a-url","method":"GET"}}],
				"total":2,"page":1,"page_size":100}`
		case "service":
			structured = `{"items":[
				{"type":"service","data":{"url":"https://www.example.com","host":"www.example.com","ip":"1.2.3.4","port":443,
					"title":"Example","status_code":200,"technologies":["nginx"],"fingerprints":["PHP"],"status_code2":0}},
				{"type":"service","data":{"type":"other","host":"1.2.3.4","ip":"1.2.3.4","port":22,"service":"ssh","banner":"OpenSSH"}}],
				"total":2,"page":1,"page_size":100}`
		case "subdomain":
			structured = `{"items":[
				{"type":"subdomain","data":{"subdomain":"api.example.com","domain":"example.com","ips":["5.6.7.8"],"alive":true}}],
				"total":1,"page":1,"page_size":100}`
		case "port":
			structured = `{"items":[
				{"type":"port","data":{"host":"5.6.7.8","ip":"5.6.7.8","port":8080,"service":"http"}}],
				"total":1,"page":1,"page_size":100}`
		default:
			structured = `{"items":[],"total":0}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{
			"content":[{"type":"text","text":"{}"}],
			"structuredContent":` + structured + `}}`))
	}))
	return srv, &calls
}

func TestZrearkTaskResultsDryRun(t *testing.T) {
	srv, calls := fakeMCPResultsServer(t)
	defer srv.Close()

	s := &Server{m: &Manager{}}
	rec := postJSON(t, s.zrearkTaskResults, "/api/assets/zreark/task-results", map[string]any{
		"base_url": srv.URL,
		"api_key":  "test-key",
		"task_id":  "abc123",
		"dry_run":  true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out zrearkTaskResultsResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TaskID != "abc123" || out.Fetched != 4 || out.Services != 2 || out.Endpoints != 2 {
		t.Fatalf("unexpected result: %+v", out)
	}
	// crawler 与 service 各自独立分页：两个 result_type 各一页请求
	if len(*calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(*calls))
	}
	args0 := (*calls)[0]["args"].(map[string]any)
	if args0["result_type"] != "crawler" || args0["task_id"] != "abc123" || args0["page_size"].(float64) != 100 {
		t.Fatalf("unexpected args: %+v", args0)
	}
}

func TestZrearkTaskResultsValidation(t *testing.T) {
	s := &Server{m: &Manager{}}
	// 缺 task_id → 400
	rec := postJSON(t, s.zrearkTaskResults, "/api/assets/zreark/task-results", map[string]any{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	// 非法 include → 400
	rec = postJSON(t, s.zrearkTaskResults, "/api/assets/zreark/task-results", map[string]any{
		"task_id": "abc", "include": []string{"vuln"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestZrearkTaskResultsSubdomainPortDryRun(t *testing.T) {
	srv, calls := fakeMCPResultsServer(t)
	defer srv.Close()

	s := &Server{m: &Manager{}}
	rec := postJSON(t, s.zrearkTaskResults, "/api/assets/zreark/task-results", map[string]any{
		"base_url": srv.URL,
		"api_key":  "test-key",
		"task_id":  "abc123",
		"include":  []string{"subdomain", "port"},
		"dry_run":  true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out zrearkTaskResultsResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Fetched != 2 || out.Subdomains != 1 || out.Ports != 1 {
		t.Fatalf("dry-run counters = %+v", out)
	}
	if len(*calls) != 2 {
		t.Fatalf("calls = %d, want 2 (subdomain+port)", len(*calls))
	}
}
