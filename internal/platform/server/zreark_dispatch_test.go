package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newFakeMCPDispatchServer 按序应答 create_task / start_task / list_tasks，
// 并记录收到的 arguments 供断言。
func newFakeMCPDispatchServer(t *testing.T, startFails bool) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var calls []map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/mcp", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if req.Method != "tools/call" {
			t.Errorf("unexpected method: %s", req.Method)
			return
		}
		calls = append(calls, map[string]any{"name": req.Params.Name, "args": req.Params.Arguments})
		if req.Params.Name == "start_task" && startFails {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{
				"content":[{"type":"text","text":"任务状态不允许启动"}],
				"isError":true}}`))
			return
		}
		var structured string
		switch req.Params.Name {
		case "create_task":
			structured = `{"id":"abc123def456","project_id":1,"status":"pending","type":"subdomain","targets":2}`
		case "start_task":
			structured = `{"task_id":"abc123def456","command":"start","ok":true}`
		case "list_tasks":
			structured = `{"items":[` +
				`{"id":"t1","name":"巡检","type":"subdomain","status":"completed","progress":100,` +
				`"targets":["a.com","b.com"],"target_type":"domain",` +
				`"result_stats":{"discovered_assets":12,"discovered_ports":30}},` +
				`{"id":"t2","name":"端口","type":"port_scan","status":"running","progress":40,` +
				`"targets":["1.2.3.4"],"target_type":"ip","last_error":null}` +
				`],"total":2,"page":1,"page_size":20}`
		default:
			structured = `{}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{
			"content":[{"type":"text","text":"{}"}],
			"structuredContent":` + structured + `}}`))
	})
	return httptest.NewServer(mux), &calls
}

func postJSON(t *testing.T, handler http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestZrearkDispatch(t *testing.T) {
	srv, calls := newFakeMCPDispatchServer(t, false)
	defer srv.Close()

	s := &Server{m: &Manager{}}
	rec := postJSON(t, s.zrearkDispatch, "/api/assets/zreark/dispatch", map[string]any{
		"base_url":          srv.URL,
		"api_key":           "test-key",
		"source_project_id": 1,
		"name":              "巡检",
		"type":              "subdomain",
		"targets":           []string{"a.com", " b.com ", "a.com", ""},
		"target_type":       "domain",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		TaskID  string `json:"task_id"`
		Status  string `json:"status"`
		Targets int    `json:"targets"`
		Started bool   `json:"started"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TaskID != "abc123def456" || !out.Started || out.Status != "running" {
		t.Fatalf("unexpected out: %+v", out)
	}
	if out.Targets != 2 {
		t.Fatalf("targets = %d, want 2 (去空/去重后)", out.Targets)
	}
	if len(*calls) != 2 || (*calls)[0]["name"] != "create_task" || (*calls)[1]["name"] != "start_task" {
		t.Fatalf("call order = %+v", *calls)
	}
	args := (*calls)[0]["args"].(map[string]any)
	if args["project_id"].(float64) != 1 || args["type"] != "subdomain" || args["target_type"] != "domain" {
		t.Fatalf("create_task args = %+v", args)
	}
	if got := len(args["targets"].([]any)); got != 2 {
		t.Fatalf("create_task targets = %d, want 2", got)
	}
	if (*calls)[1]["args"].(map[string]any)["task_id"] != "abc123def456" {
		t.Fatalf("start_task args = %+v", (*calls)[1]["args"])
	}
}

func TestZrearkDispatchAutoStartFailureStillCreated(t *testing.T) {
	srv, _ := newFakeMCPDispatchServer(t, true)
	defer srv.Close()

	s := &Server{m: &Manager{}}
	rec := postJSON(t, s.zrearkDispatch, "/api/assets/zreark/dispatch", map[string]any{
		"base_url":          srv.URL,
		"api_key":           "test-key",
		"source_project_id": 1,
		"name":              "巡检",
		"type":              "full",
		"targets":           []string{"a.com"},
		"target_type":       "domain",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		TaskID     string `json:"task_id"`
		Started    bool   `json:"started"`
		StartError string `json:"start_error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TaskID == "" || out.Started || !strings.Contains(out.StartError, "任务状态不允许启动") {
		t.Fatalf("unexpected out: %+v", out)
	}
}

func TestZrearkDispatchValidation(t *testing.T) {
	s := &Server{m: &Manager{}}
	tests := []struct {
		name string
		body map[string]any
		code int
	}{
		{"bad type", map[string]any{"type": "vuln_scan", "targets": []string{"a.com"}, "target_type": "domain", "source_project_id": 1}, http.StatusBadRequest},
		{"bad target_type", map[string]any{"type": "full", "targets": []string{"a.com"}, "target_type": "host", "source_project_id": 1}, http.StatusBadRequest},
		{"empty targets", map[string]any{"type": "full", "targets": []string{" "}, "target_type": "domain", "source_project_id": 1}, http.StatusBadRequest},
		{"missing project", map[string]any{"type": "full", "targets": []string{"a.com"}, "target_type": "domain"}, http.StatusBadRequest},
		{"missing key", map[string]any{"type": "full", "targets": []string{"a.com"}, "target_type": "domain", "source_project_id": 1}, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postJSON(t, s.zrearkDispatch, "/api/assets/zreark/dispatch", tt.body)
			if rec.Code != tt.code {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestZrearkTasksNormalize(t *testing.T) {
	srv, _ := newFakeMCPDispatchServer(t, false)
	defer srv.Close()

	s := &Server{m: &Manager{}}
	rec := postJSON(t, s.zrearkTasks, "/api/assets/zreark/tasks", map[string]any{
		"base_url": srv.URL,
		"api_key":  "test-key",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Tasks []zrearkTask `json:"tasks"`
		Total int64        `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Total != 2 || len(out.Tasks) != 2 {
		t.Fatalf("unexpected out: %+v", out)
	}
	first, second := out.Tasks[0], out.Tasks[1]
	if first.TargetCount != 2 || first.DiscoveredAssets != 12 || first.Status != "completed" {
		t.Fatalf("unexpected first task: %+v", first)
	}
	if second.Progress != 40 || second.LastError != "" { // last_error:null 归一为空串
		t.Fatalf("unexpected second task: %+v", second)
	}
}

func TestZrearkAuthSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"API key 无效"}`))
	}))
	defer srv.Close()

	caller, err := newMCPSyncCaller(srv.URL, "bad-key")
	if err != nil {
		t.Fatalf("new caller: %v", err)
	}
	_, err = caller.call(context.Background(), "list_assets", map[string]any{})
	if !errors.Is(err, errZrearkAuth) {
		t.Fatalf("err = %v, want errZrearkAuth", err)
	}
}

func TestMaskZrearkKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"short", "*****"},
		{"zr_abcdef1234567890", "zr_a******90"},
	}
	for _, tt := range tests {
		if got := maskZrearkKey(tt.in); got != tt.want {
			t.Fatalf("mask(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestZrearkConfigGetUnconfigured(t *testing.T) {
	s := &Server{m: &Manager{}}
	req := httptest.NewRequest(http.MethodGet, "/api/assets/zreark/config", nil)
	rec := httptest.NewRecorder()
	s.zrearkConfigGet(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		BaseURL    string `json:"base_url"`
		Configured bool   `json:"configured"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.BaseURL != zrearkDefaultBaseURL || out.Configured {
		t.Fatalf("unexpected out: %+v", out)
	}
}
