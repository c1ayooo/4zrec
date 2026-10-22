package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeAssetSyncBaseURL(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "http://127.0.0.1:8080/api/mcp", false},
		{"127.0.0.1:8080", "http://127.0.0.1:8080/api/mcp", false},
		{"http://127.0.0.1:8080/", "http://127.0.0.1:8080/api/mcp", false},
		{"http://127.0.0.1:8080/api/mcp", "http://127.0.0.1:8080/api/mcp", false},
		{"https://zre.example.com/base/", "https://zre.example.com/base/api/mcp", false},
		{"ftp://zre.example.com", "", true},
	}
	for _, tt := range tests {
		got, err := normalizeAssetSyncBaseURL(tt.in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("normalize(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
		if err == nil && got != tt.want {
			t.Fatalf("normalize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMapZrearkSite(t *testing.T) {
	tests := []struct {
		name string
		site zrearkSite
		url  string
		ok   bool
	}{
		{
			name: "value url wins",
			site: zrearkSite{Host: "www.example.com", Value: "https://www.example.com/app"},
			url:  "https://www.example.com/app",
			ok:   true,
		},
		{
			name: "https default port omitted",
			site: zrearkSite{Host: "www.example.com", Protocol: "https", Port: 443, HTTPStatus: 200},
			url:  "https://www.example.com",
			ok:   true,
		},
		{
			name: "http non-default port kept",
			site: zrearkSite{Host: "www.example.com", Protocol: "http", Port: 8080},
			url:  "http://www.example.com:8080",
			ok:   true,
		},
		{
			name: "protocol missing defaults to https",
			site: zrearkSite{Host: "api.example.com", Port: 8443},
			url:  "https://api.example.com:8443",
			ok:   true,
		},
		{
			name: "ipv6 host bracketed",
			site: zrearkSite{Host: "2001:db8::1", Protocol: "https", Port: 443},
			url:  "https://[2001:db8::1]",
			ok:   true,
		},
		{
			name: "missing host skipped",
			site: zrearkSite{Value: "not-a-url"},
			ok:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item, upsert, ok := mapZrearkSite(tt.site)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if item.URL != tt.url || upsert.URL != tt.url {
				t.Fatalf("url = %q / %q, want %q", item.URL, upsert.URL, tt.url)
			}
		})
	}
}

func fakeMCPAssetServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q", got)
		}
		var req struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if req.Method != "tools/call" || req.Params.Name != "list_assets" {
			t.Errorf("unexpected request: %s / %s", req.Method, req.Params.Name)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"jsonrpc":"2.0","id":1,
			"result":{
				"content":[{"type":"text","text":"{}"}],
				"structuredContent":{
					"items":[{
						"id":7,"project_id":1,"project_name":"演示项目",
						"host":"www.example.com","port":443,"protocol":"https",
						"http_status":200,"title":"Example","technology_stack":["nginx"],
						"ip":"1.2.3.4","state":"active"
					}],
					"total":1,"page":1,"page_size":200,"has_more":false,"kind":"site"
				}
			}
		}`))
	}))
}

func TestMCPSyncCallerListAssets(t *testing.T) {
	srv := fakeMCPAssetServer(t)
	defer srv.Close()

	caller, err := newMCPSyncCaller(srv.URL, "test-key")
	if err != nil {
		t.Fatalf("new caller: %v", err)
	}
	raw, err := caller.call(context.Background(), "list_assets", map[string]any{"kind": "site"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	var page zrearkAssetPage
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].Host != "www.example.com" {
		t.Fatalf("unexpected page: %+v", page)
	}
}

func TestAssetSyncDryRun(t *testing.T) {
	srv := fakeMCPAssetServer(t)
	defer srv.Close()

	body, _ := json.Marshal(assetSyncRequest{
		BaseURL: srv.URL,
		APIKey:  "test-key",
		DryRun:  true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/assets/sync", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	s := &Server{m: &Manager{}}
	s.assetSync(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var result assetSyncResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !result.DryRun || result.Fetched != 1 || result.WouldImport != 1 || result.Imported != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(result.Sample) != 1 || result.Sample[0].URL != "https://www.example.com" {
		t.Fatalf("unexpected sample: %+v", result.Sample)
	}
}
