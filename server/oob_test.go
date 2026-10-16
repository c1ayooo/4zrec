package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/oob"
)

// TestDnslogStub dnslog 客户端(桩服务):get_domain 拿域名+cookie,get_records 带cookie 查记录。
func TestDnslogStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "sess123"})
		switch {
		case r.URL.Path == "/getdomain.php":
			_, _ = w.Write([]byte("abc123.dnslog.stub"))
		case r.URL.Path == "/getrecords.php":
			if r.Header.Get("Cookie") == "" {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`["q1.abc123.dnslog.stub","q2.abc123.dnslog.stub"]%`))
		}
	}))
	defer srv.Close()

	domain, err := oob.DnslogGetDomain(context.Background(), srv.URL)
	if err != nil || domain != "abc123.dnslog.stub" {
		t.Fatalf("get_domain: %v %q", err, domain)
	}
	records, err := oob.DnslogGetRecords(context.Background(), srv.URL, domain, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || !strings.Contains(records[0], "q1.abc123") {
		t.Fatalf("记录解析错误(JSON+尾缀%%): %v", records)
	}
	// 行文本形态。
	records2 := oobParseOnly("line1.dnslog.stub\nline2.dnslog.stub%")
	if len(records2) != 2 {
		t.Fatalf("行文本解析错误: %v", records2)
	}
}

func oobParseOnly(raw string) []string { return oob.ParseRecordsForTest(raw) }

// TestVTSubdomainsStub VT 被动子域(桩 API)。
func TestVTSubdomainsStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "vt-key" {
			w.WriteHeader(401)
			return
		}
		if strings.Contains(r.URL.Path, "/subdomains") {
			_, _ = w.Write([]byte(`{"data":[{"id":"a.vt.example"},{"id":"b.vt.example"}],"links":{}}`))
			return
		}
		if strings.Contains(r.URL.Path, "/resolutions") {
			_, _ = w.Write([]byte(`{"data":[{"attributes":{"ip_address":"1.2.3.4"}}]}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	subs, ips, err := oob.VTSubdomains(context.Background(), "vt-key", "vt.example", 10, false, srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("VT 桩调用失败: %v", err)
	}
	if len(subs) != 2 || subs[0] != "a.vt.example" {
		t.Fatalf("VT 子域解析错误: %v", subs)
	}
	_ = ips
}

// TestAIProtocolScanStub AI 端点探测(桩靶标)。
func TestAIProtocolScanStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-x"}]}`))
		case r.URL.Path == "/mcp" && r.Method == "POST":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"stub-mcp"}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	results, err := oob.AIProtocolScan(context.Background(), srv.URL, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var llm, mcp bool
	for _, res := range results {
		if res.Kind == "llm" && res.Exposed && strings.Contains(res.Detail, "/v1/models") {
			llm = true
		}
		if res.Kind == "mcp" && res.Exposed {
			mcp = true
		}
		if res.Kind == "a2a" && res.Exposed {
			t.Fatalf("未实现 a2a 的桩不应命中: %+v", res)
		}
	}
	if !llm || !mcp {
		t.Fatalf("LLM/MCP 暴露未检出: %+v", results)
	}

	// 工具层:无 key 报错明确。
	s := &Server{}
	in, _ := json.Marshal(map[string]any{"domain": "x.example"})
	res, err := s.toolVTSubdomains().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "VirusTotal") {
		t.Fatalf("无 key 应明确报错: %s", res.Flatten())
	}
}
