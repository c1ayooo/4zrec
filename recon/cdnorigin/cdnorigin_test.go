package cdnorigin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// withEndpoints 临时替换外部数据源端点（包级 var，测试可注入 mock）。
func withEndpoints(t *testing.T, crtURL, histURL string) {
	t.Helper()
	origCRT, origHist := crtShEndpoint, securityTrailsEndpoint
	crtShEndpoint, securityTrailsEndpoint = crtURL, histURL
	t.Cleanup(func() { crtShEndpoint, securityTrailsEndpoint = origCRT, origHist })
}

// TestQueryCrtSANs crt.sh 响应解析：通配剥离、多值 \n 分隔、去重、排除主域自身与跨域。
func TestQueryCrtSANs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("output") != "json" || r.URL.Query().Get("q") != "%.example.com" {
			t.Errorf("crt.sh 请求参数异常: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"name_value": "example.com"},
			{"name_value": "www.example.com"},
			{"name_value": "*.dev.example.com"},
			{"name_value": "api.example.com\nadmin.example.com"},
			{"name_value": "www.example.com"},
			{"name_value": "other.org"}
		]`))
	}))
	defer srv.Close()
	withEndpoints(t, srv.URL, "")

	got := queryCrtSANs(context.Background(), srv.Client(), "example.com", 5*time.Second)
	want := map[string]bool{
		"www.example.com":   true,
		"dev.example.com":   true,
		"api.example.com":   true,
		"admin.example.com": true,
	}
	if len(got) != len(want) {
		t.Fatalf("SAN 提取数量错误: got %d want %d (%v)", len(got), len(want), got)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("意外 SAN: %s", name)
		}
	}
}

// TestQueryDNSHistoryNoKey 无 key 时不发请求、返回 nil。
func TestQueryDNSHistoryNoKey(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	withEndpoints(t, "", srv.URL)

	if got := queryDNSHistory(context.Background(), srv.Client(), "example.com", "", 5*time.Second); got != nil {
		t.Fatalf("无 key 应返回 nil, got %v", got)
	}
	if called {
		t.Fatal("无 key 不应发起 SecurityTrails 请求")
	}
}

// TestQueryDNSHistoryParsing SecurityTrails 响应解析 + IP 去重。
func TestQueryDNSHistoryParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("APIKEY") != "test-key" {
			t.Errorf("缺少 APIKEY 头: %q", r.Header.Get("APIKEY"))
		}
		if r.URL.Path != "/v1/history/example.com/dns/a" {
			t.Errorf("路径错误: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"records":[
			{"values":[{"ip":"203.0.113.9","first_seen":"2020-01-01"}]},
			{"values":[{"ip":"104.16.1.1","first_seen":"2019-05-05"},{"ip":"203.0.113.9","first_seen":"2018-01-01"}]}
		]}}`))
	}))
	defer srv.Close()
	withEndpoints(t, "", srv.URL)

	got := queryDNSHistory(context.Background(), srv.Client(), "example.com", "test-key", 5*time.Second)
	if len(got) != 2 {
		t.Fatalf("历史 IP 去重后应为 2 条, got %v", got)
	}
	seen := map[string]bool{}
	for _, ip := range got {
		seen[ip] = true
	}
	if !seen["203.0.113.9"] || !seen["104.16.1.1"] {
		t.Errorf("历史 IP 内容错误: %v", got)
	}
}

// TestFind 主干：mock crt.sh + SecurityTrails（有 key），Lookup 注入免真实 DNS，
// 验证 CDN/源站分类、排序（源站候选在前）、来源证据与去重。
func TestFind(t *testing.T) {
	crt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"name_value": "www.example.com"},
			{"name_value": "cdn.example.com"},
			{"name_value": "admin.example.com"},
			{"name_value": "*.cdn.example.com"}
		]`))
	}))
	defer crt.Close()
	hist := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"records":[{"values":[{"ip":"203.0.113.9","first_seen":"2020-01-01"}]},{"values":[{"ip":"104.16.1.1","first_seen":"2019-05-05"}]}]}}`))
	}))
	defer hist.Close()
	withEndpoints(t, crt.URL, hist.URL)

	// Lookup：www→源站 IP、cdn→Cloudflare 段（应判 CDN）、admin→另一源站 IP。
	lookup := map[string][]string{
		"www.example.com":   {"203.0.113.10"},
		"cdn.example.com":   {"104.16.1.1"}, // Cloudflare 104.16.0.0/13
		"admin.example.com": {"203.0.113.11"},
	}
	got, err := Find(context.Background(), "example.com", Options{
		SecurityTrailsKey: "test-key",
		Lookup: func(ctx context.Context, host string) ([]string, error) {
			return lookup[host], nil
		},
	})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	// 期望集合（4 个非 CDN 源站候选 + 1 个 CDN 边缘）：
	//   san:www.example.com → 203.0.113.10
	//   san:admin.example.com → 203.0.113.11
	//   history → 203.0.113.9（重复出现应去重为一条）
	//   san:cdn.example.com → 104.16.1.1（Cloudflare = CDN）
	//   history → 104.16.1.1（与 san:cdn 同 IP，合并 sources）
	if len(got) != 4 {
		t.Fatalf("期望 4 个唯一 IP, got %d: %+v", len(got), got)
	}
	// 源站候选（非 CDN）必须排在 CDN 边缘之前。
	if got[0].IsCDN || got[1].IsCDN || got[2].IsCDN {
		t.Fatalf("前三应为源站候选, got %+v", got)
	}
	if !got[3].IsCDN {
		t.Fatalf("末位应为 CDN 边缘, got %+v", got[3])
	}
	// CDN 边缘 IP 来源应合并 san + history 两条证据。
	cdn := got[3]
	if cdn.IP != "104.16.1.1" || len(cdn.Sources) != 2 {
		t.Errorf("CDN 边缘来源未合并: %+v", cdn)
	}
	// 源站候选顺序按 IP 字典序。
	if got[0].IP > got[1].IP || got[1].IP > got[2].IP {
		t.Errorf("源站候选应按 IP 字典序: %+v", got[:3])
	}
}

// TestFindNoKey 无 SecurityTrails key：仅 crt.sh + DNS 解析，不请求历史数据源。
func TestFindNoKey(t *testing.T) {
	crt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name_value": "www.example.com"}]`))
	}))
	defer crt.Close()
	histCalled := false
	hist := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { histCalled = true }))
	defer hist.Close()
	withEndpoints(t, crt.URL, hist.URL)

	got, err := Find(context.Background(), "example.com", Options{
		Lookup: func(ctx context.Context, host string) ([]string, error) {
			if host == "www.example.com" {
				return []string{"203.0.113.10"}, nil
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if histCalled {
		t.Fatal("无 key 不应请求 SecurityTrails")
	}
	if len(got) != 1 || got[0].IP != "203.0.113.10" || got[0].IsCDN {
		t.Fatalf("结果错误: %+v", got)
	}
}

// TestFindEmptyDomain 空/非法域名应报错。
func TestFindEmptyDomain(t *testing.T) {
	if _, err := Find(context.Background(), "  ", Options{}); err == nil {
		t.Fatal("空域名应报错")
	}
}
