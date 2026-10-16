package spacemap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testClient 构造指向 httptest 上游的客户端(provider 请求全部打桩)。
func testClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewClient()
	c.KeyResolver = func(string) string { return "test-key" }
	c.BaseURLResolver = func(string) string { return srv.URL }
	return c
}

// TestFofaSearchAndNormalize FOFA 路径:CSV 行 → 字段映射 → 归一化。
// 直接移植自 4zreco 的 provider 形态,响应结构按官方 API 打桩。
func TestFofaSearchAndNormalize(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("key"); got != "test-key" {
			t.Errorf("key 参数缺失: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": false, "size": 2, "page": 1, "total": 2,
			"results": [][]any{
				{"sub.example.com", "1.2.3.4", float64(443), "sub.example.com", "登录页", "https", "", "", "", "", "", "nginx"},
			},
		})
	}))
	results, raw, total, err := c.SearchEngineAssets(context.Background(), "fofa", `domain="example.com"`, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(results) != 1 || len(raw) != 1 {
		t.Fatalf("total=%d results=%d raw=%d", total, len(results), len(raw))
	}
	got := results[0]
	if got.Domain != "sub.example.com" || got.IP != "1.2.3.4" || got.Port != 443 {
		t.Fatalf("归一化错误: %+v", got)
	}
	if got.Title != "登录页" || got.Protocol != "https" || got.Server != "nginx" {
		t.Fatalf("字段映射错误: %+v", got)
	}
	if got.Host != "sub.example.com" || got.Source != "FOFA" {
		t.Fatalf("host/source 错误: %+v", got)
	}
}

// TestQuakeSearchAndNormalize Quake 路径:envelope 壳 + 嵌套字段路径回落链。
func TestQuakeSearchAndNormalize(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["query"] != `domain:"example.com"` {
			t.Errorf("query 透传错误: %v", body["query"])
		}
		if r.Header.Get("X-QuakeToken") != "test-key" {
			t.Errorf("quake token 头缺失")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0, "total_count": 1,
			"data": []map[string]any{{
				"ip": "5.6.7.8", "port": float64(80),
				"service": map[string]any{
					"name": "http/ssl",
					"http": map[string]any{"title": "控制台", "server": "Apache"},
				},
				"location": map[string]any{"country_cn": "中国", "province_cn": "北京", "city_cn": "北京"},
			}},
		})
	}))
	results, _, _, err := c.SearchEngineAssets(context.Background(), "quake", `domain:"example.com"`, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results=%d", len(results))
	}
	got := results[0]
	if got.Protocol != "http" { // "http/ssl" 取 / 前段
		t.Errorf("协议归一错误: %q", got.Protocol)
	}
	// server 不在 quake 默认 include 字段表里(4zreco 实测调优的字段集),
	// projectRows 投影后被裁——需要 server 时显式传 fields。此处断言忠实于默认行为。
	if got.Server != "" {
		t.Errorf("默认字段集不应含 server: %q", got.Server)
	}
	if got.Title != "控制台" || got.Country != "中国" || got.Province != "北京" {
		t.Fatalf("quake 字段回落链错误: %+v", got)
	}
	if got.Domain != "" || got.Host != "5.6.7.8" {
		t.Fatalf("quake 无 domain 时 host 应回落 IP: %+v", got)
	}
}

// TestHunterSearchAndNormalize Hunter 路径:code=20000 壳 + url 提主机回落。
func TestHunterSearchAndNormalize(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api-key") != "test-key" {
			t.Errorf("hunter api-key 缺失")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 20000,
			"data": map[string]any{
				"total": 1,
				"arr": []map[string]any{
					{"url": "http://api.hunter-test.example:8080/x", "ip": "9.9.9.9", "port": float64(8080), "web_title": "接口文档", "protocol": "http"},
				},
			},
		})
	}))
	results, _, _, err := c.SearchEngineAssets(context.Background(), "hunter", `domain.suffix="example"`, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := results[0]
	if got.Domain != "api.hunter-test.example" {
		t.Fatalf("hunter url→domain 回落错误: %+v", got)
	}
	if got.Title != "接口文档" || got.Port != 8080 {
		t.Fatalf("hunter 字段错误: %+v", got)
	}
}

// TestUnconfiguredKey 未配置 key:明确报错(fail-loud),不静默空结果。
func TestUnconfiguredKey(t *testing.T) {
	c := NewClient() // KeyResolver nil
	_, _, _, err := c.SearchEngineAssets(context.Background(), "fofa", "x", 0, 0)
	if err == nil || !strings.Contains(err.Error(), "未配置") {
		t.Fatalf("未配置 key 应报错: %v", err)
	}
}

// TestDomainQuerySyntax 各引擎域名查询语法(与 4zreco batch 语法表逐项对齐)。
func TestDomainQuerySyntax(t *testing.T) {
	cases := map[string]string{
		"fofa":        `domain="example.com"`,
		"zoomeye":     `domain="example.com"`,
		"quake":       `domain:"example.com"`,
		"shodan":      `hostname:example.com`,
		"hunter":      `domain.suffix="example.com"`,
		"FOFA":        `domain="example.com"`, // 归一化
		"zoom-eye":    `domain="example.com"`,
		"unsupported": `domain="example.com"`, // 未知名按 fofa 兜底——ValidProvider 拦截调用方
	}
	for provider, want := range cases {
		if got := DomainQuery(provider, "example.com"); got != want {
			t.Errorf("DomainQuery(%q) = %q, want %q", provider, got, want)
		}
	}
	if !ValidProvider("quake") || ValidProvider("censys") {
		t.Error("ValidProvider 判定错误")
	}
}

// TestMaskKey 掩码回显:保留前 4 后 2,过短全打码。
func TestMaskKey(t *testing.T) {
	if got := Mask(""); got != "" {
		t.Errorf("空 key: %q", got)
	}
	if got := Mask("short"); got != "*****" {
		t.Errorf("短 key 应全打码: %q", got)
	}
	if got := Mask("abcdefghijk"); got != "abcd******jk" {
		t.Errorf("长 key 掩码错误: %q", got)
	}
}

// TestZoomEyeFailure 非成功码:透出上游 message(ZoomEye 60000=成功)。
func TestZoomEyeFailure(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 60001, "message": "配额不足"})
	}))
	_, _, _, err := c.SearchEngineAssets(context.Background(), "zoomeye", "x", 0, 0)
	if err == nil || !strings.Contains(err.Error(), "配额不足") {
		t.Fatalf("zoomeye 错误应透出: %v", err)
	}
}
