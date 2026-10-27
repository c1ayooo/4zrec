package spacemap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type httpFetcher struct{}

func (httpFetcher) Fetch(ctx context.Context, req core.Request) (*core.Response, error) {
	body := bytes.NewReader(req.Body)
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	started := time.Now()
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &core.Response{Status: resp.StatusCode, Headers: resp.Header, Body: data, Duration: time.Since(started)}, nil
}

// testClient 构造指向 httptest 上游的客户端(provider 请求全部打桩)。
func testClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewClient(core.Deps{Fetcher: httpFetcher{}})
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
	c := NewClient(core.Deps{Fetcher: httpFetcher{}}) // KeyResolver nil
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

func TestCapabilitySpaceSearchUsesEngine(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 20000, "data": map[string]any{"total": 0, "arr": []any{}},
		})
	}))
	defer srv.Close()
	c := NewClient(core.Deps{Fetcher: httpFetcher{}})
	c.KeyResolver = func(string) string { return "test-key" }
	c.BaseURLResolver = func(provider string) string {
		if provider == "hunter" {
			return srv.URL + "/openApi/search"
		}
		return srv.URL
	}
	res, err := c.Call(context.Background(), core.Call{
		Tool:  "space_search",
		Input: json.RawMessage(`{"engine":"hunter","query":"domain.suffix=\"example.com\""}`),
	})
	if err != nil || !res.OK {
		t.Fatalf("call = %#v, err=%v", res, err)
	}
	if gotPath != "/openApi/search" {
		t.Fatalf("engine not honored, path=%q", gotPath)
	}
	providers, err := c.Call(context.Background(), core.Call{Tool: "space_providers"})
	if err != nil || !providers.OK {
		t.Fatalf("providers = %#v, err=%v", providers, err)
	}
}

// ---- 更多引擎路径 ----

// TestShodanSearchAndNormalize Shodan 路径:分页循环 + hostnames/domains 回落。
func TestShodanSearchAndNormalize(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "test-key" {
			t.Errorf("shodan key 参数缺失: %q", r.URL.Query().Get("key"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total": 1,
			"matches": []map[string]any{{
				"ip_str": "2.2.2.2", "port": float64(8443),
				"hostnames": []any{"portal.example"}, "http": map[string]any{"title": "Portal"},
			}},
		})
	}))
	results, _, total, err := c.SearchEngineAssets(context.Background(), "shodan", "hostname:example", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(results) != 1 {
		t.Fatalf("total=%d results=%d", total, len(results))
	}
	got := results[0]
	// Shodan 默认字段集不含 http.title，projectRows 会把 http 子树裁掉——
	// 忠实断言默认行为:主机/端口/域名命中，title 需显式传 fields 才有。
	if got.IP != "2.2.2.2" || got.Port != 8443 || got.Domain != "portal.example" {
		t.Fatalf("shodan 归一化错误: %+v", got)
	}
}

// TestZoomEyeSearchSuccess ZoomEye 成功码 60000:data 数组行正常投影。
func TestZoomEyeSearchSuccess(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("API-KEY") != "test-key" {
			t.Errorf("zoomeye API-KEY 头缺失")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 60000, "total": 1,
			"data": []map[string]any{{
				"ip": "3.3.3.3", "port": float64(443),
				"domain": "z.example", "title": "Zoom", "country": "中国",
			}},
		})
	}))
	results, _, _, err := c.SearchEngineAssets(context.Background(), "zoomeye", `domain="example"`, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].IP != "3.3.3.3" || results[0].Title != "Zoom" {
		t.Fatalf("zoomeye 归一化错误: %+v", results)
	}
}

// ---- 输出契约：Summary 与信封 ----

// fofaRowClient 返回一个 FOFA 打桩客户端,每次查询稳定返回 1 条资产。
func fofaRowClient(t *testing.T) *Client {
	t.Helper()
	return testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": false, "size": 1, "page": 1, "total": 1,
			"results": [][]any{
				{"sub.example.com", "1.2.3.4", float64(443), "sub.example.com", "登录页", "https"},
			},
		})
	}))
}

// TestSpaceSearchSummary 成功路径 Summary:引擎 + 查询 + 资产条数,Meta 完整。
func TestSpaceSearchSummary(t *testing.T) {
	c := fofaRowClient(t)
	res, err := c.Call(context.Background(), core.Call{
		Tool:  "space_search",
		Input: json.RawMessage(`{"engine":"fofa","query":"domain=\"example.com\""}`),
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess || !res.OK {
		t.Fatalf("status=%s ok=%v", res.Status, res.OK)
	}
	if res.Meta.Tool != "space_search" || res.Meta.Version != kitVersion {
		t.Fatalf("meta = %+v", res.Meta)
	}
	want := `用 FOFA 查询 domain="example.com"，返回 1 条资产`
	if res.Summary != want {
		t.Fatalf("Summary = %q, want %q", res.Summary, want)
	}
}

// TestSpaceDomainSearchSummary 域名查询 Summary 必须点名域名与条数。
func TestSpaceDomainSearchSummary(t *testing.T) {
	c := fofaRowClient(t)
	res, err := c.Call(context.Background(), core.Call{
		Tool:  "space_domain_search",
		Input: json.RawMessage(`{"engine":"fofa","domain":"example.com"}`),
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess || res.Meta.Tool != "space_domain_search" {
		t.Fatalf("status=%s meta=%+v", res.Status, res.Meta)
	}
	want := "用 FOFA 查询域名 example.com 的资产，返回 1 条"
	if res.Summary != want {
		t.Fatalf("Summary = %q, want %q", res.Summary, want)
	}
}

// TestSpaceProvidersSummary providers 的 Summary 汇总引擎数与已配置密钥数。
func TestSpaceProvidersSummary(t *testing.T) {
	c := NewClient(core.Deps{Fetcher: httpFetcher{}})
	c.KeyResolver = func(provider string) string {
		if provider == "fofa" {
			return "test-key"
		}
		return ""
	}
	res, err := c.Call(context.Background(), core.Call{Tool: "space_providers"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess || res.Meta.Tool != "space_providers" {
		t.Fatalf("status=%s meta=%+v", res.Status, res.Meta)
	}
	want := "返回 5 个测绘引擎，其中 1 个密钥已配置"
	if res.Summary != want {
		t.Fatalf("Summary = %q, want %q", res.Summary, want)
	}
}

// TestSpaceSearchFailures 失败路径的信封仍须完整:query 缺失、未知工具、未配置 key。
func TestSpaceSearchFailures(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		input string
	}{
		{"missing query", "space_search", `{}`},
		{"missing domain", "space_domain_search", `{}`},
		{"unknown tool", "space_nope", `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(core.Deps{Fetcher: httpFetcher{}})
			c.KeyResolver = func(string) string { return "test-key" }
			res, _ := c.Call(context.Background(), core.Call{Tool: tc.tool, Input: json.RawMessage(tc.input)})
			if res.Status != core.StatusFailed || res.OK {
				t.Fatalf("status=%s ok=%v", res.Status, res.OK)
			}
			if res.Error == nil || res.Error.Code == "" {
				t.Fatalf("失败必须带固定枚举内的 Error.Code: %+v", res.Error)
			}
			if strings.TrimSpace(res.Summary) == "" {
				t.Fatalf("失败路径 Summary 不得为空")
			}
			if res.Meta.Tool != tc.tool {
				t.Fatalf("Meta.Tool = %q, want %q", res.Meta.Tool, tc.tool)
			}
		})
	}
}

// TestUnconfiguredKeyEnvelope 未配置 key 是失败信封(而非静默空结果),且带 Summary。
func TestUnconfiguredKeyEnvelope(t *testing.T) {
	c := NewClient(core.Deps{Fetcher: httpFetcher{}})
	res, _ := c.Call(context.Background(), core.Call{
		Tool:  "space_search",
		Input: json.RawMessage(`{"engine":"fofa","query":"domain=\"example.com\""}`),
	})
	if res.Status != core.StatusFailed || res.Error == nil {
		t.Fatalf("未配置 key 应为失败信封: %+v", res)
	}
	if !strings.Contains(res.Summary, "未配置") {
		t.Fatalf("Summary 应说明未配置: %q", res.Summary)
	}
	if res.Meta.Tool != "space_search" {
		t.Fatalf("Meta.Tool = %q", res.Meta.Tool)
	}
}
