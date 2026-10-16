package httpprobe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/redirectguard"
)

// 默认（FollowRedirects 零值）不跟随：捕获原始 302，跳转目标随 Redirects 返回，
// 由用户决定下一轮是否测试该跳转。
func TestDoRequest_DefaultNoFollow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("final"))
	}))
	defer srv.Close()

	res, err := DoRequest(context.Background(), Request{URL: srv.URL + "/a"})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("默认应捕获原始 302，got %d body=%q", res.StatusCode, res.RespBody)
	}
	if strings.Contains(res.RespBody, "final") {
		t.Fatal("默认不跟随却取到了跳转后的响应")
	}
	if res.FinalURL != srv.URL+"/a" {
		t.Errorf("未跟随时 FinalURL 应为原始 URL: %s", res.FinalURL)
	}
	if len(res.Redirects) != 1 {
		t.Fatalf("应记录 1 跳: %+v", res.Redirects)
	}
	hop := res.Redirects[0]
	if !hop.NotFollowed || hop.Blocked {
		t.Errorf("跳转应标记未跟随: %+v", hop)
	}
	if hop.Status != http.StatusFound || !strings.HasSuffix(hop.ToURL, "/b") {
		t.Errorf("跳转目标/状态记录错误: %+v", hop)
	}
	summary := Summarize(res)
	if !strings.Contains(summary, "需要用户决策") || !strings.Contains(summary, "单独发起请求") || !strings.Contains(summary, "不得表述为已访问") {
		t.Errorf("摘要应给出用户决策提示与逐跳请求指引:\n%s", summary)
	}
}

// Guard 拦截：保留当前 30x（报文/证据不丢），拦截原因随跳转链返回。
func TestDoRequest_RedirectGuardBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("final"))
	}))
	defer srv.Close()

	guard := func(hop redirectguard.Hop) error {
		return fmt.Errorf("测试拦截: 不允许跳转到 %s", hop.ToURL)
	}
	res, err := DoRequest(context.Background(), Request{
		URL:             srv.URL + "/a",
		FollowRedirects: true,
		RedirectGuard:   guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusFound || strings.Contains(res.RespBody, "final") {
		t.Fatalf("被拦截后应保留原始 302: status=%d body=%q", res.StatusCode, res.RespBody)
	}
	hop := res.Redirects[0]
	if !hop.Blocked || !strings.Contains(hop.BlockReason, "测试拦截") {
		t.Fatalf("应记录拦截原因: %+v", hop)
	}
	summary := Summarize(res)
	if !strings.Contains(summary, "已拦截") || !strings.Contains(summary, "不得绕过") {
		t.Errorf("摘要应提示已拦截且不得绕过:\n%s", summary)
	}
}

// Guard 放行时多跳跟随，逐跳观测（跨域标注为纯逻辑，见 redirectguard 包测试）。
func TestDoRequest_RedirectGuardFollowsAndRecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusMovedPermanently)
		case "/b":
			w.Header().Set("Location", "/c")
			w.WriteHeader(http.StatusFound)
		default:
			_, _ = w.Write([]byte("done"))
		}
	}))
	defer srv.Close()

	var hops []redirectguard.Hop
	res, err := DoRequest(context.Background(), Request{
		URL:             srv.URL + "/a",
		FollowRedirects: true,
		RedirectGuard:   func(hop redirectguard.Hop) error { hops = append(hops, hop); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || !strings.Contains(res.RespBody, "done") {
		t.Fatalf("放行后应跟随到最终响应: status=%d body=%q", res.StatusCode, res.RespBody)
	}
	if res.FinalURL != srv.URL+"/c" {
		t.Errorf("FinalURL 应为末跳地址: %s", res.FinalURL)
	}
	if len(hops) != 2 || len(res.Redirects) != 2 {
		t.Fatalf("应逐跳调用 Guard 并记录 2 跳: guard=%d result=%d", len(hops), len(res.Redirects))
	}
	if hops[0].Status != http.StatusMovedPermanently || !strings.HasSuffix(hops[0].ToURL, "/b") {
		t.Errorf("第 1 跳记录错误: %+v", hops[0])
	}
	if hops[1].Status != http.StatusFound || !strings.HasSuffix(hops[1].ToURL, "/c") {
		t.Errorf("第 2 跳记录错误: %+v", hops[1])
	}
	if hops[0].CrossDomain || hops[0].SchemeDowngrade {
		t.Errorf("同 host 同协议不应标注跨域/降级: %+v", hops[0])
	}
}

// 策略直连：敏感地址（回环）跳转在 Guard 处被拦截，不发起连接。
// TestDoRequest_SensitiveRedirectAnalyzed SSRF 门禁已放开：敏感跳转不再拦截，
// 跳转目标照常分析（CrossDomain 等属性随 Hop 返回供决策）。但 agent 工具层默认
// 不跟随（FollowRedirects=false），此处用显式跟随验证 Guard 不再因敏感地址阻断。
func TestDoRequest_SensitiveRedirectAnalyzed(t *testing.T) {
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("reached"))
	}))
	defer second.Close()
	target := second.URL + "/unreachable" // 回环地址（127.0.0.1），可达
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	policy := redirectguard.Policy{}
	res, err := DoRequest(context.Background(), Request{
		URL:             srv.URL + "/a",
		FollowRedirects: true,
		RedirectGuard:   policy.Check,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("回环跳转应被跟随（SSRF 放开）: %d", res.StatusCode)
	}
	hop := res.Redirects[0]
	if hop.Blocked {
		t.Fatalf("敏感跳转不应再被 Policy 拦截: %+v", hop)
	}
	if hop.ToURL != target {
		t.Fatalf("跳转目标应被记录: %+v", hop)
	}
}
