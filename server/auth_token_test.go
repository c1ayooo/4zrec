package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestExtractTokenSources 鉴权来源:Authorization 头优先;两种登录 cookie
// (artex_token / 4zrec_token)都认——浏览器直接打开导出链接只带 cookie。
func TestExtractTokenSources(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/exploration/findings/1/export?format=md", nil)
	req.AddCookie(&http.Cookie{Name: "artex_token", Value: "cookie-artex"})
	if got := extractToken(req); got != "cookie-artex" {
		t.Fatalf("artex_token cookie 应被接受, got %q", got)
	}
	req2 := httptest.NewRequest("GET", "/x", nil)
	req2.AddCookie(&http.Cookie{Name: "4zrec_token", Value: "cookie-4zrec"})
	if got := extractToken(req2); got != "cookie-4zrec" {
		t.Fatalf("4zrec_token cookie 应被接受, got %q", got)
	}
	req3 := httptest.NewRequest("GET", "/x", nil)
	req3.Header.Set("Authorization", "Bearer header-token")
	req3.AddCookie(&http.Cookie{Name: "artex_token", Value: "cookie-artex"})
	if got := extractToken(req3); got != "header-token" {
		t.Fatalf("Authorization 头应优先, got %q", got)
	}
	req4 := httptest.NewRequest("GET", "/x?token=query-token", nil)
	if got := extractToken(req4); got != "query-token" {
		t.Fatalf("?token= 应作为兜底, got %q", got)
	}
}
