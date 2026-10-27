package tunnel

import (
	"strings"
	"testing"
)

func TestRenderPage(t *testing.T) {
	for _, lang := range []string{"jsp", "php"} {
		page, err := RenderPage(lang, "abc123def4567890")
		if err != nil {
			t.Fatalf("RenderPage(%q): %v", lang, err)
		}
		if !strings.Contains(page, "abc123def4567890") {
			t.Errorf("%s 页未注入口令哈希", lang)
		}
		if strings.Contains(page, "__PWHASH__") {
			t.Errorf("%s 页残留占位符", lang)
		}
		if !strings.Contains(page, "TUNR") || !strings.Contains(page, "TUNZ") {
			t.Errorf("%s 页缺少响应标记", lang)
		}
	}
	if _, err := RenderPage("asp", "x"); err == nil {
		t.Error("asp 应返回错误")
	}
}

func TestPageLangAndPath(t *testing.T) {
	if got := PageLangFor("jsp"); got != "jsp" {
		t.Errorf("PageLangFor(jsp)=%q", got)
	}
	if got := PageLangFor("php"); got != "php" {
		t.Errorf("PageLangFor(php)=%q", got)
	}
	if got := PageLangFor(""); got != "jsp" {
		t.Errorf("PageLangFor(\"\")=%q（回退 jsp）", got)
	}
	if got := SuggestPagePath("https://a.b/c/d/zzsh.jsp", "jsp"); got != "/c/d/ztun.jsp" {
		t.Errorf("SuggestPagePath=%q", got)
	}
	if got := SuggestPagePath("http://1.2.3.4:8080/zzsg.jsp", "jsp"); got != "/ztun.jsp" {
		t.Errorf("SuggestPagePath 根路径=%q", got)
	}
}
