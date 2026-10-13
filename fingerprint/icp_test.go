package fingerprint

import (
	"strings"
	"testing"
)

func TestExtractICP(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{"<a>粤ICP备14006354号</a>", "粤ICP备14006354号"},
		{"京ICP备2021000001号-5 京公网安备 11010802012345号", "京ICP备2021000001号"},
		{"沪ICP证123456号", "沪ICP证123456号"},
		{"<footer><a href='beian.miit.gov.cn'>浙ICP备0501号-3</a></footer>", "浙ICP备0501号"},
		// 线上实测：woniuxy.com 页脚使用方言前缀「蜀」（MIIT 标准简称是川）
		{"<a href='beian.miit.gov.cn'>蜀ICP备15014130号-2</a>", "蜀ICP备15014130号"},
		{"没有备案号的页面", ""},
		{"公网安备 11010802012345号 不是 ICP", ""},
	}
	for _, c := range cases {
		if got := ExtractICP(c.body); got != c.want {
			t.Errorf("ExtractICP(%q) = %q; want %q", c.body, got, c.want)
		}
	}
}

func TestNormalizeICP(t *testing.T) {
	if got := NormalizeICP(" 粤ICP备14006354号-3 "); got != "粤ICP备14006354号" {
		t.Fatalf("NormalizeICP = %q", got)
	}
	if got := NormalizeICP(""); got != "" {
		t.Fatalf("NormalizeICP empty = %q", got)
	}
}

func TestExtractLinks(t *testing.T) {
	body := `<html><body>
		<a href="https://mail.example.com/">邮箱系统</a>
		<a href='/oa/'>OA办公</a>
		<a href="survey.woniuxy.com:8010/login">问卷系统</a>
		<a href="javascript:void(0)">空链接</a>
		<a href="mailto:a@b.com">邮件</a>
		<a href="#top">锚点</a>
		<a href="https://mail.example.com/">重复链接</a>
		</body></html>`
	links := ExtractLinks(body, "https://www.example.com/portal/", 50)
	want := []string{
		"https://mail.example.com/",
		"https://www.example.com/oa/",
		"https://survey.woniuxy.com:8010/login",
		// 注意：无 scheme 的 survey.woniuxy.com:8010/login 解析为相对路径
	}
	if len(links) < 2 {
		t.Fatalf("链接过少: %v", links)
	}
	if links[0] != want[0] {
		t.Fatalf("首条 = %v", links[0])
	}
	for _, l := range links {
		if strings.Contains(l, "javascript") || strings.Contains(l, "mailto") || strings.HasSuffix(l, "#top") {
			t.Fatalf("过滤失败: %v", l)
		}
	}
	// 相对路径解析
	found := false
	for _, l := range links {
		if l == "https://www.example.com/oa/" {
			found = true
		}
	}
	if !found {
		t.Fatalf("相对路径未解析: %v", links)
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"survey.woniuxy.com":   "woniuxy.com",
		"www.woniuxy.com:8443": "woniuxy.com",
		"beian.miit.gov.cn":    "miit.gov.cn",
		"a.b.example.co.uk":    "example.co.uk",
		"1.2.3.4":              "1.2.3.4",
		"WONIUXY.COM.":         "woniuxy.com",
	}
	for in, want := range cases {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q; want %q", in, got, want)
		}
	}
}
