package redirectguard

import (
	"errors"
	"strings"
	"testing"
)

func TestIsSensitiveTarget(t *testing.T) {
	cases := []struct {
		url       string
		sensitive bool
		reason    string // 期望原因包含的关键字（空=不校验）
	}{
		{"http://127.0.0.1:8080/admin", true, "回环"},
		{"http://[::1]/", true, "回环"},
		{"http://localhost/x", true, "localhost"},
		{"http://app.localhost/x", true, "localhost"},
		{"http://10.1.2.3/", true, "内网"},
		{"http://192.168.1.1/", true, "内网"},
		{"http://172.16.0.9/", true, "内网"},
		{"http://169.254.169.254/latest/meta-data/", true, "云元数据"},
		{"http://100.100.100.200/latest/meta-data/", true, "云元数据"},
		{"http://metadata.google.internal/computeMetadata/v1/", true, "云元数据"},
		{"http://0.0.0.0:9000/", true, "未指定"},
		{"http://[fd00::1]/", true, "内网"},
		{"http://[fe80::1]/", true, "链路本地"},
		{"http://100.64.1.1/", true, "NAT"},
		{"http://0.1.2.3/", true, "保留"},
		{"https://example.com/login", false, ""},
		{"https://8.8.8.8/", false, ""},
		{"http://sub.example.com.//", false, ""},
	}
	for _, tc := range cases {
		got, reason := IsSensitiveTarget(tc.url)
		if got != tc.sensitive {
			t.Errorf("%s: sensitive=%v want %v (reason=%q)", tc.url, got, tc.sensitive, reason)
			continue
		}
		if tc.reason != "" && !strings.Contains(reason, tc.reason) {
			t.Errorf("%s: reason %q 不含 %q", tc.url, reason, tc.reason)
		}
	}
}

func TestAnalyze(t *testing.T) {
	hop := Analyze(0, "https://example.com/a", "https://www.example.com/b", 302, "https://example.com/a")
	if !hop.CrossDomain {
		t.Error("www 子域与裸域 hostname 不同，应标注跨域")
	}
	if hop.SchemeDowngrade {
		t.Error("同为 https 不应标注降级")
	}

	hop = Analyze(1, "https://example.com/a", "http://example.com/b", 301, "https://example.com/a")
	if hop.CrossDomain {
		t.Error("同 host 不应标注跨域")
	}
	if !hop.SchemeDowngrade {
		t.Error("https→http 应标注降级")
	}

	// 跨域以原始 host 为基准：A→B→A 的第二跳不算跨域
	hop = Analyze(1, "https://b.example.net/x", "https://example.com/", 302, "https://example.com/")
	if hop.CrossDomain {
		t.Error("回到原始 host 不应标注跨域")
	}
	if hop.Status != 302 || hop.Index != 1 || hop.FromURL == "" || hop.ToURL == "" {
		t.Errorf("字段填充错误: %+v", hop)
	}
}

func TestSameSiteOrSubdomain(t *testing.T) {
	cases := []struct {
		host, base string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"deep.www.example.com", "example.com", true},
		{"example.com", "www.example.com", false}, // 基域不是子域的反向
		{"evil-example.com", "example.com", false},
		{"example.com.evil.net", "example.com", false},
		{"EXAMPLE.com.", "example.com", true},
		{"", "example.com", false},
	}
	for _, tc := range cases {
		if got := SameSiteOrSubdomain(tc.host, tc.base); got != tc.want {
			t.Errorf("SameSiteOrSubdomain(%q,%q)=%v want %v", tc.host, tc.base, got, tc.want)
		}
	}
}

func TestPolicyCheck(t *testing.T) {
	scopeErr := errors.New("目标不在当前项目授权范围内")
	base := Hop{FromURL: "https://example.com/a", ToURL: "https://example.com/b"}

	// SSRF 门禁已放开（2026-09-18 用户决策）：回环/云元数据/跨域均不再硬拦
	p := Policy{}
	if err := p.Check(Hop{FromURL: "https://example.com/", ToURL: "http://127.0.0.1:8080/admin"}); err != nil {
		t.Fatalf("回环目标应放行（SSRF 已放开）: %v", err)
	}
	if err := p.Check(Hop{FromURL: "https://example.com/", ToURL: "http://169.254.169.254/latest/meta-data/"}); err != nil {
		t.Fatalf("云元数据目标应放行（SSRF 已放开）: %v", err)
	}
	cross := Hop{FromURL: "https://example.com/a", ToURL: "https://sso.example.net/login", CrossDomain: true}
	if err := p.Check(cross); err != nil {
		t.Fatalf("跨域跳转应放行（SSRF 已放开）: %v", err)
	}
	// 非 http(s) 协议仍拦截
	if err := p.Check(Hop{FromURL: "https://example.com/", ToURL: "ftp://example.com/x"}); err == nil {
		t.Fatal("非 http(s) 目标应拦截")
	}
	// 同站跳转：无范围回调 → 放行
	if err := p.Check(base); err != nil {
		t.Fatalf("同站跳转应放行: %v", err)
	}
	// 范围回调：拒绝时给出"超出授权边界"语义并保留原因（授权管理，非 SSRF）
	p.CheckScope = func(rawURL string) error { return scopeErr }
	if err := p.Check(cross); err == nil || !strings.Contains(err.Error(), "超出授权边界") || !errors.Is(err, scopeErr) {
		t.Fatalf("范围外跳转应拦截并保留原因: %v", err)
	}
	// 范围内跳转（回调放行）→ 放行
	p.CheckScope = func(string) error { return nil }
	if err := p.Check(cross); err != nil {
		t.Fatalf("范围内跳转应放行: %v", err)
	}

}
