package enterprise

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestStripHTML(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"  北京某某科技有限公司  ", "北京某某科技有限公司"},
		{"<em>某某</em>科技", "某某科技"},
		{"<span class=\"x\">A</span><b>B</b>", "AB"},
		{"no tags at all", "no tags at all"},
		{"<em></em>  <b>  </b> ", ""},
		{"a<br>b<i>c</i>", "abc"},
	}
	for _, tc := range cases {
		if got := stripHTML(tc.in); got != tc.want {
			t.Errorf("stripHTML(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFirstExistingString(t *testing.T) {
	item := gjson.Parse(`{"a":"first","b":"second","empty":"","n":42,"nested":{"x":"deep"}}`)
	cases := []struct {
		name  string
		paths []string
		want  string
	}{
		{"首个命中", []string{"a", "b"}, "first"},
		{"首个缺失回落第二个", []string{"missing", "b"}, "second"},
		{"空串不算存在", []string{"empty", "b"}, "second"},
		{"数字字段", []string{"n"}, "42"},
		{"全不存在", []string{"nope", "nada"}, ""},
		{"嵌套路径", []string{"nested.x"}, "deep"},
		{"无路径", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstExistingString(item, tc.paths...); got != tc.want {
				t.Fatalf("firstExistingString(%v) = %q, want %q", tc.paths, got, tc.want)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"裸域名", "example.com", "example.com"},
		{"带 scheme https", "https://example.com", "example.com"},
		{"带 scheme http", "http://example.com", "example.com"},
		{"带端口", "example.com:8443", "example.com"},
		{"带路径", "https://example.com/a/b?c=d#e", "example.com"},
		{"大写归一", "EXAMPLE.COM", "example.com"},
		{"首尾空白", "  example.com  ", "example.com"},
		{"多级域名", "a.b.c.example.com", "a.b.c.example.com"},
		{"允许下划线", "my_site.example.com", "my_site.example.com"},
		{"允许连字符", "my-site.example.com", "my-site.example.com"},
		{"空串", "", ""},
		{"仅空白", "   ", ""},
		{"无点拒绝", "localhost", ""},
		{"仅 scheme 拒绝", "https://", ""},
		{"超长拒绝", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", ""},
		{"含星号拒绝", "*.example.com", ""},
		{"含空格拒绝", "exa mple.com", ""},
		{"含中文拒绝", "例子.公司", ""},
		{"含 @ 拒绝", "user@example.com", ""},
		{"尾点保留", "example.com.", "example.com."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeDomain(tc.in); got != tc.want {
				t.Fatalf("normalizeDomain(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// 超过 253 字节的 hostname 必须拒绝。
	long := strings.Repeat("a", 250) + ".com"
	if got := normalizeDomain(long); got != "" {
		t.Fatalf("normalizeDomain(超长) = %q, want 空", got)
	}
}
