package enterprise

import (
	"strings"
	"testing"
)

func TestNewProviderKinds(t *testing.T) {
	ff := newStubFetcher(stubRoute{sub: "/api/auth/login", resp: loginResponse(`{"success":true}`, "sid=1")})

	cases := []struct {
		name     string
		provider string
		cfg      map[string]string
		wantName string
		wantErr  string
	}{
		{"aqc", "aqc", map[string]string{"cookie": "c=1"}, "aqc", ""},
		{"tyc", "tyc", map[string]string{"cookie": "auth_token=t"}, "tyc", ""},
		{"kuaicha", "kuaicha", map[string]string{"cookie": "c=1"}, "kuaicha", ""},
		{"fengniao cookie", "fengniao", map[string]string{"cookie": "c=1"}, "fengniao", ""},
		{"fengniao 账号密码", "fengniao", map[string]string{"username": "138", "password": "pw"}, "fengniao", ""},
		{"大小写与空白不敏感", "  AQC ", map[string]string{"cookie": "c=1"}, "aqc", ""},
		{"aqc 缺 cookie", "aqc", nil, "", "爱企查会话未配置"},
		{"fengniao 缺配置", "fengniao", map[string]string{}, "", "风鸟会话未配置"},
		{"qcc 待接入", "qcc", nil, "", "企查查(qcc) 适配器待接入"},
		{"xiaolanben 未迁移", "xiaolanben", nil, "", "小蓝本依赖内嵌浏览器"},
		{"未知类型", "bogus", nil, "", "不支持的数据源类型"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProvider(ff, tc.provider, tc.cfg, "")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want contains %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewProvider = %v", err)
			}
			if p.Name() != tc.wantName {
				t.Fatalf("Name = %q, want %q", p.Name(), tc.wantName)
			}
		})
	}
}

func TestNewProviderProxyOverride(t *testing.T) {
	c, err := NewProvider(newStubFetcher(), "aqc", map[string]string{"cookie": "c=1", "proxy_url": "http://session:1"}, "http://global:2")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.(*aqcProvider).c.proxy; got != "http://session:1" {
		t.Fatalf("会话级代理未生效: %q", got)
	}
	c2, err := NewProvider(newStubFetcher(), "aqc", map[string]string{"cookie": "c=1"}, "http://global:2")
	if err != nil {
		t.Fatal(err)
	}
	if got := c2.(*aqcProvider).c.proxy; got != "http://global:2" {
		t.Fatalf("应回落全局代理: %q", got)
	}
}

// TestProviderConstructorsNilFetcher 覆盖各 adapter 构造时 newWebClient 失败
// 的早退分支（fetcher 未注入）。
func TestProviderConstructorsNilFetcher(t *testing.T) {
	cases := []struct {
		name string
		call func() (Provider, error)
	}{
		{"aqc", func() (Provider, error) { return NewAqcProvider(nil, "cookie=1", "") }},
		{"tyc", func() (Provider, error) { return NewTycProvider(nil, "auth_token=t", "") }},
		{"kuaicha", func() (Provider, error) { return NewKuaichaProvider(nil, "cookie=1", "") }},
		{"fengniao", func() (Provider, error) { return NewFengniaoProvider(nil, "cookie=1", "") }},
		{"fengniao 账号", func() (Provider, error) { return NewFengniaoAccountProvider(nil, "138", "pw", "") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.call(); err == nil {
				t.Fatal("nil fetcher 应返回错误")
			}
		})
	}
}
