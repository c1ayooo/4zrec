package enterprise

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckAPI(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
		wantRaw string
	}{
		{"成功", `{"status":0,"data":{"x":1}}`, "", `{"x":1}`},
		{"安全验证", `{"status":0,"data":{},"msg":"百度安全验证"}`, "安全验证", ""},
		{"无 status", `{"foo":1}`, "响应不是有效业务 JSON", ""},
		{"业务错误", `{"status":2,"message":"  上游炸了  "}`, "上游错误: 上游炸了", ""},
		{"非 JSON", `not-json`, "响应不是有效业务 JSON", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := checkAPI(tc.body)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkAPI = %v, want nil", err)
				}
				if data.Raw != tc.wantRaw {
					t.Fatalf("data.Raw = %q, want %q", data.Raw, tc.wantRaw)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkAPI err = %v, want contains %q", err, tc.wantErr)
			}
		})
	}
}

func TestKcState(t *testing.T) {
	if _, err := kcState(`{"msg":"请登录后再操作"}`); !IsSessionMissing(err) {
		t.Fatalf("请登录 应映射为会话失效, got %v", err)
	}
	if _, err := kcState(`{"msg":"请重新登录"}`); !IsSessionMissing(err) {
		t.Fatalf("请重新登录 应映射为会话失效, got %v", err)
	}
	if _, err := kcState(`{"foo":1}`); err == nil || !strings.Contains(err.Error(), "缺少 data") {
		t.Fatalf("缺 data 应报错, got %v", err)
	}
	data, err := kcState(`{"data":{"list":[1]}}`)
	if err != nil || !data.Get("list").IsArray() {
		t.Fatalf("kcState 正常路径 = %v, %v", data.Raw, err)
	}
}

func TestTycState(t *testing.T) {
	if _, err := tycState(`{"message":"mustlogin"}`); !IsSessionMissing(err) {
		t.Fatalf("mustlogin 应映射为会话失效, got %v", err)
	}
	if _, err := tycState(`{"msg":"请输入中国大陆手机号"}`); !IsSessionMissing(err) {
		t.Fatalf("手机号提示应映射为会话失效, got %v", err)
	}
	if _, err := tycState(`{"state":"fail"}`); err == nil || !strings.Contains(err.Error(), "state=fail") {
		t.Fatalf("state!=ok 应报错, got %v", err)
	}
	data, err := tycState(`{"state":"ok","data":{"id":7}}`)
	if err != nil || data.Get("id").Int() != 7 {
		t.Fatalf("tycState 正常路径 = %v, %v", data.Raw, err)
	}
	// 无 state 字段时不做业务校验，直接取 data。
	if data, err := tycState(`{"data":{"id":8}}`); err != nil || data.Get("id").Int() != 8 {
		t.Fatalf("无 state 时应直取 data, got %v %v", data.Raw, err)
	}
}

func TestRbState(t *testing.T) {
	f := &fengniaoProvider{}
	if _, err := f.rbState(`{"code":"40001","msg":"please login"}`, "20000"); !IsSessionMissing(err) {
		t.Fatalf("login+40001 应映射为会话失效, got %v", err)
	}
	if _, err := f.rbState(`{"code":"8888","msg":"  出错  "}`, "20000"); err == nil || !strings.Contains(err.Error(), "风鸟错误: 出错") {
		t.Fatalf("业务码不符应报错, got %v", err)
	}
	if data, err := f.rbState(`{"code":"20000","data":{"totalCount":3}}`, "20000"); err != nil || data.Get("totalCount").Int() != 3 {
		t.Fatalf("rbState 成功 = %v, %v", data.Raw, err)
	}
	// 无 code 字段视为成功。
	if data, err := f.rbState(`{"data":{"x":1}}`, "20000"); err != nil || !data.Exists() {
		t.Fatalf("无 code 应放行, got %v %v", data.Raw, err)
	}
}

func TestTransformAqcPID(t *testing.T) {
	cases := []struct {
		name  string
		input string
		t     int64
		want  string
	}{
		{"ddw=1 全数字表", "0123456789", 1, "0123547698"},
		{"ddw=2 全数字表", "0123456789", 2, "0123689457"},
		{"其余 ddw 原样", "0123456789", 7, "0123456789"},
		{"ddw=0 原样", "4899", 0, "4899"},
		{"非数字字符保留", "12a34", 1, "12a35"},
		{"空串", "", 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := transformAqcPID(tc.input, tc.t); got != tc.want {
				t.Fatalf("transformAqcPID(%q, %d) = %q, want %q", tc.input, tc.t, got, tc.want)
			}
		})
	}
}

func TestCookieParam(t *testing.T) {
	cookie := "auth_token=abc; TYCID=tyc456; sid=xyz"
	if got := cookieParam(cookie, "auth_token"); got != "abc" {
		t.Fatalf("auth_token = %q", got)
	}
	if got := cookieParam(cookie, "tycid"); got != "tyc456" {
		t.Fatalf("大小写不敏感失败 = %q", got)
	}
	if got := cookieParam(cookie, "missing"); got != "" {
		t.Fatalf("缺失键应为空 = %q", got)
	}
	if got := cookieParam("novalue", "novalue"); got != "" {
		t.Fatalf("无 = 的段应跳过 = %q", got)
	}
	// 段整体会 TrimSpace，段内键名两侧空白不裁剪（与实现一致）。
	if got := cookieParam("  a = b  ", "a"); got != "" {
		t.Fatalf("键名含空白应按字面匹配 = %q", got)
	}
	if got := cookieParam("x; a=b ; y", "a"); got != "b" {
		t.Fatalf("段级空白应裁剪 = %q", got)
	}
}

func TestSetCookiePairs(t *testing.T) {
	headers := map[string][]string{
		"Set-Cookie":    {"a=1; Path=/; HttpOnly", "b=2", "   "},
		"set-cookie":    {"c=3; SameSite=Lax"},
		"Content-Type":  {"application/json"},
		"X-Other-Thing": {"ignored"},
	}
	got := setCookiePairs(headers)
	want := map[string]bool{"a=1": true, "b=2": true, "c=3": true}
	if len(got) != len(want) {
		t.Fatalf("setCookiePairs = %#v, want %d 项", got, len(want))
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("意外的 pair: %q (%#v)", p, got)
		}
	}
	if parts := setCookiePairs(map[string][]string{"Content-Type": {"x"}}); len(parts) != 0 {
		t.Fatalf("无 Set-Cookie 应为空, got %#v", parts)
	}
}

func TestEffectiveProxy(t *testing.T) {
	if got := effectiveProxy(map[string]string{"proxy_url": "http://a:1"}, "http://global:2"); got != "http://a:1" {
		t.Fatalf("会话级代理应优先 = %q", got)
	}
	if got := effectiveProxy(map[string]string{"proxy_url": "  "}, "http://global:2"); got != "http://global:2" {
		t.Fatalf("空白会话代理应回落全局 = %q", got)
	}
	if got := effectiveProxy(map[string]string{}, "http://global:2"); got != "http://global:2" {
		t.Fatalf("无会话代理应回落全局 = %q", got)
	}
	if got := effectiveProxy(nil, ""); got != "" {
		t.Fatalf("都为空的应返回空 = %q", got)
	}
}

func TestProviderErrors(t *testing.T) {
	err := SessionMissing("会话未配置")
	if err.Error() != "会话未配置" {
		t.Fatalf("Error() = %q", err.Error())
	}
	if !IsSessionMissing(err) {
		t.Fatal("IsSessionMissing 应为 true")
	}
	if IsSessionMissing(errors.New("其它错误")) {
		t.Fatal("普通错误不应判定为会话失效")
	}
	if IsSessionMissing(nil) {
		t.Fatal("nil 不应判定为会话失效")
	}
	// 包装后仍可识别。
	wrapped := errors.Join(errors.New("ctx"), SessionMissing("x"))
	if !IsSessionMissing(wrapped) {
		t.Fatal("包装后的会话错误应被识别")
	}
}
