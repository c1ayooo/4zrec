package enterprise

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read fail") }

func TestNewWebClient(t *testing.T) {
	if _, err := newWebClient(nil, "https://api.example.com", "", time.Second); err == nil {
		t.Fatal("nil fetcher 应返回错误")
	}
	ff := newStubFetcher()
	if _, err := newWebClient(ff, "://bad", "", time.Second); err == nil {
		t.Fatal("非法 base 应返回错误")
	}

	c, err := newWebClient(ff, "https://api.example.com/", "", 0)
	if err != nil {
		t.Fatalf("newWebClient = %v", err)
	}
	if c.base != "https://api.example.com" {
		t.Fatalf("base 尾斜杠未去除: %q", c.base)
	}
	if c.timeout != 15*time.Second {
		t.Fatalf("timeout <= 0 应回落 15s，得到 %v", c.timeout)
	}
	if c.headers["User-Agent"] == "" || c.headers["Accept"] == "" {
		t.Fatalf("缺少默认头: %#v", c.headers)
	}

	c2, err := newWebClient(ff, "https://api.example.com", "http://proxy:8080", 3*time.Second)
	if err != nil {
		t.Fatalf("newWebClient = %v", err)
	}
	if c2.timeout != 3*time.Second || c2.proxy != "http://proxy:8080" {
		t.Fatalf("proxy/timeout 未保留: %v %q", c2.timeout, c2.proxy)
	}
}

func TestWebClientGet(t *testing.T) {
	ff := newStubFetcher(stubRoute{sub: "/ok", resp: json200(`{"a":1}`)})
	c, err := newWebClient(ff, "https://api.example.com", "http://proxy:8080", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.headers["Cookie"] = "sid=1"

	body, err := c.getJSON(context.Background(), "/ok?q=1", map[string]string{"X-Extra": "v", "X-Skip": ""})
	if err != nil {
		t.Fatalf("getJSON = %v", err)
	}
	if body != `{"a":1}` {
		t.Fatalf("body = %q", body)
	}

	req := ff.last(t)
	if req.Method != http.MethodGet {
		t.Fatalf("method = %q", req.Method)
	}
	if req.URL != "https://api.example.com/ok?q=1" {
		t.Fatalf("相对路径应拼接 base: %q", req.URL)
	}
	if req.Proxy != "http://proxy:8080" || req.Timeout != 2*time.Second {
		t.Fatalf("proxy/timeout 未传递: %q %v", req.Proxy, req.Timeout)
	}
	if req.Headers["Cookie"] != "sid=1" {
		t.Fatalf("Cookie 头未传递: %#v", req.Headers)
	}
	if req.Headers["X-Extra"] != "v" {
		t.Fatalf("extra 头未合并: %#v", req.Headers)
	}
	if _, ok := req.Headers["X-Skip"]; ok {
		t.Fatalf("空值 extra 头不应注入: %#v", req.Headers)
	}
	if req.Headers["Content-Type"] != "" {
		t.Fatalf("GET 不应设置 Content-Type: %q", req.Headers["Content-Type"])
	}

	// 绝对 URL 原样透传，不再拼 base。
	ff.routes = []stubRoute{{sub: "https://other.example.com/abs", resp: json200("abs")}}
	if got, err := c.getJSON(context.Background(), "https://other.example.com/abs", nil); err != nil || got != "abs" {
		t.Fatalf("绝对 URL getJSON = %q, %v", got, err)
	}
	if got := ff.last(t).URL; got != "https://other.example.com/abs" {
		t.Fatalf("绝对 URL 被改写: %q", got)
	}
}

func TestWebClientPost(t *testing.T) {
	ff := newStubFetcher(stubRoute{sub: "/post", resp: json200(`{"ok":true}`)})
	c, err := newWebClient(ff, "https://api.example.com", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	body, err := c.postJSON(context.Background(), "/post", `{"k":"v"}`, nil)
	if err != nil {
		t.Fatalf("postJSON = %v", err)
	}
	if body != `{"ok":true}` {
		t.Fatalf("body = %q", body)
	}
	req := ff.last(t)
	if req.Method != http.MethodPost {
		t.Fatalf("method = %q", req.Method)
	}
	if string(req.Body) != `{"k":"v"}` {
		t.Fatalf("body 未传递: %q", req.Body)
	}
	if !strings.HasPrefix(req.Headers["Content-Type"], "application/json") {
		t.Fatalf("POST 应设置 JSON Content-Type: %q", req.Headers["Content-Type"])
	}
}

func TestWebClientErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("非 200", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/err", resp: statusResp(403, "denied")})
		c, _ := newWebClient(ff, "https://api.example.com", "", time.Second)
		_, err := c.getJSON(ctx, "/err", nil)
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("非 200 应报错，得到 %v", err)
		}
	})

	t.Run("传输层错误", func(t *testing.T) {
		ff := newStubFetcher()
		ff.failWith(errors.New("boom"))
		c, _ := newWebClient(ff, "https://api.example.com", "", time.Second)
		if _, err := c.getJSON(ctx, "/x", nil); err == nil {
			t.Fatal("fetcher 错误应向上传递")
		}
	})

	t.Run("请求体读取失败", func(t *testing.T) {
		ff := newStubFetcher()
		c, _ := newWebClient(ff, "https://api.example.com", "", time.Second)
		if _, err := c.do(ctx, http.MethodPost, "/x", errReader{}, false, nil); err == nil {
			t.Fatal("body 读取错误应向上传递")
		}
		// doRaw 同样暴露该错误路径。
		if _, err := c.doRaw(ctx, http.MethodPost, "/x", errReader{}, true, nil); err == nil {
			t.Fatal("doRaw body 读取错误应向上传递")
		}
	})
}

func TestURLQueryEscape(t *testing.T) {
	cases := map[string]string{
		"abc":   "abc",
		"a b":   "a+b",
		"中":     "%E4%B8%AD",
		"a&b=c": "a%26b%3Dc",
		"":      "",
		"北京 公司": "%E5%8C%97%E4%BA%AC+%E5%85%AC%E5%8F%B8",
	}
	for in, want := range cases {
		if got := urlQueryEscape(in); got != want {
			t.Errorf("urlQueryEscape(%q) = %q, want %q", in, got, want)
		}
	}
}
