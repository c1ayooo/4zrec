package enterprise

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// webClient is the shared outbound client for enterprise data sources. It
// keeps browser-like headers and cookies, but every request goes through the
// injected core.Fetcher (rate limit + audit, external scope).
type webClient struct {
	base    string
	fetcher core.Fetcher
	proxy   string
	timeout time.Duration
	headers map[string]string
}

const webBodyLimit = 4 << 20 // single response limit

func newWebClient(fetcher core.Fetcher, base, proxy string, timeout time.Duration) (*webClient, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("enterprisekit: Fetcher 未注入")
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("数据源地址无效: %w", err)
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &webClient{
		base: strings.TrimRight(base, "/"), fetcher: fetcher, proxy: proxy, timeout: timeout,
		headers: map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
			"Accept":          "application/json, text/plain, */*",
			"Accept-Language": "zh-CN,zh;q=0.9",
		},
	}, nil
}

func (w *webClient) doRaw(ctx context.Context, method, path string, body io.Reader, isJSON bool, extra map[string]string) (*core.Response, error) {
	if !strings.HasPrefix(path, "http") {
		path = w.base + path
	}
	var data []byte
	if body != nil {
		var err error
		data, err = io.ReadAll(io.LimitReader(body, webBodyLimit))
		if err != nil {
			return nil, err
		}
	}
	headers := make(map[string]string, len(w.headers)+len(extra)+1)
	for k, v := range w.headers {
		headers[k] = v
	}
	for k, v := range extra {
		if v != "" {
			headers[k] = v
		}
	}
	if isJSON {
		headers["Content-Type"] = "application/json;charset=UTF-8"
	}
	resp, err := w.fetcher.Fetch(ctx, core.Request{
		Method: method, URL: path, Headers: headers, Body: data, Proxy: w.proxy, Timeout: w.timeout,
	})
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("上游状态码 %d（会话可能过期）", resp.Status)
	}
	return resp, nil
}

// do returns the response body as text.
func (w *webClient) do(ctx context.Context, method, path string, body io.Reader, isJSON bool, extra map[string]string) (string, error) {
	resp, err := w.doRaw(ctx, method, path, body, isJSON, extra)
	if err != nil {
		return "", err
	}
	return string(resp.Body), nil
}

func (w *webClient) getJSON(ctx context.Context, path string, extra map[string]string) (string, error) {
	return w.do(ctx, http.MethodGet, path, nil, false, extra)
}

func (w *webClient) postJSON(ctx context.Context, path, body string, extra map[string]string) (string, error) {
	return w.do(ctx, http.MethodPost, path, strings.NewReader(body), true, extra)
}

// urlQueryEscape 查询串转义（adapter 内共用）。
func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}
