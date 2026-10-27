package enterprise

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// errNoRoute 模拟传输层不可达。
var errNoRoute = errors.New("simulated transport failure")

// fetchFunc 适配函数为 core.Fetcher，便于内联桩响应。
type fetchFunc func(ctx context.Context, req core.Request) (*core.Response, error)

func (f fetchFunc) Fetch(ctx context.Context, req core.Request) (*core.Response, error) {
	return f(ctx, req)
}

// json200 构造 200 JSON 响应。
func json200(body string) *core.Response {
	return &core.Response{
		Status:  200,
		Body:    []byte(body),
		Headers: map[string][]string{"Content-Type": {"application/json"}},
	}
}

// statusResp 构造任意状态码响应。
func statusResp(status int, body string) *core.Response {
	return &core.Response{Status: status, Body: []byte(body)}
}

// stubRoute 一条「URL 子串 → 预置响应」的路由规则，按声明顺序匹配。
type stubRoute struct {
	sub  string
	resp *core.Response
}

// stubFetcher 按 URL 子串分发预置响应并记录收到的请求。provider 里的绝对
// 地址常量由它接管，测试全程不触网。
type stubFetcher struct {
	mu     sync.Mutex
	routes []stubRoute
	seen   []core.Request
	err    error
}

func newStubFetcher(routes ...stubRoute) *stubFetcher {
	return &stubFetcher{routes: routes}
}

// failWith 让后续所有请求返回传输层错误。
func (s *stubFetcher) failWith(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *stubFetcher) Fetch(_ context.Context, req core.Request) (*core.Response, error) {
	s.mu.Lock()
	s.seen = append(s.seen, req)
	s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	for _, r := range s.routes {
		if strings.Contains(req.URL, r.sub) {
			return r.resp, nil
		}
	}
	return statusResp(404, fmt.Sprintf(`{"status":-1,"message":"stubFetcher: no route for %s"}`, req.URL)), nil
}

func (s *stubFetcher) requests() []core.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]core.Request, len(s.seen))
	copy(out, s.seen)
	return out
}

// last 返回最近一次请求，用于断言 URL / 头 / 体。
func (s *stubFetcher) last(t *testing.T) core.Request {
	t.Helper()
	reqs := s.requests()
	if len(reqs) == 0 {
		t.Fatal("stubFetcher: 没有记录到请求")
	}
	return reqs[len(reqs)-1]
}

// routeFor 按 URL 子串找一条已记录请求。
func (s *stubFetcher) routeFor(t *testing.T, sub string) core.Request {
	t.Helper()
	for _, req := range s.requests() {
		if strings.Contains(req.URL, sub) {
			return req
		}
	}
	t.Fatalf("stubFetcher: 没有匹配 %q 的请求", sub)
	return core.Request{}
}

// countFor 统计匹配 URL 子串的请求次数。
func (s *stubFetcher) countFor(sub string) int {
	n := 0
	for _, req := range s.requests() {
		if strings.Contains(req.URL, sub) {
			n++
		}
	}
	return n
}
