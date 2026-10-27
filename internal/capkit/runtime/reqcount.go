package runtime

import (
	"context"
	"sync/atomic"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// The runtime counts every outbound request a tool makes so the envelope can
// tell the agent how much request budget the call spent (docs §5.5.7: "Requests
// 很重要：agent 需要知道自己刚才消耗了多少请求预算"). Counting is done by
// decorating the HTTP and Fetcher ports; kits stay unaware.

type reqCounter struct{ n atomic.Int64 }

type reqCounterKey struct{}

// withRequestCounter installs a fresh per-call counter in ctx.
func withRequestCounter(ctx context.Context) context.Context {
	return context.WithValue(ctx, reqCounterKey{}, &reqCounter{})
}

// countRequest bumps the counter installed by withRequestCounter, if any.
func countRequest(ctx context.Context) {
	if c, ok := ctx.Value(reqCounterKey{}).(*reqCounter); ok {
		c.n.Add(1)
	}
}

// requestCount reads the counter installed by withRequestCounter.
func requestCount(ctx context.Context) int {
	if c, ok := ctx.Value(reqCounterKey{}).(*reqCounter); ok {
		return int(c.n.Load())
	}
	return 0
}

// countingHTTP wraps an HTTPDoer so every call is counted for the live call.
type countingHTTP struct{ inner core.HTTPDoer }

func (h countingHTTP) Do(ctx context.Context, req core.Request) (*core.Response, error) {
	countRequest(ctx)
	return h.inner.Do(ctx, req)
}

// countingFetcher wraps a Fetcher so external-data fetches are counted too.
type countingFetcher struct{ inner core.Fetcher }

func (f countingFetcher) Fetch(ctx context.Context, req core.Request) (*core.Response, error) {
	countRequest(ctx)
	return f.inner.Fetch(ctx, req)
}
