package acllm

import (
	"context"
	"sync"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// Port of norma llm/ratelimit.go: a token-bucket/window limiter shared by every
// call through one built model, applied once per logical request (before the
// retry decorator, so retries do not consume additional tokens).

// rateLimiter enforces PerSecond AND PerMinute simultaneously. Safe for
// concurrent use by many goroutines. A nil *rateLimiter is a no-op (unlimited).
type rateLimiter struct {
	sec    *bucket
	min    *bucket
	onWait func(time.Duration)
}

func newRateLimiter(rl *RateLimit) *rateLimiter {
	if rl == nil || (rl.PerSecond <= 0 && rl.PerMinute <= 0) {
		return nil // unlimited
	}
	l := &rateLimiter{onWait: rl.OnWait}
	if rl.PerSecond > 0 {
		burst := rl.Burst
		if burst <= 0 {
			burst = rl.PerSecond
		}
		l.sec = newBucket(rl.PerSecond, burst)
	}
	if rl.PerMinute > 0 {
		l.min = newBucket(rl.PerMinute/60.0, rl.PerMinute) // burst = a full minute
	}
	return l
}

// Wait blocks until one request is permitted by both windows, or ctx is done.
// A nil receiver returns immediately (unlimited).
func (l *rateLimiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	var d time.Duration
	if l.sec != nil {
		d = l.sec.reserve()
	}
	if l.min != nil {
		if dm := l.min.reserve(); dm > d {
			d = dm
		}
	}
	if d <= 0 {
		l.report(0)
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		// The caller bailed; the reserved tokens are not returned (a minor
		// over-count under cancellation), which only makes the limiter slightly
		// more conservative — never less.
		return ctx.Err()
	case <-t.C:
		l.report(d)
		return nil
	}
}

func (l *rateLimiter) report(d time.Duration) {
	if l.onWait != nil {
		l.onWait(d)
	}
}

// bucket is a token bucket: tokens refill at rate/sec up to burst; reserve()
// takes one token (going negative to reserve future capacity) and returns how
// long the caller must wait for it.
type bucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rate, burst float64) *bucket {
	return &bucket{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

func (b *bucket) reserve() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	b.tokens--
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

// rateLimitedModel wraps any chat model so that all of its calls share one rate
// limit. WithTools passes through untouched (binding tools is not a request).
type rateLimitedModel struct {
	next model.ToolCallingChatModel
	l    *rateLimiter
}

func (m *rateLimitedModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	inner, err := m.next.WithTools(tools)
	if err != nil {
		return nil, err
	}
	return &rateLimitedModel{next: inner, l: m.l}, nil
}

func (m *rateLimitedModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	if err := m.l.Wait(ctx); err != nil {
		return nil, err
	}
	return m.next.Generate(ctx, input, opts...)
}

func (m *rateLimitedModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	if err := m.l.Wait(ctx); err != nil {
		return nil, err
	}
	return m.next.Stream(ctx, input, opts...)
}
