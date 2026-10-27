package gates

import (
	"context"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type bucket struct {
	tokens float64
	last   time.Time
	spec   core.RateLimitSpec
}

// Limiter is a per-key token bucket plus a per-key concurrency semaphore.
// Keys are typically hostnames. The host injects it; kits cannot bypass it
// because the only HTTP/process entry points call Acquire.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	slots   map[string]chan struct{}
	now     func() time.Time
}

func NewLimiter() *Limiter {
	return NewLimiterWithClock(time.Now)
}

func NewLimiterWithClock(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		buckets: map[string]*bucket{},
		slots:   map[string]chan struct{}{},
		now:     now,
	}
}

func (l *Limiter) Acquire(ctx context.Context, key string, spec core.RateLimitSpec) (func(), error) {
	spec = spec.Normalized()
	if spec.PerSecond <= 0 {
		spec.PerSecond = 5
	}
	if spec.Burst <= 0 {
		spec.Burst = 1
	}
	if spec.Concurrency <= 0 {
		spec.Concurrency = 4
	}
	if key == "" {
		key = "global"
	}
	if err := l.waitToken(ctx, key, spec); err != nil {
		return nil, err
	}
	slot := l.slot(key, spec.Concurrency)
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, nil
	case <-ctx.Done():
		return nil, core.NewError(core.CodeRateLimited, "rate limit wait cancelled")
	}
}

func (l *Limiter) waitToken(ctx context.Context, key string, spec core.RateLimitSpec) error {
	for {
		l.mu.Lock()
		b := l.buckets[key]
		now := l.now()
		if b == nil {
			b = &bucket{tokens: float64(spec.Burst), last: now, spec: spec}
			l.buckets[key] = b
		}
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * spec.PerSecond
			if b.tokens > float64(spec.Burst) {
				b.tokens = float64(spec.Burst)
			}
			b.last = now
		}
		b.spec = spec
		if b.tokens >= 1 {
			b.tokens -= 1
			l.mu.Unlock()
			return nil
		}
		need := (1 - b.tokens) / spec.PerSecond
		l.mu.Unlock()

		timer := time.NewTimer(time.Duration(need * float64(time.Second)))
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return core.NewError(core.CodeRateLimited, "rate limit wait cancelled")
		}
	}
}

func (l *Limiter) slot(key string, concurrency int) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	ch := l.slots[key]
	if ch == nil || cap(ch) != concurrency {
		ch = make(chan struct{}, concurrency)
		l.slots[key] = ch
	}
	return ch
}
