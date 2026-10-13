package acllm

// Rate-limit decorator smoke tests: the token-bucket limiter lets a burst
// through instantly, then smooths to the configured rate; the OnWait hook
// reports blocking; a cancelled context aborts the wait.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/eino/schema"
)

func TestRateLimitUnlimitedWhenNoWindows(t *testing.T) {
	if l := newRateLimiter(nil); l != nil {
		t.Fatal("nil RateLimit must build no limiter")
	}
	if l := newRateLimiter(&RateLimit{}); l != nil {
		t.Fatal("all-zero RateLimit must build no limiter")
	}
}

func TestRateLimitBurstPassesInstantlyThenBlocks(t *testing.T) {
	var blocked atomic.Int64
	fm := newFakeModel(func(int) (*schema.Message, error) {
		return schema.AssistantMessage("ok", nil), nil
	})
	rl := &RateLimit{PerSecond: 50, Burst: 1, OnWait: func(d time.Duration) { blocked.Add(int64(d)) }}
	m := &rateLimitedModel{next: newRetryModel(fm, Config{MaxRetries: -1}), l: newRateLimiter(rl)}

	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
			t.Fatalf("Generate %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	if fm.count() != 3 {
		t.Errorf("calls = %d, want 3", fm.count())
	}
	// Burst 1: first call instant, the next two smooth to 20ms each.
	if elapsed < 30*time.Millisecond {
		t.Errorf("elapsed = %v, want >= ~40ms of smoothing", elapsed)
	}
	if blocked.Load() == 0 {
		t.Error("OnWait never reported blocking")
	}
}

func TestRateLimitWaitAbortsOnCancelledContext(t *testing.T) {
	fm := newFakeModel(func(int) (*schema.Message, error) { return schema.AssistantMessage("ok", nil), nil })
	rl := &RateLimit{PerSecond: 0.01} // 1 request per 100s: any wait is effectively forever
	m := &rateLimitedModel{next: fm, l: newRateLimiter(rl)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.Generate(ctx, []*schema.Message{schema.UserMessage("hi")})
	if err == nil {
		t.Fatal("want the cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if fm.count() != 0 {
		t.Errorf("the wrapped model must not be reached, calls = %d", fm.count())
	}
}

func TestRateLimitWithToolsAndStreamPassthrough(t *testing.T) {
	fm := newFakeModel(func(int) (*schema.Message, error) { return schema.AssistantMessage("ok", nil), nil })
	rl := &RateLimit{PerSecond: 10000}
	m0 := &rateLimitedModel{next: newRetryModel(fm, Config{MaxRetries: -1}), l: newRateLimiter(rl)}
	tool, err := ToolSchemaToInfo(ToolSchema{Name: "t", Description: "d"})
	if err != nil {
		t.Fatalf("ToolSchemaToInfo: %v", err)
	}
	m, err := m0.WithTools([]*schema.ToolInfo{tool})
	if err != nil {
		t.Fatalf("WithTools: %v", err)
	}
	if _, err := m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sr, err := m.Stream(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if _, err := sr.Recv(); err != nil {
		t.Fatalf("Recv: %v", err)
	}
	sr.Close()
	if len(fm.lastTools()) != 1 {
		t.Errorf("tools lost through the limiter: %v", fm.lastTools())
	}
}
