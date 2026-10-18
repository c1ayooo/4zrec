package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestDrainInFlightAfter 验证 goal-met 软收尾：worker 在窗口内自然结束就不取消；
// 超过窗口仍有在跑操作才硬取消。
func TestDrainInFlightAfter(t *testing.T) {
	ctx := context.Background()

	e := &Engine{execCancel: map[string]context.CancelCauseFunc{}}
	var canceled atomic.Bool
	e.execCancel["t1"] = func(error) { canceled.Store(true) }
	atomic.AddInt64(e.inflightCounter("t1"), 1)
	e.drainInFlightAfter(ctx, "t1", 20*time.Millisecond, errors.New("goal met"))
	time.Sleep(200 * time.Millisecond)
	if !canceled.Load() {
		t.Fatal("stuck in-flight operation should be canceled after grace")
	}

	e2 := &Engine{execCancel: map[string]context.CancelCauseFunc{}}
	var canceled2 atomic.Bool
	e2.execCancel["t2"] = func(error) { canceled2.Store(true) }
	atomic.AddInt64(e2.inflightCounter("t2"), 1)
	e2.drainInFlightAfter(ctx, "t2", 500*time.Millisecond, errors.New("goal met"))
	atomic.AddInt64(e2.inflightCounter("t2"), -1) // worker finished within grace
	time.Sleep(100 * time.Millisecond)
	if canceled2.Load() {
		t.Fatal("drained operation must not be canceled")
	}
}
