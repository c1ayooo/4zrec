package collect

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPolicyFor(t *testing.T) {
	if p := PolicyFor("quake"); p.MinInterval != 2*time.Second || p.MaxInflight != 1 {
		t.Fatalf("quake 策略应为单飞 2s: %+v", p)
	}
	if p := PolicyFor("OTX "); p.MaxInflight != 2 {
		t.Fatalf("otx 应放宽到 2 路（大小写/空白归一）: %+v", p)
	}
	if p := PolicyFor("unknown-src"); p.MaxInflight != 1 || p.MinInterval != time.Second {
		t.Fatalf("未知源应回退保守默认: %+v", p)
	}
}

func TestClassifyError(t *testing.T) {
	if ClassifyError(nil) != ErrorClassOther {
		t.Fatal("nil 应为 Other")
	}
	if !IsTransientError(errors.New("quake: 调用API过于频繁")) {
		t.Fatal("限流应识别为瞬态")
	}
	if !IsTransientError(errors.New("HTTP 429 Too Many Requests")) {
		t.Fatal("429 应识别为瞬态")
	}
	if !IsAuthError(errors.New("fofa: 未配置 API Key")) {
		t.Fatal("未配置 key 应识别为鉴权类")
	}
	if !IsAuthError(errors.New("hunter: 余额不足")) {
		t.Fatal("欠费应识别为鉴权类")
	}
	if ClassifyError(errors.New("页面解析失败")) != ErrorClassOther {
		t.Fatal("普通错误应为 Other")
	}
}

// 全部单元执行且结果可取。
func TestRunUnitsAllComplete(t *testing.T) {
	SetPolicy("src-a", SourcePolicy{MaxInflight: 2, MinInterval: time.Millisecond})
	defer SetPolicy("src-a", SourcePolicy{MaxInflight: 1, MinInterval: time.Second})
	s := NewScheduler()
	var ran atomic.Int32
	units := make([]Unit, 0, 5)
	for i := 0; i < 5; i++ {
		units = append(units, Unit{Source: "src-a", Run: func(ctx context.Context) error {
			ran.Add(1)
			return nil
		}})
	}
	outcomes := s.RunUnits(context.Background(), units, 0)
	if ran.Load() != 5 {
		t.Fatalf("应执行 5 个单元, got %d", ran.Load())
	}
	for i, o := range outcomes {
		if o.Err != nil || o.Skipped {
			t.Fatalf("单元 %d 不应失败: %+v", i, o)
		}
	}
}

// 同源 MaxInflight 约束生效（单飞源任意时刻只有一路在跑）。
func TestRunUnitsRespectsMaxInflight(t *testing.T) {
	SetPolicy("solo", SourcePolicy{MaxInflight: 1, MinInterval: time.Millisecond})
	defer SetPolicy("solo", SourcePolicy{MaxInflight: 1, MinInterval: time.Second})
	s := NewScheduler()
	var cur, max atomic.Int32
	units := make([]Unit, 0, 6)
	for i := 0; i < 6; i++ {
		units = append(units, Unit{Source: "solo", Run: func(ctx context.Context) error {
			n := cur.Add(1)
			for {
				old := max.Load()
				if n <= old || max.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			cur.Add(-1)
			return nil
		}})
	}
	s.RunUnits(context.Background(), units, 0)
	if max.Load() > 1 {
		t.Fatalf("单飞源并发应恒为 1, got %d", max.Load())
	}
}

// 瞬态错误重试 1 次后成功。
func TestRunUnitsTransientRetry(t *testing.T) {
	SetPolicy("src", SourcePolicy{MaxInflight: 1, MinInterval: time.Millisecond})
	defer SetPolicy("src", SourcePolicy{MaxInflight: 1, MinInterval: time.Second})
	s := NewScheduler()
	var attempts atomic.Int32
	units := []Unit{{Source: "src", Run: func(ctx context.Context) error {
		if attempts.Add(1) == 1 {
			return errors.New("HTTP 429")
		}
		return nil
	}}}
	outcomes := s.RunUnits(context.Background(), units, 0)
	if attempts.Load() != 2 {
		t.Fatalf("瞬态错误应重试一次, attempts=%d", attempts.Load())
	}
	if outcomes[0].Err != nil || outcomes[0].Attempts != 2 {
		t.Fatalf("重试后应成功: %+v", outcomes[0])
	}
}

// 同源连续 2 个单元瞬态终败 → 短路该源剩余单元。
func TestRunUnitsCircuitOpen(t *testing.T) {
	s := NewScheduler()
	SetPolicy("flaky", SourcePolicy{MaxInflight: 1, MinInterval: time.Millisecond})
	defer SetPolicy("flaky", SourcePolicy{MaxInflight: 1, MinInterval: time.Second})
	var okRun, failRun atomic.Int32
	units := []Unit{
		{Source: "flaky", Run: func(ctx context.Context) error { failRun.Add(1); return errors.New("503") }},
		{Source: "flaky", Run: func(ctx context.Context) error { failRun.Add(1); return errors.New("429") }},
		{Source: "flaky", Run: func(ctx context.Context) error { okRun.Add(1); return nil }},
	}
	outcomes := s.RunUnits(context.Background(), units, 0)
	if failRun.Load() != 4 {
		t.Fatalf("两个失败单元应各含一次重试: %d", failRun.Load())
	}
	if okRun.Load() != 0 {
		t.Fatal("第三个单元应被短路跳过")
	}
	if !outcomes[2].Skipped || outcomes[2].SkipReason != "source circuit-open" {
		t.Fatalf("短路跳过语义缺失: %+v", outcomes[2])
	}
}

// 鉴权类错误不重试、不短路后续单元（每个都独立失败）。
func TestRunUnitsAuthNoRetry(t *testing.T) {
	SetPolicy("src", SourcePolicy{MaxInflight: 1, MinInterval: time.Millisecond})
	defer SetPolicy("src", SourcePolicy{MaxInflight: 1, MinInterval: time.Second})
	s := NewScheduler()
	var attempts atomic.Int32
	units := []Unit{
		{Source: "src", Run: func(ctx context.Context) error { attempts.Add(1); return errors.New("未配置 API Key") }},
		{Source: "src", Run: func(ctx context.Context) error { attempts.Add(1); return errors.New("未配置 API Key") }},
	}
	outcomes := s.RunUnits(context.Background(), units, 0)
	if attempts.Load() != 2 {
		t.Fatalf("鉴权类不应重试, attempts=%d", attempts.Load())
	}
	for i, o := range outcomes {
		if o.Skipped || o.Err == nil {
			t.Fatalf("单元 %d 应为独立失败: %+v", i, o)
		}
	}
}

// ctx 取消时 pending 单元标记 canceled。
func TestRunUnitsContextCancel(t *testing.T) {
	s := NewScheduler()
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(1)
	units := []Unit{
		{Source: "src", Run: func(ctx context.Context) error {
			started.Done()
			<-release
			return nil
		}},
		{Source: "src", Run: func(ctx context.Context) error { return nil }},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		started.Wait()
		cancel()
		close(release)
	}()
	outcomes := s.RunUnits(ctx, units, 1)
	if !outcomes[1].Skipped {
		t.Fatalf("被取消的单元应标记 skipped: %+v", outcomes[1])
	}
}

// 源状态跨 RunUnits 保持：第二阶段的首次开工仍须与第一阶段隔开 MinInterval。
func TestSchedulerStatePersistsAcrossRuns(t *testing.T) {
	s := NewScheduler()
	SetPolicy("paced", SourcePolicy{MaxInflight: 1, MinInterval: 80 * time.Millisecond})
	defer SetPolicy("paced", SourcePolicy{MaxInflight: 1, MinInterval: time.Second})
	var stamps []time.Time
	var mu sync.Mutex
	unit := Unit{Source: "paced", Run: func(ctx context.Context) error {
		mu.Lock()
		stamps = append(stamps, time.Now())
		mu.Unlock()
		return nil
	}}
	s.RunUnits(context.Background(), []Unit{unit}, 0)
	s.RunUnits(context.Background(), []Unit{unit}, 0)
	mu.Lock()
	defer mu.Unlock()
	if len(stamps) != 2 {
		t.Fatalf("应执行两次, got %d", len(stamps))
	}
	if gap := stamps[1].Sub(stamps[0]); gap < 60*time.Millisecond {
		t.Fatalf("跨阶段最小间隔未生效, gap=%s", gap)
	}
}
