package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/db"
)

// TestReconScheduleEngineIncremental 引擎形态执行体端到端:桩引擎→建任务→执行
// →资产入库+last_new>0;再执行一轮→last_new=0(增量幂等)。真连 PG,无库跳过。
func TestReconScheduleEngineIncremental(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	domain := fmt.Sprintf("sched-%d.example", stamp)
	host := "www." + domain

	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": false, "size": 1, "page": 1, "total": 1,
			"results": [][]any{{host, "198.51.100.7", float64(443), host, "站点", "https"}},
		})
	}))
	defer stub.Close()
	if err := m.pg.SetSetting("spacemap.key.fofa", "test-key"); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting("spacemap.baseurl.fofa", stub.URL); err != nil {
		t.Fatal(err)
	}
	// 注意 defer(而非 t.Cleanup):t.Cleanup 在 defer m.Close 之后执行,连接已关。
	defer func() {
		_, _ = m.pg.Exec(`DELETE FROM assets WHERE domain LIKE '%` + domain + `'`)
		_, _ = m.pg.Exec(`DELETE FROM recon_schedules`)
		_ = m.pg.SetSetting("spacemap.key.fofa", "")
		_ = m.pg.SetSetting("spacemap.baseurl.fofa", "")
	}()

	cfg, _ := json.Marshal(map[string]any{"domains": []string{domain}, "engines": []string{"fofa"}})
	id, err := m.pg.CreateReconSchedule(context.Background(), &db.ReconSchedule{
		Name: "增量测试", Kind: "engine", Config: cfg, IntervalSec: 1800,
	})
	if err != nil {
		t.Fatal(err)
	}

	s.executeReconSchedule(id)
	sc, err := m.pg.GetReconSchedule(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if sc.LastNew != 1 || !strings.Contains(sc.LastResult, "新资产 1") {
		t.Fatalf("首轮应计 1 个新资产: last_new=%d result=%s", sc.LastNew, sc.LastResult)
	}
	var found int
	if err := m.pg.QueryRow(`SELECT count(*) FROM assets WHERE domain=$1`, host).Scan(&found); err != nil || found == 0 {
		t.Fatalf("资产未入库: %d %v", found, err)
	}

	// 第二轮:同一资产已存在 → 增量为 0(幂等)。
	s.executeReconSchedule(id)
	sc2, err := m.pg.GetReconSchedule(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if sc2.LastNew != 0 {
		t.Fatalf("第二轮增量应为 0: %d", sc2.LastNew)
	}
	if sc2.AuthFailures != 0 || sc2.BackoffUntil != nil {
		t.Fatalf("正常执行不应熔断: %+v", sc2)
	}
}

// TestReconScheduleBackoff 鉴权失败熔断:退避窗口内不出现在到期列表,成功后清零。
func TestReconScheduleBackoff(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	cfg, _ := json.Marshal(map[string]any{"domains": []string{"backoff.example"}})
	id, err := m.pg.CreateReconSchedule(context.Background(), &db.ReconSchedule{
		Name: "熔断测试", Kind: "engine", Config: cfg, IntervalSec: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM recon_schedules`) }() // 先于 Close

	// 两次鉴权失败 → auth_failures=2、backoff 1h。
	_ = m.pg.MarkScheduleRan(context.Background(), id, 60, true, "auth failed", 0)
	if err := m.pg.MarkScheduleRan(context.Background(), id, 60, true, "auth failed", 0); err != nil {
		t.Fatal(err)
	}
	sc, _ := m.pg.GetReconSchedule(context.Background(), id)
	if sc.AuthFailures != 2 || sc.BackoffUntil == nil {
		t.Fatalf("熔断态不符: %+v", sc)
	}
	if due, _ := m.pg.ListDueSchedules(context.Background()); len(due) != 0 {
		t.Fatalf("退避窗口内不应到期: %v", due)
	}

	// 成功一轮 → 熔断清零;下一轮回归正常周期(成功收尾会把 next_run 推进一个
	// 周期,这是正常节奏;RunReconScheduleNow 再标记到期即应出现在列表)。
	if err := m.pg.MarkScheduleRan(context.Background(), id, 60, false, "ok", 2); err != nil {
		t.Fatal(err)
	}
	sc2, _ := m.pg.GetReconSchedule(context.Background(), id)
	if sc2.AuthFailures != 0 || sc2.BackoffUntil != nil {
		t.Fatalf("成功后应清零: %+v", sc2)
	}
	if err := m.pg.RunReconScheduleNow(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if due, _ := m.pg.ListDueSchedules(context.Background()); len(due) != 1 {
		t.Fatalf("熔断解除后应可正常调度: %v", due)
	}
}

// TestSchedulePipelineCreatesRun 周期 pipeline 执行落运行历史行(schedule_id 关联)。
func TestSchedulePipelineCreatesRun(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	cfg, _ := json.Marshal(map[string]any{
		"domains": []string{"no-run.example"}, "subdomain": false, "dns": false,
		"portscan": false, "http": false, "permute": false, "brute": false,
	})
	id, err := m.pg.CreateReconSchedule(context.Background(), &db.ReconSchedule{
		Name: "运行历史测试", Kind: "pipeline", Config: cfg, IntervalSec: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM recon_schedules`) }()

	result, _, _ := s.executePipelineSchedule(&db.ReconSchedule{
		ID: id, Kind: "pipeline", Config: cfg, IntervalSec: 3600,
	})
	if !strings.Contains(result, "run #") {
		t.Fatalf("结果应引用 run id: %s", result)
	}
	runs, err := m.pg.ListReconRunsForSchedule(context.Background(), id, 5)
	if err != nil || len(runs) != 1 {
		t.Fatalf("运行历史应有一行: %v %v", runs, err)
	}
	if runs[0].ScheduleID == nil || *runs[0].ScheduleID != id || runs[0].Status != "done" {
		t.Fatalf("运行行关联/状态不符: %+v", runs[0])
	}
}
