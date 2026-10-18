package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestTaskAgentsReceiveGuardHooks 钉住 planner/mainagent 与 worker 共用同一套
// 安全边界；它们都有 Bash/Read/Write，漏挂 Guard 会让提示注入绕过整个拦截/围栏。
func TestTaskAgentsReceiveGuardHooks(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	task, err := s.m.CreateTask("guard wiring", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	bundle := s.agentsForTask(task)
	if bundle == nil || bundle.pl == nil || bundle.main == nil {
		t.Fatal("agentsForTask returned an incomplete bundle")
	}
	if !bundle.pl.GuardHooksSet() {
		t.Fatal("planner missing guard hooks")
	}
	if !bundle.main.GuardHooksSet() {
		t.Fatal("mainagent missing guard hooks")
	}
}

// TestPauseAllTasks 验证全局急停接口：无需枚举 ID，暂停所有非终态任务。
func TestPauseAllTasks(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	a, err := s.m.CreateTask("pause-all A", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = s.m.DeleteTask(a.ID, DeleteTaskOptions{}) }()
	b, err := s.m.CreateTask("pause-all B", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = s.m.DeleteTask(b.ID, DeleteTaskOptions{}) }()

	rec := request("POST", "/api/tasks/control/pause-all", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Paused int                `json:"paused"`
		Items  []batchControlItem `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Paused < 2 {
		t.Fatalf("paused = %d, want >= 2; body=%s", out.Paused, rec.Body.String())
	}
	for _, want := range []string{a.ID, b.ID} {
		found := false
		for _, item := range out.Items {
			if item.ID == want && item.OK {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("task %s not paused; items=%+v", want, out.Items)
		}
		if !s.engine.IsPaused(want) {
			t.Fatalf("task %s engine not paused", want)
		}
	}
}

// TestICPExpandAuthorizeRequiresProjectContext 验证范围扩容不能在没有任务/会话
// 项目上下文时自批；模型传的 project_id 不能绕过。
func TestICPExpandAuthorizeRequiresProjectContext(t *testing.T) {
	s := &Server{}
	tool := s.toolIcpExpand()
	res, err := tool.Call(context.Background(), json.RawMessage(
		`{"icp":"粤ICP备00000000号","authorize":true,"domains":["example.com"],"project_id":123}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "项目上下文") {
		t.Fatalf("authorize without project context should be rejected, got: %s", res.Flatten())
	}
}
