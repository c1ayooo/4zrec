package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestProjectTargetsValue 与 ZREC_TARGETS 注入语义：值 = 项目范围(domain/ip/cidr)
// ∪ approved 资产；未挂项目/无项目上下文不注入；agent 绑定解析按任务/会话定位项目。
func TestProjectTargetsValue(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())

	stamp := time.Now().UnixNano()
	p, err := m.pg.Projects().CreateProject("targets-env"+string(rune(stamp%1000)), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.Projects().DeleteProject(p.ID) })
	if added, _, _, errs := m.pg.Projects().AddProjectScope(p.ID, []string{"scope.example.com", "10.8.0.0/24"}, "test"); added == 0 && len(errs) > 0 {
		t.Fatalf("AddProjectScope: %v", errs)
	}
	// 一条 approved 资产(批准即授权目标也进变量)。
	aid, err := m.pg.EnsureDiscoveredAsset(p.ID, "ip", "", "203.0.113.77")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.Assets().SetAssetAuthz([]int64{aid}, "approved"); err != nil {
		t.Fatal(err)
	}

	v, ok := s.projectTargetsValue(p.ID)
	if !ok {
		t.Fatal("projectTargetsValue should read successfully")
	}
	for _, want := range []string{"scope.example.com", "10.8.0.0/24", "203.0.113.77"} {
		if !strings.Contains(" "+v+" ", " "+want+" ") {
			t.Fatalf("targets value missing %q: %q", want, v)
		}
	}

	// 任务侧闭包:任务挂项目后注入 ZREC_TARGETS。
	task, err := m.pg.CreateTask("targets-env", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })
	if _, err := m.pg.Exec(`UPDATE tasks SET project_id=$1 WHERE id=$2`, p.ID, task.ID); err != nil {
		t.Fatal(err)
	}
	env := s.targetsEnvForTask(strconv.FormatInt(task.ID, 10))("ignored-session")
	if len(env) != 1 || !strings.HasPrefix(env[0], "ZREC_TARGETS=") {
		t.Fatalf("targetsEnvForTask = %v", env)
	}

	// 未挂项目的任务 → 不注入。
	task2, err := m.pg.CreateTask("targets-env-noproj", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, task2.ID) })
	if env := s.targetsEnvForTask(strconv.FormatInt(task2.ID, 10))("ignored"); env != nil {
		t.Fatalf("task without project should not inject, got %v", env)
	}

	// chat 侧闭包:conv-<id> 形态的会话键。
	conv, err := m.pg.CreateConversation("auto", "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteConversation(conv.ID) })
	if _, err := m.pg.Exec(`UPDATE conversations SET project_id=$1 WHERE id=$2`, p.ID, conv.ID); err != nil {
		t.Fatal(err)
	}
	if env := s.targetsEnvForConv()("conv-" + strconv.FormatInt(conv.ID, 10)); len(env) != 1 {
		t.Fatalf("targetsEnvForConv = %v", env)
	}
	if env := s.targetsEnvForConv()("task-other-key"); env != nil {
		t.Fatalf("non-conv session key should not inject, got %v", env)
	}
}
