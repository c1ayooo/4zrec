package server

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/orchestration/agent"
)

// TestSeedReconAgent 预置完整性:agent 行/提示词/触发策略/工具绑定/OnTaskCreate
// 触发器/幂等。真连 PostgreSQL,无库跳过。
func TestSeedReconAgent(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	// 清掉一次性 flag(允许重复播种测试),并清理可能存在的旧行。
	// 注意用 defer(先于 m.Close 执行)——t.Cleanup 在全部 defer 之后跑,
	// 那时连接已关,删除会静默失败留下脏行,毒化后续测试。
	_ = m.pg.SetSetting("recon_agent_seed_v1", "")
	defer func() {
		_, _ = m.pg.Exec(`DELETE FROM agent_triggers WHERE agent_key='recon'`)
		_, _ = m.pg.Exec(`DELETE FROM agents WHERE key='recon'`)
		_ = m.pg.SetSetting("recon_agent_seed_v1", "")
	}()

	s.seedSpacemapTools() // 先播种收集工具的工具表行(生产启动序列在前)
	s.seedReconAgent()

	a, err := m.pg.GetAgentByKey("recon")
	if err != nil || a == nil {
		t.Fatalf("recon agent 未创建: %v", err)
	}
	// 口径更新:recon 为内置角色(不可删除,提示词仍可编辑)。
	if !a.Builtin || !a.Enabled {
		t.Fatalf("recon 应为内置启用的 agent: %+v", a)
	}
	// 可独立绑定 LLM profile 的前提是 agents.llm_profile_id 列存在(默认 NULL=继承)。
	if a.LLMProfileID != nil {
		t.Fatalf("播种不应指定 LLM profile: %+v", a.LLMProfileID)
	}

	// 提示词已播种且为侦察方法论。
	cur, err := m.pg.CurrentPrompt(a.ID)
	if err != nil || cur == "" {
		t.Fatalf("提示词未播种: %q %v", cur, err)
	}
	if !strings.Contains(cur, "信息收集 agent") || !strings.Contains(cur, "space_search_batch") || !strings.Contains(cur, "范围纪律") {
		t.Fatalf("提示词内容不符(方法论/工具面/纪律缺失)")
	}
	if cur != agent.ReconDefaultPrompt {
		t.Fatalf("播种提示词应等于代码默认")
	}

	// 触发器:OnTaskCreate、串行、不合并。
	trs, err := m.pg.ListTriggersFor("recon")
	if err != nil || len(trs) != 1 {
		t.Fatalf("触发器数量异常: %v %v", trs, err)
	}
	tr := trs[0]
	if !tr.Enabled || !tr.OnTaskCreate {
		t.Fatalf("应为启用的任务创建触发器: %+v", tr)
	}
	if !strings.Contains(tr.TaskCreateMessage, "list_assets") || !strings.Contains(tr.TaskCreateMessage, "不主动探测") {
		t.Fatalf("触发消息应包含清扫剧本与范围纪律: %q", tr.TaskCreateMessage)
	}
	if a.TriggerRunMode != "serial" || a.TriggerMergeMode != "none" || a.TriggerMaxParallel != 1 {
		t.Fatalf("触发运行策略应为 serial/none/1: %+v", a)
	}

	// 工具绑定:收集工具 + 资产工具。
	tools, err := m.pg.ListTools()
	if err != nil {
		t.Fatal(err)
	}
	bound := map[string]bool{}
	for _, tl := range tools {
		if tl.Enabled {
			for _, ag := range tl.Agents {
				if ag == "recon" {
					bound[tl.Key] = true
				}
			}
		}
	}
	for _, want := range []string{
		"info_collect_capabilities", "space_search", "space_search_batch",
		"icp_expand", "cert_expand", "asn_expand",
		"subdomain_enum", "subdomain_brute",
		"list_assets", "insert_assets", "add_task_scope",
	} {
		if !bound[want] {
			t.Fatalf("recon 应绑定工具 %s (实绑: %v)", want, bound)
		}
	}

	// 幂等:flag 置位后再调不重复创建触发器。
	s.seedReconAgent()
	trs2, _ := m.pg.ListTriggersFor("recon")
	if len(trs2) != 1 {
		t.Fatalf("重复播种不应叠加触发器: %d", len(trs2))
	}
}

// TestReconAgentDeletableByUser 用户删除后不被重建(flag 已置位)。
func TestReconAgentDeletableByUser(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	defer func() { _ = m.pg.SetSetting("recon_agent_seed_v1", "") }() // 先于 Close 执行

	_ = m.pg.SetSetting("recon_agent_seed_v1", "true") // 已播种过
	s.seedReconAgent()
	if a, _ := m.pg.GetAgentByKey("recon"); a != nil {
		_, _ = m.pg.Exec(`DELETE FROM agent_triggers WHERE agent_key='recon'`)
		_, _ = m.pg.Exec(`DELETE FROM agents WHERE key='recon'`)
		t.Fatal("flag 置位时不应重建 agent")
	}
}
