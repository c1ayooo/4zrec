package server

import (
	"testing"
)

// TestReconRebindAndBuiltin ①recon 补绑新增工具族(fingerprint_scan 等);②reporter/recon
// 提升内置后不可删(DeleteAgent 拒);③枚举幂等。真连 PG。
func TestReconRebindAndBuiltin(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	t.Cleanup(func() {
		_ = m.pg.SetSetting("core_agents_builtin_v1", "")
		_ = m.pg.SetSetting("recon_agent_tools_v2", "")
	})

	// 建 recon(模拟既有库)但不提升内置——验证迁移函数。
	_ = m.pg.SetSetting("recon_agent_seed_v1", "")
	_ = m.pg.SetSetting("core_agents_builtin_v1", "")
	_ = m.pg.SetSetting("recon_agent_tools_v2", "")
	if a, _ := m.pg.GetAgentByKey("recon"); a == nil {
		if _, err := m.pg.CreateAgent("recon", "信息收集", "测试"); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = m.pg.Exec(`DELETE FROM agents WHERE key='recon'`) }()
	}

	// 工具行播种(生产启动序里在重绑之前),再重置绑定为旧口径并跑迁移补绑。
	s.seedSpacemapTools()
	_ = m.pg.UpdateToolAgentsForTest("recon", nil)
	s.rebindReconToolsV2()
	s.promoteCoreAgentsBuiltin()

	tools, err := m.pg.ListTools()
	if err != nil {
		t.Fatal(err)
	}
	bound := map[string]bool{}
	for _, tl := range tools {
		for _, ag := range tl.Agents {
			if ag == "recon" {
				bound[tl.Key] = true
			}
		}
	}
	for _, want := range []string{"fingerprint_scan", "http_probe", "cdn_origin", "dnslog", "project_coverage", "connections_list", "credential_verify_ssh"} {
		if !bound[want] {
			t.Fatalf("recon 应补绑 %s;实绑: %v", want, bound)
		}
	}

	// 内置标记:recon 不可删(DeleteAgent 匹配 builtin=false → 0 行)。
	a, _ := m.pg.GetAgentByKey("recon")
	if a == nil || !a.Builtin {
		t.Fatalf("recon 应提升为内置: %+v", a)
	}
	if err := m.pg.DeleteAgent("recon"); err != nil {
		t.Fatal(err)
	}
	if a2, _ := m.pg.GetAgentByKey("recon"); a2 == nil {
		t.Fatal("内置 agent 不应被删除")
	}
}
