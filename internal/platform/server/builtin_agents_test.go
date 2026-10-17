package server

import (
	"encoding/json"
	"testing"
)

// TestHTTPProbePriorityBindings 验证「HTTP 请求优先 http_probe」的绑定前提:
// 独立渗透(pentest)与规划(planner)也能调用结构化 HTTP 工具。
func TestHTTPProbePriorityBindings(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	// 生产启动序:工具行播种 → recon 播种(含 http_probe 绑定) → 一次性补绑。
	// 重置 flag 以验证迁移可重跑。
	s.seedSpacemapTools()
	s.seedReconAgent()
	_ = m.pg.SetSetting("http_probe_priority_v1", "")
	s.rebindHTTPProbeAgents()

	tools, err := m.pg.ListTools()
	if err != nil {
		t.Fatal(err)
	}
	var bound map[string]bool
	for _, tl := range tools {
		if tl.Key != "http_probe" {
			continue
		}
		bound = map[string]bool{}
		for _, ag := range tl.Agents {
			bound[ag] = true
		}
	}
	if bound == nil {
		t.Fatal("http_probe 工具行不存在")
	}
	for _, want := range []string{"pentest", "planner", "worker", "recon"} {
		if !bound[want] {
			t.Fatalf("http_probe 应绑定 %s;实绑: %v", want, bound)
		}
	}

	// schema 合并:模拟旧库只带 url 参数(用户改过描述),迁移后应补齐新参数
	// 且保留旧参数原样。
	old := `{"type":"object","properties":{"url":{"type":"string","description":"user-edited"}}}`
	if err := m.pg.UpdateToolSchema("http_probe", []byte(old)); err != nil {
		t.Fatal(err)
	}
	_ = m.pg.SetSetting("http_probe_schema_v3", "")
	s.mergeHTTPProbeSchema()

	tools, err = m.pg.ListTools()
	if err != nil {
		t.Fatal(err)
	}
	var props map[string]any
	for _, tl := range tools {
		if tl.Key == "http_probe" {
			var schema map[string]any
			_ = json.Unmarshal(tl.Schema, &schema)
			props, _ = schema["properties"].(map[string]any)
		}
	}
	if props == nil {
		t.Fatal("http_probe schema 缺失")
	}
	for _, want := range []string{"url", "extract", "cookie_jar", "save_to_file", "requests", "template"} {
		if _, ok := props[want]; !ok {
			t.Fatalf("schema 应包含参数 %s;现有: %v", want, props)
		}
	}
	urlProp, _ := props["url"].(map[string]any)
	if d, _ := urlProp["description"].(string); d != "user-edited" {
		t.Fatalf("迁移不应覆盖用户改过的参数描述, got %q", d)
	}
}

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
