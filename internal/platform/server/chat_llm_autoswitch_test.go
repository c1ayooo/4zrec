package server

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// TestConversationLLMAutoSwitch 对话路径的 LLM 自动切换:会话 pin 的配置
// 熔断冷却中 → resolveChatAgent 自动改绑到链上下一个可用配置并落库留痕;
// 没有可用备选时保持原绑定(由全局语义回落/报错)。
func TestConversationLLMAutoSwitch(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())

	// 从干净 profile 表开始(共享库可能有其它测试残留)。
	existing, _ := m.pg.ListProfiles()
	for _, p := range existing {
		if p.IsDefault {
			_, _ = m.pg.Exec(`UPDATE llm_profiles SET is_default=false WHERE id=$1`, p.ID)
		}
		_ = m.pg.DeleteProfile(p.ID)
	}

	p1, err := m.pg.SaveProfile(&db.LLMProfile{Name: "dead", Format: "anthropic", Model: "claude-x", APIKey: "sk-test"})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := m.pg.SaveProfile(&db.LLMProfile{Name: "alive", Format: "anthropic", Model: "claude-y", APIKey: "sk-test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetActiveProfile(p2); err != nil { // 链头 = 激活配置
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.llmHealth.Reset(p1)
		s.llmHealth.Reset(p2)
		_, _ = m.pg.Exec(`UPDATE llm_profiles SET is_default=false WHERE id IN ($1,$2)`, p1, p2)
		_ = m.pg.DeleteProfile(p1)
		_ = m.pg.DeleteProfile(p2)
	})

	conv, err := m.pg.CreateConversation("auto", "autoswitch", &p1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteConversation(conv.ID) })

	// pin 的配置熔断(硬失败立即打开)→ 下一次 resolve 自动改绑到 p2。
	s.llmHealth.Trip(p1, "402 payment required", true)
	_ = s.resolveChatAgent(&db.Conversation{ID: conv.ID, AgentKey: "auto", LLMProfileID: &p1})
	got, err := m.pg.GetConversation(conv.ID)
	if err != nil || got == nil {
		t.Fatalf("reload conversation: %v %v", got, err)
	}
	if got.LLMProfileID == nil || *got.LLMProfileID != p2 {
		t.Fatalf("conversation profile = %v, want #%d (auto-switched)", got.LLMProfileID, p2)
	}

	// 全部候选都熔断 → 不改绑,保持原状。
	conv2, err := m.pg.CreateConversation("auto", "noswitch", &p2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteConversation(conv2.ID) })
	s.llmHealth.Trip(p2, "402 payment required", true)
	_ = s.resolveChatAgent(&db.Conversation{ID: conv2.ID, AgentKey: "auto", LLMProfileID: &p2})
	got2, err := m.pg.GetConversation(conv2.ID)
	if err != nil || got2 == nil {
		t.Fatalf("reload conversation2: %v %v", got2, err)
	}
	if got2.LLMProfileID == nil || *got2.LLMProfileID != p2 {
		t.Fatalf("exhausted chain should keep the pin, got %v", got2.LLMProfileID)
	}
}
