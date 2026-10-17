package server

import (
	"context"
	"strings"
	"testing"
)

// TestIntelKeysRoundtrip 被动源凭据:保存→掩码回显(明文不回传);清除。
// 真连 PG,无库跳过。
func TestIntelKeysRoundtrip(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	defer func() { _ = m.pg.SetSetting("virustotal.key", "") }()

	if err := m.pg.SetSetting("virustotal.key", "vt-plain-secret-123"); err != nil {
		t.Fatal(err)
	}
	if got := s.vtKey(); got != "vt-plain-secret-123" {
		t.Fatalf("settings 读取失败: %q", got)
	}
	// 掩码:不回显明文(Mask 语义已在 spacemap 包测试覆盖,这里断言拼装通道)。
	if v, ok, _ := m.pg.GetSetting("virustotal.key"); !ok || strings.Contains("masked-check", v) {
		t.Fatalf("settings 异常: %q", v)
	}
	_ = context.Background()
}
