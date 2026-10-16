package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/acllm"
	actool "github.com/c1ayooo/4zrec/tools"
)

func TestDeferredSystem_NoGlobal(t *testing.T) {
	// No global MCP names → plain single-segment system (the kernel renders the
	// deferred block itself).
	sys := deferredSystem("SYS", DeferredInfo{})
	if len(sys) != 1 || sys[0] != "SYS" {
		t.Fatalf("expected [SYS] — got %v", sys)
	}
}

func TestDeferredSystem_WithGlobal(t *testing.T) {
	// Finding guidance rides the host segment. The <available-deferred-tools>
	// block itself is kernel-owned now (appended over Options.DeferredTools), so
	// the host segment must NOT duplicate it.
	def := DeferredInfo{
		Deferred:        []string{"mcp__browser__navigate", "mcp__browser__click"},
		GlobalNames:     []string{"mcp__browser__navigate", "mcp__browser__click"},
		FindingGuidance: "\n\n**guidance**",
	}
	sys := deferredSystem("SYS", def)
	if len(sys) != 1 || !strings.HasPrefix(sys[0], "SYS") || !strings.Contains(sys[0], "**guidance**") {
		t.Fatalf("expected [SYS+guidance], got %v", sys)
	}
	if strings.Contains(sys[0], "<available-deferred-tools>") {
		t.Fatalf("host segment must not duplicate the kernel's deferred block:\n%s", sys[0])
	}
}

func TestSkillCallBlocksDetectableInDTO(t *testing.T) {
	// The kernel block surfaces ALL deferred names (skill-gated included, gated
	// by the unlock set instead); seedUnlockFromHistory is what re-arms those
	// gates on resume, driven by Skill tool_use blocks in the DTO history.
	skillCall := func(name string) acllm.ContentBlock {
		return acllm.ContentBlock{Type: acllm.BlockToolUse, Name: "Skill", Input: json.RawMessage(`{"name":"` + name + `"}`)}
	}
	msgs := []acllm.Message{
		{Role: acllm.RoleAssistant, Content: []acllm.ContentBlock{skillCall("browsing")}},
	}
	var got []string
	seedUnlockFromHistory(msgs, func(name string) { got = append(got, name) })
	if len(got) != 1 || got[0] != "browsing" {
		t.Fatalf("skill calls not detectable in the DTO history: %v", got)
	}
}

func TestSeedUnlockFromHistory(t *testing.T) {
	skillCall := func(name string) acllm.ContentBlock {
		return acllm.ContentBlock{Type: acllm.BlockToolUse, Name: "Skill", Input: json.RawMessage(`{"name":"` + name + `"}`)}
	}
	msgs := []acllm.Message{
		{Role: acllm.RoleAssistant, Content: []acllm.ContentBlock{skillCall("browsing")}},
		{Role: acllm.RoleAssistant, Content: []acllm.ContentBlock{
			{Type: acllm.BlockToolUse, Name: "Bash", Input: json.RawMessage(`{}`)}, // ignored
			skillCall("recon"),
		}},
	}
	var got []string
	seedUnlockFromHistory(msgs, func(name string) { got = append(got, name) })
	if strings.Join(got, ",") != "browsing,recon" {
		t.Fatalf("unlocked=%v want [browsing recon]", got)
	}
	seedUnlockFromHistory(msgs, nil) // nil → no-op, no panic
}

// TestUnlockGatingFlow mirrors what OnInvoke / seedUnlockFromHistory do: a gated
// tool starts locked and becomes callable only after its skill unlocks it.
func TestUnlockGatingFlow(t *testing.T) {
	serverTools := map[string][]string{"secret": {"mcp__secret__do"}}
	unlock := actool.NewUnlockSet("mcp__browser__navigate") // global only
	unlockSkill := func(name string) {
		if name == "unlock-secret" {
			unlock.Add(serverTools["secret"]...)
		}
	}
	if unlock.Has("mcp__secret__do") {
		t.Fatal("gated tool should start locked")
	}
	unlockSkill("unlock-secret")
	if !unlock.Has("mcp__secret__do") {
		t.Fatal("gated tool should be unlocked after skill load")
	}
}
