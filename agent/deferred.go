package agent

import (
	"encoding/json"

	"github.com/Autumn-27/artex/acllm"
	"github.com/Autumn-27/artex/tools"
)

// deferredSystem builds an agent's system-prompt segments from its DeferredInfo.
// The finding-guidance text (derived from the final permitted tools) rides on the
// single host segment; the <available-deferred-tools> block itself is NOT
// rendered here anymore — askernel appends tools.RenderDeferredToolsBlock over
// Options.DeferredTools at the tail of the system message on every request, so
// rendering a second block here would duplicate it. (Norma hosts placed the
// block themselves via GlobalNames; the kernel now owns it. Note the kernel
// block lists ALL deferred names — skill-gated ones included — while the unlock
// gate keeps them uncallable until their skill loads.)
func deferredSystem(sysText string, def DeferredInfo) (system []string) {
	return []string{sysText + def.FindingGuidance}
}

// seedUnlockFromHistory replays prior Skill() invocations in the conversation so
// their skill-gated MCPs are re-unlocked on a resumed session (design doc C2). The
// main agent builds a fresh session each turn; its in-memory unlock set would
// otherwise reset, leaving the model able to see a skill-revealed tool name yet
// unable to call it. No-op when unlockSkill is nil (no deferred tools).
func seedUnlockFromHistory(msgs []acllm.Message, unlockSkill func(string)) {
	if unlockSkill == nil {
		return
	}
	for _, m := range msgs {
		for _, b := range m.ToolUses() {
			if b.Name != "Skill" {
				continue
			}
			var in struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(b.Input, &in) == nil && in.Name != "" {
				unlockSkill(in.Name)
			}
		}
	}
}

// sessionTools appends the session-level tools the norma kernel injected
// automatically and askernel leaves to the host: the TodoWrite tool for the
// store, and the background-task tools (TaskOutput/TaskStop/TaskList/Monitor)
// unless the run is a focused single-purpose agent (the old
// DisableBackgroundTasks). Order matches norma: base..., TodoWrite, task tools.
func sessionTools(base []tools.CoreTool, todos *tools.TodoStore, bgTasks bool) []tools.CoreTool {
	out := base
	if todos != nil {
		out = append(out, todos.Tool())
	}
	if bgTasks {
		out = append(out, tools.NewTaskOutput(), tools.NewTaskStop(), tools.NewTaskList(), tools.NewMonitor())
	}
	return out
}
