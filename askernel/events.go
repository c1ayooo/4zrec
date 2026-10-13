// Package askernel is the eino ADK implementation of the norma
// agentcore+harness runtime: a stateful Session whose Prompt method streams
// the agent loop as a range-over-func iterator of Events, on top of a
// ChatModelAgent + Runner (see docs/askernel-spec.md).
//
// Core invariant: the kernel holds a DTO master history ([]acllm.Message) as
// the single source of truth. Transcripts record DTO births verbatim (frozen
// JSONL format), and every model call projects acllm.MessagesForAPI(dto)
// through acllm.ToSchema into the ADK agent state — compaction semantics do
// not drift from the norma era. ADK checkpoints are not used across processes;
// pause/resume is ctx cancellation plus transcript replay (Session.Resume).
package askernel

import (
	"github.com/Autumn-27/artex/acllm"
)

// EventKind classifies a loop Event (harness.Event-compatible shape).
type EventKind string

const (
	KindText       EventKind = "text"        // assistant text delta
	KindThinking   EventKind = "thinking"    // reasoning delta
	KindToolUse    EventKind = "tool_use"    // a tool is about to run
	KindToolResult EventKind = "tool_result" // a tool finished
	KindProgress   EventKind = "progress"    // mid-tool progress (reserved; not emitted yet)
	KindUsage      EventKind = "usage"       // cumulative token usage so far (per model turn)
	KindResult     EventKind = "result"      // terminal event (loop finished)
)

// RunEvent is one item in the loop's output stream — the spec §2 Event
// (harness.Event-compatible shape, package-local redefinition). It is named
// RunEvent instead of Event because the verbatim hook port (hookreg.go) must
// keep hook.Event's name so guard/ re-points with an import swap only.
type RunEvent struct {
	Kind EventKind
	// Text carries KindText / KindThinking / KindProgress deltas.
	Text string
	// ToolUse carries the tool_use block for KindToolUse.
	ToolUse *acllm.ContentBlock
	// ToolResult carries the tool_result block for KindToolResult.
	ToolResult *acllm.ContentBlock
	// Terminal carries the final state for KindResult.
	Terminal *Terminal
	// Usage carries the cumulative usage after the latest model turn for KindUsage.
	Usage *acllm.Usage
}

// TerminalReason explains why the loop stopped. The 11 enum values match the
// norma harness exactly — the engine state machine and db.Activity depend on
// them (frozen contract).
type TerminalReason string

const (
	ReasonCompleted         TerminalReason = "completed"           // model ended its turn
	ReasonBlockingLimit     TerminalReason = "blocking_limit"      // hard context limit hit pre-request
	ReasonImageError        TerminalReason = "image_error"         // unsupported media (multimodal)
	ReasonModelError        TerminalReason = "model_error"         // provider/API failure
	ReasonAbortedStreaming  TerminalReason = "aborted_streaming"   // canceled during streaming
	ReasonAbortedTools      TerminalReason = "aborted_tools"       // canceled during tool execution
	ReasonPromptTooLong     TerminalReason = "prompt_too_long"     // overflow recovery exhausted
	ReasonStopHookPrevented TerminalReason = "stop_hook_prevented" // a Stop hook blocked continuation
	ReasonHookStopped       TerminalReason = "hook_stopped"        // a tool/hook stopped continuation
	ReasonMaxTurns          TerminalReason = "max_turns"           // hit MaxTurns
	ReasonTimeout           TerminalReason = "timeout"             // hit a wall-clock run budget
)

// Terminal is the final state of a Prompt, delivered as the KindResult event.
type Terminal struct {
	Reason TerminalReason
	Err    error
	Usage  acllm.Usage
	Turns  int
	// Messages is the full DTO conversation snapshot (non-destructive:
	// retains history including compact boundaries).
	Messages []acllm.Message
	// Text is the assistant's final text, for convenience.
	Text string
}
