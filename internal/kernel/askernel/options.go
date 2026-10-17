package askernel

import (
	"time"

	"github.com/c1ayooo/4zrec/internal/platform/llm/acllm"
	"github.com/c1ayooo/4zrec/internal/kernel/compaction"
	"github.com/c1ayooo/4zrec/internal/toolface/tools"
	"github.com/c1ayooo/4zrec/internal/kernel/transcript"
	"github.com/cloudwego/eino/components/model"
)

// Options is the single assembly point for the six agent classes (model, tools,
// permission, hooks, context management, persistence) — the norma agentcore
// Options shape carried over to the eino runtime. The host assembles everything
// (including the model decorator stack and the toolset); the kernel injects
// nothing of its own except the deferred-tool access tools when DeferredTools
// is non-empty.
type Options struct {
	// Model is the already-decorated chat model (llmrec → sidequestion →
	// llmpool → taskLLM ordering is the host assembler's decision).
	Model model.ToolCallingChatModel

	// SystemPrompt is the host-controlled system prompt, in segments. The
	// kernel appends the noa segments (when Noa is set) and the deferred-tools
	// block (when DeferredTools is non-empty) after it, and submits the joined
	// text as the system message of every model call.
	SystemPrompt []string

	// Tools is the assembled toolset (skill meta-tool, MCP, domain tools...).
	// Nil defaults to tools.DefaultTools().
	Tools []tools.CoreTool

	// DeferredTools names tools whose schemas are withheld from the model (only
	// their names surface via the deferred-tools block appended to the system
	// prompt). They stay callable: directly once unlocked, and via the
	// auto-added SearchExtraTools/ExecuteExtraTool pair. Empty = all tool
	// schemas sent as usual.
	DeferredTools []string
	// Unlock gates which deferred tools are currently callable. Nil with
	// non-empty DeferredTools → the kernel seeds one with all DeferredTools
	// unlocked. Hosts doing skill-gated disclosure pass their own (possibly
	// empty) set and Add() to it when a skill loads.
	Unlock *tools.UnlockSet

	// PermissionMode is the permission pipeline mode. 4zrec runs bypass
	// everywhere today; empty defaults to tools.ModeBypass. Non-bypass modes go
	// through the tools.Evaluate pipeline shape (no interactive ask callback —
	// an "ask" verdict denies).
	PermissionMode tools.Mode

	WorkingDir string
	// BashEnv holds extra "KEY=VALUE" entries injected into Bash subprocess
	// environments (foreground + background). Empty = inherit unchanged.
	BashEnv []string
	// AgentID, when set, marks this session as a subagent: its transcript
	// writes to the sidechain file and tool calls carry the agent id.
	AgentID string

	// MaxTurns bounds model turns (0 = ADK default of 20) → ChatModelAgent
	// MaxIterations. MaxDuration bounds wall-clock run time; on hit the run
	// ends with ReasonTimeout and settlement may still checkpoint findings.
	MaxTurns int
	// MaxDuration bounds wall-clock run time (0 = off).
	MaxDuration time.Duration

	// NudgeLimit caps the empty-turn nudges per Prompt run: when the model ends
	// a run with an assistant turn that has neither text nor tool calls, the
	// kernel injects a continuation instruction (norma's empty-turn Stop-hook
	// semantics) and re-runs, at most NudgeLimit times per Prompt, then lets
	// the run complete. norma's per-agent counts were 2 for the worker and 5
	// elsewhere — the worker assembler sets NudgeLimit: 2; 0 defaults to 5.
	NudgeLimit int

	// Settlement, when set with a Prompt, runs a bounded wrap-up phase when a
	// budget (MaxTurns/MaxDuration) is hit — injecting the prompt as a user
	// turn and hiding DisabledTools — so a budget-terminated run can
	// checkpoint its findings. The run still finishes with the budget's
	// reason (max_turns/timeout), never completed.
	Settlement *Settlement

	// ToolOutputDir, when set, makes oversized tool output spill to a file
	// there (full content preserved) instead of being discarded by truncation.
	ToolOutputDir string
	// MaxToolOutputChars caps per-tool output (head size; 0 = default 30000,
	// the tools.Capture default).
	MaxToolOutputChars int

	// Compaction, when non-nil, enables automatic context-window management
	// (MicroCompact/AutoCompact/Reactive — the ARTEX compaction package)
	// against the DTO master history. The summarizer defaults to a
	// NewModelSummarizer over Options.Model (tool-less Generate calls); set
	// CompactionSummarizer to override (tests, or a dedicated model).
	// Ignored when Noa is set (mutually exclusive context managers).
	Compaction *compaction.Config
	// CompactionSummarizer overrides the default model-backed summarizer.
	CompactionSummarizer compaction.Summarizer

	// Noa, when non-nil, hands context management to the noa port: the kernel
	// skips its built-in compaction and asks the takeover for the extra tools
	// (Compress) and the resident system-prompt segments. See NoaOptions and
	// NoaTakeover.
	Noa *NoaOptions

	// Todos is carried for host convenience (sharing/observing the store). The
	// TodoWrite tool itself is host-assembled: TodoStore.Tool is
	// package-private to tools.
	Todos *tools.TodoStore

	// Transcript, when non-nil, persists the conversation to an append-only
	// JSONL log so the session can be resumed (Session.Resume). The kernel owns
	// the transcript.Writer (the Recorder) — hosts only supply the store.
	Transcript *transcript.Store
	// SessionID names the transcript file. Empty generates a fresh id (read it
	// back via Session.SessionID).
	SessionID string

	// Hooks is optional lifecycle instrumentation — guard, possibly wrapped by
	// the engine's steer hooks. Nil disables it.
	Hooks HookRunner

	// NonStreaming runs every model call as a single non-streaming request.
	// The host still receives the same event sequence, delivered when the full
	// response arrives rather than incrementally. Zero value = streaming.
	NonStreaming bool
	// MaxTokens caps model output per call (0 = provider default).
	MaxTokens int

	// OnWarn receives configuration warnings raised while building the session
	// (misconfigurations the kernel works around rather than rejecting).
	OnWarn func(string)

	// EnableWebFetch adds the network-facing WebFetch tool (permission-gated).
	EnableWebFetch bool
	// WebFetch configures its proxy/TLS behavior.
	WebFetch tools.WebFetchConfig
	// EnableWebSearch adds the network-facing web_search tool (permission-gated).
	EnableWebSearch bool
	// WebSearch configures the search backend. A misconfigured backend drops
	// the tool with a warning instead of failing the session.
	WebSearch tools.WebSearchConfig
}

// Settlement configures the wrap-up phase that runs when a budget is hit.
type Settlement struct {
	// Prompt is the wrap-up instruction injected as a user turn (empty =
	// settlement off).
	Prompt string
	// MaxTurns is the wrap-up phase's own turn budget (0 = default 2).
	MaxTurns int
	// DisabledTools are hidden from the model during wrap-up (e.g. ["Bash"]).
	DisabledTools []string
	// PromptByReason optionally overrides Prompt based on WHY the run settled
	// (keyed by the terminal reason). A non-empty entry wins over Prompt.
	PromptByReason map[TerminalReason]string
}

// promptFor returns the wrap-up prompt for a settling reason: the
// PromptByReason override when present and non-empty, else Prompt.
func (s *Settlement) promptFor(reason TerminalReason) string {
	if s.PromptByReason != nil {
		if p := s.PromptByReason[reason]; p != "" {
			return p
		}
	}
	return s.Prompt
}

// NoaOptions mirrors the noa port's session Options (noaadapter.Options). The
// kernel never interprets these beyond handing them to the takeover: they are
// carried so hosts can keep building one Options value and so the future noa
// port's Enable(opts, noaOpts) can fill Noa in one call.
type NoaOptions struct {
	// ArchiveBaseDir is where archives and state live (required by noa).
	ArchiveBaseDir string
	// SessionID names the subdirectory under ArchiveBaseDir.
	SessionID string
	// Config is the noa.Config override; any so this package does not depend
	// on the noa package (typed *noa.Config at the call site).
	Config any
	// ModelContextLimit sizes the default config when Config is nil.
	ModelContextLimit int
	// ParentSessionIDs are ancestors to inherit a ledger from, nearest first.
	ParentSessionIDs []string
	// OnWarn receives non-fatal noa diagnostics.
	OnWarn func(string)
	// Now overrides the clock, for tests.
	Now func() time.Time
	// Takeover is the seam implementation the noa port installs. Required for
	// Noa to be considered enabled.
	Takeover NoaTakeover
}

// NoaTakeover is the minimal compile-time seam between the kernel and the noa
// port (a separate task — nothing in this package implements it). When
// Options.Noa is set with a Takeover, the kernel:
//
//   - ignores Options.Compaction entirely (noa owns the context view; the two
//     are mutually exclusive, exactly like norma's Compactor-over-Compaction
//     precedence);
//   - appends Takeover.ExtraTools() (the Compress tool) to the session registry;
//   - appends Takeover.SystemPromptSegments() (the resident sections) to the
//     system prompt, before the deferred-tools block.
//
// If the takeover also implements NoaView, its View replaces
// acllm.MessagesForAPI as the request projection — that is how noa's
// compression view takes over what the model sees without touching the DTO
// master history (mirrors norma's harness.ContextView).
type NoaTakeover interface {
	// ExtraTools returns the additional tools (Compress) appended to the
	// session registry.
	ExtraTools() []tools.CoreTool
	// SystemPromptSegments returns the resident prompt sections appended after
	// Options.SystemPrompt.
	SystemPromptSegments() []string
}

// NoaView is the optional projection seam (norma harness.ContextView shape).
// View must be pure: the returned messages are used for the current request
// only and never written back to the DTO master history.
type NoaView interface {
	View(msgs []acllm.Message) []acllm.Message
}
