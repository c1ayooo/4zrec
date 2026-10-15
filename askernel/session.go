package askernel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/acllm"
	"github.com/Autumn-27/artex/compaction"
	"github.com/Autumn-27/artex/tools"
	"github.com/Autumn-27/artex/transcript"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// Session is a long-lived conversation over one model + one toolset. Call
// Prompt repeatedly; the DTO master history and the transcript persist across
// calls. Not safe for concurrent Prompt calls on the same Session (mirrors
// norma agentcore).
type Session struct {
	opts Options

	registry    *tools.Registry
	unlock      *tools.UnlockSet // deferred-tool call gate (nil when no deferred tools)
	noaView     NoaView          // installed by the noa port, optional
	noaSegments []string         // noa resident prompt sections (nil when noa is off)
	compactor   *compaction.Compactor
	tasks       *tools.Manager // background-task manager shared with the tools

	tcTpl tools.ToolContext // per-call ToolContext template (ToolUseID filled in)
	sched *toolScheduler

	mu  sync.Mutex      // guards dto (middleware goroutines)
	dto []acllm.Message // DTO master history: the single source of truth

	usage acllm.Usage // cumulative usage, rebuilt on Resume / replaced per terminal

	sessionID string
	store     *transcript.Store
	writer    *transcript.Writer
}

// NewSession builds a Session, applying defaults. Configuration warnings go to
// opts.OnWarn; nothing is written to stdout/stderr.
func NewSession(opts Options) *Session {
	s := &Session{opts: opts}

	toolSet := opts.Tools
	if toolSet == nil {
		toolSet = tools.DefaultTools()
	}
	if s.opts.PermissionMode == "" {
		s.opts.PermissionMode = tools.ModeBypass // ARTEX现状恒为 bypass
	}
	if s.opts.NudgeLimit <= 0 {
		s.opts.NudgeLimit = 5 // norma: worker 2 / others 5; the worker assembler sets 2
	}

	// Exactly one context manager: noa wins over built-in compaction (mutually
	// exclusive, like norma's Compactor-over-Compaction precedence).
	if opts.Noa != nil {
		if opts.Compaction != nil {
			s.warn("both Noa and Compaction are set — Compaction is IGNORED. " +
				"They are mutually exclusive context managers; set only one.")
		}
		s.opts.Compaction = nil
		if t := opts.Noa.Takeover; t != nil {
			toolSet = append(toolSet, t.ExtraTools()...)
			s.noaSegments = t.SystemPromptSegments()
			if v, ok := t.(NoaView); ok {
				s.noaView = v
			}
		} else {
			s.warn("Noa set without a Takeover — noa is NOT enabled; built-in compaction keeps working.")
			s.opts.Noa = nil
			s.opts.Compaction = opts.Compaction
		}
	}
	if s.opts.Compaction != nil {
		summarizer := opts.CompactionSummarizer
		if summarizer == nil {
			summarizer = compaction.NewModelSummarizer(opts.Model, opts.MaxTokens, opts.NonStreaming)
		}
		s.compactor = compaction.New(*opts.Compaction, summarizer)
	}

	s.registry = tools.NewRegistry(toolSet...)
	// Deferred tools: withhold their schemas (deferredMiddleware filters by
	// unlock state) but keep them callable via the two always-loaded access
	// tools, which close over the registry (it already holds the deferred tools).
	if len(opts.DeferredTools) > 0 {
		s.unlock = opts.Unlock
		if s.unlock == nil {
			s.unlock = tools.NewUnlockSet(opts.DeferredTools...)
		}
		s.registry.Add(tools.NewSearchExtraTools(s.registry, opts.DeferredTools))
		s.registry.Add(tools.NewExecuteExtraTool(s.registry, s.unlock))
	}
	if opts.EnableWebFetch {
		s.registry.Add(tools.NewWebFetch(opts.WebFetch))
	}
	if opts.EnableWebSearch {
		// A misconfigured backend drops the tool rather than failing the whole
		// session — the rest of the agent stays usable and the missing tool
		// surfaces the misconfig.
		if ws, err := tools.NewWebSearch(opts.WebSearch); err == nil {
			s.registry.Add(ws)
		} else {
			s.warn("web_search dropped: " + err.Error())
		}
	}

	// A session id is always needed: it names the background-task temp dir and
	// the transcript file.
	s.sessionID = opts.SessionID
	if s.sessionID == "" {
		s.sessionID = transcript.NewSessionID()
	}
	// Background-task execution manager shared with the tools. The task tools
	// themselves (TaskOutput/TaskStop/TaskList/Monitor) are host-assembled via
	// Options.Tools; the kernel only provides the manager they run against.
	if mgr, err := tools.NewManager(s.sessionID); err == nil {
		s.tasks = mgr
	}

	s.tcTpl = tools.ToolContext{
		WorkingDir:     opts.WorkingDir,
		AgentID:        opts.AgentID,
		MaxOutputChars: opts.MaxToolOutputChars,
		OutputDir:      opts.ToolOutputDir,
		Tasks:          s.tasks,
		Env:            opts.BashEnv,
	}
	s.sched = newToolScheduler(0) // default MaxConcurrency 10

	if opts.Transcript != nil {
		s.store = opts.Transcript
		s.writer = s.store.NewWriter(s.sessionID, opts.AgentID)
	}
	return s
}

// warn reports a configuration warning to the host, if it asked for them.
func (s *Session) warn(msg string) {
	if s.opts.OnWarn != nil {
		s.opts.OnWarn("askernel: " + msg)
	}
}

// SessionID returns the transcript session id (always non-empty).
func (s *Session) SessionID() string { return s.sessionID }

// UnlockSet returns the session's deferred-tool call gate (nil when no deferred
// tools). Hosts Add() to it to unlock skill-gated tools at runtime.
func (s *Session) UnlockSet() *tools.UnlockSet { return s.unlock }

// Usage returns the cumulative token usage (rebuilt on Resume, replaced by
// each terminal — norma parity).
func (s *Session) Usage() acllm.Usage { return s.usage }

// Messages returns the DTO master history (full, non-destructive — includes
// compact boundaries).
func (s *Session) Messages() []acllm.Message { return s.dto }

// Close releases session resources (background tasks and their temporary
// output directory). Safe to call multiple times.
func (s *Session) Close() error {
	if s.tasks != nil {
		s.tasks.Cleanup()
		s.tasks = nil
	}
	return nil
}

// Resume reloads a prior conversation from the transcript store: load →
// cleanResumed (drop trailing dangling tool_use) → cumulative usage rebuild →
// ResumeWriter, so the next Prompt continues the same file. Requires
// Options.Transcript.
func (s *Session) Resume(sessionID string) error {
	if s.store == nil {
		return errors.New("askernel: Resume requires Options.Transcript")
	}
	recs, err := s.store.Load(s.store.MainPath(sessionID))
	if err != nil {
		return err
	}
	msgs, usage := transcript.Messages(recs)
	s.mu.Lock()
	s.dto = cleanResumed(msgs)
	s.mu.Unlock()
	s.usage = usage
	s.sessionID = sessionID
	if s.writer != nil {
		s.writer = s.store.ResumeWriter(sessionID, transcript.LastUUID(recs))
	}
	return nil
}

// cleanResumed drops trailing assistant tool calls whose results were never
// persisted — a crash mid-tool would otherwise leave a dangling tool_use that
// the API rejects.
func cleanResumed(msgs []acllm.Message) []acllm.Message {
	for len(msgs) > 0 {
		last := msgs[len(msgs)-1]
		if last.Role == acllm.RoleAssistant && len(last.ToolUses()) > 0 {
			msgs = msgs[:len(msgs)-1]
			continue
		}
		break
	}
	return msgs
}

// systemMessage joins the system prompt segments: host segments, then the noa
// resident sections (when enabled), then the deferred-tools block (spec §7:
// appended at the tail of the system prompt).
func (s *Session) systemMessage() *schema.Message {
	segments := append([]string(nil), s.opts.SystemPrompt...)
	segments = append(segments, s.noaSegments...)
	if block := tools.RenderDeferredToolsBlock(s.opts.DeferredTools); block != "" {
		segments = append(segments, block)
	}
	if len(segments) == 0 {
		return nil
	}
	return schema.SystemMessage(strings.Join(segments, "\n\n"))
}

// promptState is the per-Prompt accounting shared across the runner runs of
// one Prompt (primary + empty-turn re-runs + settlement).
type promptState struct {
	usage           acllm.Usage // accumulated by the event pump
	turns           int         // model calls in the primary phase
	nudges          int         // empty-turn nudges injected this Prompt
	lastInputTokens int         // previous response's reported size (compaction gate)
	stopHookActive  bool        // a Stop-hook blocking injection awaits a real turn
}

// consumerStoppedError marks "the Prompt consumer stopped draining" — the
// Prompt then returns without a KindResult (norma consumerStopped).
var consumerStoppedError = errors.New("askernel: consumer stopped")

// Prompt appends a user message and streams the agent loop to completion. The
// final event is KindResult carrying a Terminal (unless the consumer stops
// draining early). Session state (DTO, usage) is updated as the loop runs.
func (s *Session) Prompt(ctx context.Context, input string) iter.Seq2[RunEvent, error] {
	return func(yield func(RunEvent, error) bool) {
		// 1. User input → DTO + transcript.
		userMsg := acllm.UserText(input)
		s.mu.Lock()
		s.dto = append(s.dto, userMsg)
		writer := s.writer
		s.mu.Unlock()
		if writer != nil {
			writer.RecordMessage(userMsg, acllm.Usage{})
		}

		// 2. Run context: consumer-stop cancellation + wall-clock budget.
		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		if s.opts.MaxDuration > 0 {
			var stopClock context.CancelFunc
			runCtx, stopClock = context.WithTimeout(runCtx, s.opts.MaxDuration)
			defer stopClock()
		}
		if writer != nil {
			runCtx = transcript.WithSessionID(runCtx, s.sessionID)
		}

		ps := &promptState{}
		rs := newRunState()

		// 3. Primary phase (with empty-turn nudges and Stop-hook continuations).
		reason, runErr, stopped := s.runPrimary(runCtx, ps, rs, yield)
		if stopped {
			return
		}

		// 4. Settlement: a budget-terminated run gets one bounded wrap-up
		//    phase; the terminal keeps the budget reason either way.
		if (reason == ReasonMaxTurns || reason == ReasonTimeout) && s.opts.Settlement != nil {
			if s.runSettlement(ctx, ps, rs, reason, yield) {
				return // the consumer stopped draining mid-settlement
			}
		}

		// 5. Terminal.
		term := &Terminal{
			Reason:   reason,
			Err:      runErr,
			Usage:    ps.usage,
			Turns:    ps.turns,
			Messages: append([]acllm.Message(nil), s.dto...),
			Text:     lastAssistantText(s.dto),
		}
		if reason == ReasonStopHookPrevented {
			term.Text = stopHookMessage
		}
		s.usage = ps.usage
		yield(RunEvent{Kind: KindResult, Terminal: term}, nil)
	}
}

const (
	// emptyTurnNudge is the continuation instruction injected when a model run
	// ends with an assistant turn that has neither text nor tool calls (norma's
	// empty-turn Stop-hook semantics).
	emptyTurnNudge = "You produced an empty response with no tool calls. Continue the task now: " +
		"either take the next concrete action with the available tools, or give your final answer as text. " +
		"Do not return an empty response."
	// stopHookMessage is the Terminal.Text for a Stop-hook-prevented run
	// (norma finished with the hook's message).
	stopHookMessage = "run stopped by hook"
)

// runPrimary drives runner runs until a terminal reason is reached. Empty
// turns are nudged (bounded by NudgeLimit) and Stop-hook blocking errors are
// injected, each triggering one more bounded runner run.
func (s *Session) runPrimary(ctx context.Context, ps *promptState, rs *runState, yield func(RunEvent, error) bool) (TerminalReason, error, bool) {
	for {
		before := rs.size()
		runErr, stopped := s.runOnce(ctx, ps, rs, yield)
		if stopped {
			return "", nil, true
		}
		// A real tool turn happened → Stop hooks may fire fresh (norma resets
		// stopHookActive in the tools-were-executed path).
		if rs.size() > before {
			ps.stopHookActive = false
		}

		if runErr != nil {
			reason, err := mapRunError(ctx, runErr)
			// Budget reasons may still settle; everything else is final.
			if reason == ReasonMaxTurns || reason == ReasonTimeout {
				return reason, nil, false
			}
			return reason, err, false
		}

		// Natural stop. Stop hooks first: a prevented run hard-terminates;
		// blocking errors are injected as user messages and the loop continues
		// (once — until a real tool turn happens, norma stopHookActive).
		s.mu.Lock()
		emptyTurn := lastAssistantEmpty(s.dto)
		s.mu.Unlock()
		if s.opts.Hooks != nil && !ps.stopHookActive && !emptyTurn {
			prevent, blocking, _ := s.opts.Hooks.Stop(ctx, s.dto)
			if prevent {
				return ReasonStopHookPrevented, nil, false
			}
			if len(blocking) > 0 {
				msgs := make([]acllm.Message, 0, len(blocking))
				for _, b := range blocking {
					msgs = append(msgs, acllm.UserText(b))
				}
				s.appendDTO(msgs)
				ps.stopHookActive = true
				continue
			}
		}

		// Empty-turn nudge (norma Stop-hook semantics): an assistant turn with
		// neither text nor tool calls gets a continuation instruction injected
		// into the DTO + transcript and one more bounded runner run, at most
		// NudgeLimit times per Prompt, then the run completes as-is.
		if emptyTurn && ps.nudges < s.opts.NudgeLimit {
			s.appendDTO([]acllm.Message{acllm.UserText(emptyTurnNudge)})
			ps.nudges++
			continue
		}

		ps.stopHookActive = false
		return ReasonCompleted, nil, false
	}
}

// mapRunError maps a runner error to its TerminalReason: max iterations →
// max_turns; reactive-recovery exhaustion → prompt_too_long; wall-clock
// deadline → timeout; consumer/parent cancellation → aborted_streaming;
// anything else → model_error.
func mapRunError(ctx context.Context, runErr error) (TerminalReason, error) {
	if errors.Is(runErr, adk.ErrExceedMaxIterations) {
		return ReasonMaxTurns, nil
	}
	var exhausted *reactiveExhaustedError
	if errors.As(runErr, &exhausted) || compaction.IsOverflow(runErr) {
		return ReasonPromptTooLong, runErr
	}
	if errors.Is(runErr, context.DeadlineExceeded) {
		return ReasonTimeout, nil
	}
	if errors.Is(runErr, context.Canceled) || ctx.Err() != nil {
		return ReasonAbortedStreaming, runErr
	}
	return ReasonModelError, runErr
}

// runOnce builds one bounded runner (fresh agent, fresh middleware bound to
// ps/rs) and drains its events. Returns the run error (nil = natural stop).
// stopped reports that the Prompt consumer stopped draining.
func (s *Session) runOnce(ctx context.Context, ps *promptState, rs *runState, yield func(RunEvent, error) bool) (error, bool) {
	err := s.driveAgent(ctx, ps, rs, yield, s.registry.List(), s.opts.MaxTurns, true)
	if errors.Is(err, consumerStoppedError) {
		return nil, true
	}
	return err, false
}

// runSettlement injects the wrap-up prompt and runs one bounded agent with the
// disabled tools hidden. The terminal keeps the ORIGINAL budget reason (the
// settlement is just a checkpoint), so the engine state machine semantics are
// unchanged. Settlement runs free of the run's wall-clock budget (its tools
// run freely, bounded only by its own turn budget), but it must die with its
// Prompt: when runSettlement returns — in particular when the consumer stops
// draining — the derived context cancels the runner, so an abandoned wrap-up
// cannot keep spending model calls in the background or interleave its DTO
// writes with a subsequent Prompt on the same session. It reports whether the
// consumer stopped draining (the Prompt then ends without a KindResult).
func (s *Session) runSettlement(ctx context.Context, ps *promptState, rs *runState, reason TerminalReason, yield func(RunEvent, error) bool) bool {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	st := s.opts.Settlement
	prompt := st.promptFor(reason)
	if prompt == "" {
		return false
	}
	s.appendDTO([]acllm.Message{acllm.UserText(prompt)})

	registry := tools.NewRegistry()
	blocked := make(map[string]bool, len(st.DisabledTools))
	for _, d := range st.DisabledTools {
		blocked[d] = true
	}
	for _, t := range s.registry.List() {
		if !blocked[t.Name()] {
			registry.Add(t)
		}
	}
	maxTurns := st.MaxTurns
	if maxTurns <= 0 {
		maxTurns = 2 // norma settleMaxTurns default
	}
	err := s.driveAgent(sctx, ps, rs, yield, registry.List(), maxTurns, false)
	// Settlement errors (including its own max iterations) are absorbed: the
	// run finishes with the budget reason, never completed/model_error. Only a
	// consumer stop propagates.
	return errors.Is(err, consumerStoppedError)
}

// driveAgent constructs the ChatModelAgent + Runner for one run and drains the
// event iterator. countTurns increments promptState.turns for model calls
// (primary runs only — settlement turns do not advance the run's count, norma
// parity).
func (s *Session) driveAgent(ctx context.Context, ps *promptState, rs *runState, yield func(RunEvent, error) bool, toolSet []tools.CoreTool, maxTurns int, countTurns bool) error {
	einoTools := make([]tool.BaseTool, 0, len(toolSet))
	infos := make([]*schema.ToolInfo, 0, len(toolSet))
	for _, t := range toolSet {
		et := tools.ToEino(t)
		ti, err := et.Info(ctx)
		if err != nil {
			return fmt.Errorf("askernel: tool %s: %w", t.Name(), err)
		}
		einoTools = append(einoTools, et)
		infos = append(infos, ti)
	}

	handlers := []adk.ChatModelAgentMiddleware{
		s.newViewMiddleware(ps, countTurns),
		&deferredMiddleware{infos: infos, deferred: deferredSet(s.opts.DeferredTools), unlock: s.unlock},
		&gateMiddleware{
			session:  s,
			rs:       rs,
			reg:      s.registry,
			unlock:   s.unlock,
			deferred: deferredSet(s.opts.DeferredTools),
			hooks:    s.opts.Hooks,
			mode:     s.opts.PermissionMode,
			sched:    s.sched,
			tcTpl:    s.tcTpl,
		},
	}

	cfg := &adk.ChatModelAgentConfig{
		Name:          "artex",
		Model:         s.opts.Model,
		MaxIterations: maxTurns,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{
				Tools:               einoTools,
				UnknownToolsHandler: unknownToolResult(),
			},
		},
		Handlers: handlers,
	}
	ag, err := adk.NewChatModelAgent(ctx, cfg)
	if err != nil {
		return err
	}

	runner := adk.NewRunner(ctx, adk.RunnerConfig{Agent: ag, EnableStreaming: !s.opts.NonStreaming})
	iter := runner.Run(ctx, nil) // input messages: none — the DTO projection supplies everything
	return drainEvents(iter, ps, rs, s, yield)
}

// drainEvents is the event pump: it surfaces text/thinking deltas, tool_use,
// tool_result and usage events to the consumer. DTO writes do NOT happen here
// (the middlewares write the DTO synchronously with the graph, so the next
// model call's projection can never race the pump) — except for unknown-tool
// results, which the gate never saw.
func drainEvents(iter *adk.AsyncIterator[*adk.AgentEvent], ps *promptState, rs *runState, s *Session, yield func(RunEvent, error) bool) error {
	var runErr error
	for {
		ev, ok := iter.Next()
		if !ok {
			return runErr
		}
		if ev.Err != nil {
			runErr = ev.Err // last error wins (mirrors the spike drain)
			continue
		}
		if ev.Output == nil || ev.Output.MessageOutput == nil {
			continue
		}
		mv := ev.Output.MessageOutput

		switch {
		case mv.IsStreaming && mv.Role == schema.Assistant && mv.MessageStream != nil:
			// Assistant stream: emit text/thinking deltas, then assemble the
			// final message for tool calls + usage.
			var (
				chunks []*schema.Message
				serr   error
			)
			for {
				chunk, err := mv.MessageStream.Recv()
				if err != nil {
					if !errors.Is(err, io.EOF) {
						serr = err
					}
					break
				}
				if chunk == nil {
					continue
				}
				if chunk.Content != "" {
					if !yield(RunEvent{Kind: KindText, Text: chunk.Content}, nil) {
						return consumerStoppedError
					}
				}
				if chunk.ReasoningContent != "" {
					if !yield(RunEvent{Kind: KindThinking, Text: chunk.ReasoningContent}, nil) {
						return consumerStoppedError
					}
				}
				chunks = append(chunks, chunk)
			}
			if serr != nil {
				runErr = serr
				continue
			}
			final, cerr := schema.ConcatMessages(chunks)
			if cerr != nil {
				runErr = cerr
				continue
			}
			if !emitAssistant(final, ps, yield) {
				return consumerStoppedError
			}

		case mv.Role == schema.Assistant:
			if mv.Message == nil {
				continue
			}
			m := mv.Message
			if m.ReasoningContent != "" {
				if !yield(RunEvent{Kind: KindThinking, Text: m.ReasoningContent}, nil) {
					return consumerStoppedError
				}
			}
			if m.Content != "" {
				if !yield(RunEvent{Kind: KindText, Text: m.Content}, nil) {
					return consumerStoppedError
				}
			}
			if !emitAssistant(m, ps, yield) {
				return consumerStoppedError
			}

		case mv.Role == schema.Tool:
			if mv.Message == nil {
				continue
			}
			m := mv.Message
			isErr := true
			if rec := rs.lookup(m.ToolCallID); rec != nil {
				isErr = rec.isErr
			} else {
				// Unknown-tool result: the gate never saw this call, so the
				// pump persists it (always an error — the model hallucinated
				// the tool name).
				s.appendDTO([]acllm.Message{{
					Role: acllm.RoleUser,
					Content: []acllm.ContentBlock{
						acllm.ToolResultText(m.ToolCallID, m.Content, true),
					},
				}})
			}
			block := acllm.ToolResultText(m.ToolCallID, m.Content, isErr)
			if !yield(RunEvent{Kind: KindToolResult, ToolResult: &block}, nil) {
				return consumerStoppedError
			}
		}
	}
}

// emitAssistant surfaces tool_use blocks and usage from an assembled assistant
// message (the DTO write itself happened in AfterModelRewriteState).
func emitAssistant(m *schema.Message, ps *promptState, yield func(RunEvent, error) bool) bool {
	for _, tc := range m.ToolCalls {
		block := &acllm.ContentBlock{
			Type:  acllm.BlockToolUse,
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: tools.ArgsFromEino(tc.Function.Arguments),
		}
		if !yield(RunEvent{Kind: KindToolUse, ToolUse: block}, nil) {
			return false
		}
	}
	if m.ResponseMeta != nil && m.ResponseMeta.Usage != nil {
		ps.usage.Add(acllm.UsageFromToken(m.ResponseMeta.Usage))
		u := ps.usage
		if !yield(RunEvent{Kind: KindUsage, Usage: &u}, nil) {
			return false
		}
	}
	return true
}

// appendDTO appends messages to the DTO master history and records each to the
// transcript (birth-order persistence, frozen format).
func (s *Session) appendDTO(msgs []acllm.Message) {
	s.mu.Lock()
	s.dto = append(s.dto, msgs...)
	writer := s.writer
	s.mu.Unlock()
	if writer != nil {
		for _, m := range msgs {
			writer.RecordMessage(m, acllm.Usage{})
		}
	}
}

// recordToolResult persists one executed tool call: the tool_result goes into
// the DTO + transcript synchronously with tool execution (BEFORE the next
// model call can project — the pump may still be draining when the next model
// call fires), followed by any Result.Extra skill-guidance messages (spec §6).
func (s *Session) recordToolResult(rs *runState, callID, text string, isErr bool, extras []acllm.Message) {
	msgs := make([]acllm.Message, 0, 1+len(extras))
	msgs = append(msgs, acllm.Message{
		Role: acllm.RoleUser,
		Content: []acllm.ContentBlock{
			acllm.ToolResultText(callID, text, isErr),
		},
	})
	msgs = append(msgs, extras...)
	s.appendDTO(msgs)
	rs.record(callID, &toolExecRecord{isErr: isErr})
}

// recordBoundaryLocked persists a freshly inserted compaction boundary: the
// observability record plus the post-boundary working set (boundary marker,
// summary, kept tail) as durable messages, so a cold-start Resume restores the
// COMPACTED view. Caller holds s.mu.
func (s *Session) recordBoundaryLocked(msgs []acllm.Message) {
	if s.writer == nil {
		return
	}
	i := acllm.LastBoundaryIndex(msgs)
	if i < 0 {
		return
	}
	if meta, ok := acllm.ParseBoundaryMeta(msgs[i]); ok {
		s.writer.RecordBoundary(meta)
	}
	for _, m := range msgs[i:] {
		s.writer.RecordMessage(m, acllm.Usage{})
	}
}

// lastAssistantEmpty reports whether the last assistant message in the API
// view has neither text nor tool calls (the empty-turn nudge condition).
func lastAssistantEmpty(dto []acllm.Message) bool {
	m := lastAssistant(dto)
	if m == nil {
		return false
	}
	return m.Text() == "" && len(m.ToolUses()) == 0
}

func lastAssistant(dto []acllm.Message) *acllm.Message {
	for i := len(dto) - 1; i >= 0; i-- {
		if dto[i].Role == acllm.RoleAssistant {
			return &dto[i]
		}
	}
	return nil
}

// lastAssistantText returns the last assistant message's text (Terminal.Text).
func lastAssistantText(dto []acllm.Message) string {
	if m := lastAssistant(dto); m != nil {
		return m.Text()
	}
	return ""
}

func deferredSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}

// newViewMiddleware builds the projection/compaction middleware bound to this
// run's prompt state.
func (s *Session) newViewMiddleware(ps *promptState, countTurns bool) *viewMiddleware {
	return &viewMiddleware{
		session:    s,
		ps:         ps,
		sysMsg:     s.systemMessage(),
		compactor:  s.compactor,
		noaView:    s.noaView,
		maxTokens:  s.opts.MaxTokens,
		countTurns: countTurns,
	}
}
