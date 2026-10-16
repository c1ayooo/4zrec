package askernel

// The ChatModelAgent middlewares. Three collaborate:
//
//   - viewMiddleware   (spec §1/§8): projects the DTO master history into the
//     ADK state before every model call (compaction Pre → MessagesForAPI →
//     ToSchema, system message prepended), captures the assistant response
//     back into the DTO + transcript after every model call, and wraps the
//     model with the MaxTokens cap and the reactive-compaction retry.
//   - deferredMiddleware (spec §7): withholds locked deferred-tool schemas
//     from state.ToolInfos (unlocked ones are added back).
//   - gateMiddleware   (spec §6): the WrapInvokableToolCall gate executing
//     every CoreTool with norma's execOne ordering — validation → permission
//     → PreToolUse hook → deferred hard-gate → concurrency discipline → call
//     (panic-safe) → output cap → PostToolUse audit — and recording the tool
//     result into the DTO + transcript synchronously (before the next model
//     call can project), plus Result.Extra skill-guidance messages.
//
// The middlewares are constructed per runner run (bound to that run's
// promptState/runState) and must not be reused across runs.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/c1ayooo/4zrec/acllm"
	"github.com/c1ayooo/4zrec/compaction"
	"github.com/c1ayooo/4zrec/tools"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

// runState is the per-runner-run channel between the gate and the event pump:
// for every tool call id the gate executed, whether the result was an error
// (the kernel sets acllm.ExtraIsError from its own knowledge — the eino
// ToolsNode message cannot carry it). Unknown-tool results were never seen by
// the gate and carry no record; the pump persists them itself.
type runState struct {
	mu      sync.Mutex
	results map[string]*toolExecRecord
}

type toolExecRecord struct {
	isErr bool
}

func newRunState() *runState {
	return &runState{results: map[string]*toolExecRecord{}}
}

func (rs *runState) record(callID string, rec *toolExecRecord) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.results[callID] = rec
}

func (rs *runState) lookup(callID string) *toolExecRecord {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.results[callID]
}

// size reports how many tool executions have been recorded this run.
func (rs *runState) size() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return len(rs.results)
}

// --- view middleware (spec §1 DTO projection, §8 compaction) ---

type viewMiddleware struct {
	adk.TypedBaseChatModelAgentMiddleware[*schema.Message]

	session *Session
	ps      *promptState
	sysMsg  *schema.Message // joined system prompt; nil when empty

	compactor  *compaction.Compactor
	noaView    NoaView
	maxTokens  int
	countTurns bool // increment promptState.turns on model calls (primary runs only)

	// reactive state: one reactive-compaction attempt per run, re-armed after
	// each successful model turn (norma hasAttemptedReactiveCompact).
	reactiveMu    sync.Mutex
	reactiveTried bool
}

func (v *viewMiddleware) BeforeModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, mc *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	// 1. Proactive compaction directly on the DTO master (non-destructive:
	//    boundary + summary inserted, full history retained). A new boundary is
	//    persisted to the transcript together with the post-boundary working
	//    set, so a cold-start resume restores the compacted view.
	if v.compactor != nil {
		v.session.mu.Lock()
		before := countBoundaries(v.session.dto)
		dto := v.compactor.Pre(ctx, v.session.dto, v.ps.lastInputTokens)
		if countBoundaries(dto) > before {
			v.session.recordBoundaryLocked(dto)
		}
		v.session.dto = dto
		v.session.mu.Unlock()
	}

	// 2. Project the DTO into the model view. NoaView (when installed by the
	//    noa port) replaces MessagesForAPI as the projection.
	v.session.mu.Lock()
	dto := v.session.dto
	v.session.mu.Unlock()
	apiView := acllm.MessagesForAPI(dto)
	if v.noaView != nil {
		raw := v.noaView.View(dto)
		stripped := make([]acllm.Message, 0, len(raw))
		for _, m := range raw {
			if !acllm.IsBoundaryMarker(m) {
				stripped = append(stripped, m)
			}
		}
		apiView = acllm.PairToolBlocks(stripped)
	}
	projected := acllm.ToSchema(apiView)
	if v.sysMsg != nil {
		projected = append([]*schema.Message{v.sysMsg}, projected...)
	}
	state.Messages = projected
	return ctx, state, nil
}

// AfterModelRewriteState captures the assistant response into the DTO master
// history + transcript synchronously with the graph — the projection of the
// NEXT model call must already see it, and the pump may still be draining the
// previous turn's events when it runs.
func (v *viewMiddleware) AfterModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, mc *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	v.reactiveMu.Lock()
	v.reactiveTried = false // a successful model turn re-arms reactive recovery
	v.reactiveMu.Unlock()

	if len(state.Messages) == 0 {
		return ctx, state, nil
	}
	last := state.Messages[len(state.Messages)-1]
	if last == nil || last.Role != schema.Assistant {
		return ctx, state, nil
	}
	dtoMsgs := acllm.FromSchema([]*schema.Message{last})
	if len(dtoMsgs) == 0 {
		return ctx, state, nil
	}
	var u acllm.Usage
	if last.ResponseMeta != nil && last.ResponseMeta.Usage != nil {
		u = acllm.UsageFromToken(last.ResponseMeta.Usage)
	}
	v.session.mu.Lock()
	v.session.dto = append(v.session.dto, dtoMsgs...)
	writer := v.session.writer
	v.session.mu.Unlock()
	if writer != nil {
		writer.RecordMessage(dtoMsgs[0], u)
	}
	// The size the model just reported for its input (+ its output) is the
	// compaction gate's preferred count for the next turn, exactly like norma.
	v.ps.lastInputTokens = u.InputTokens + u.OutputTokens
	if v.countTurns {
		v.ps.turns++
	}
	return ctx, state, nil
}

// WrapModel installs the MaxTokens cap and the reactive-compaction retry.
func (v *viewMiddleware) WrapModel(ctx context.Context, m model.BaseModel[*schema.Message], mc *adk.ModelContext) (model.BaseModel[*schema.Message], error) {
	if v.maxTokens > 0 {
		m = &cappedModel{inner: m, maxTokens: v.maxTokens}
	}
	if v.compactor != nil {
		m = &reactiveModel{inner: m, v: v}
	}
	return m, nil
}

// cappedModel injects model.WithMaxTokens on every call (the ADK runner has no
// per-run output-cap option).
type cappedModel struct {
	inner     model.BaseModel[*schema.Message]
	maxTokens int
}

func (c *cappedModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	return c.inner.Generate(ctx, input, append(opts, model.WithMaxTokens(c.maxTokens))...)
}

func (c *cappedModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return c.inner.Stream(ctx, input, append(opts, model.WithMaxTokens(c.maxTokens))...)
}

// reactiveModel implements the 413 recovery: on a prompt-too-long failure,
// force one AutoCompact over the DTO and retry once. Exhausted recovery
// surfaces as reactiveExhaustedError → ReasonPromptTooLong. (Overflow errors
// are caught at request time — providers validate the request size before the
// first byte streams back.)
type reactiveModel struct {
	inner model.BaseModel[*schema.Message]
	v     *viewMiddleware
}

func (r *reactiveModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	msg, err := r.inner.Generate(ctx, input, opts...)
	if err == nil {
		return msg, nil
	}
	if !r.recover(ctx, err) {
		return msg, err
	}
	msg, err = r.inner.Generate(ctx, input, opts...)
	if err != nil && compaction.IsOverflow(err) {
		return msg, &reactiveExhaustedError{err: err}
	}
	return msg, err
}

func (r *reactiveModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	sr, err := r.inner.Stream(ctx, input, opts...)
	if err == nil {
		return sr, nil
	}
	if !r.recover(ctx, err) {
		return nil, err
	}
	sr, err = r.inner.Stream(ctx, input, opts...)
	if err != nil && compaction.IsOverflow(err) {
		return nil, &reactiveExhaustedError{err: err}
	}
	return sr, err
}

// recover runs one forced AutoCompact when err is a prompt-too-long failure
// and no reactive attempt is in flight this run. It reports whether the caller
// should retry the request.
func (r *reactiveModel) recover(ctx context.Context, err error) bool {
	if !compaction.IsOverflow(err) {
		return false
	}
	r.v.reactiveMu.Lock()
	if r.v.reactiveTried {
		r.v.reactiveMu.Unlock()
		return false
	}
	r.v.reactiveTried = true
	r.v.reactiveMu.Unlock()

	r.v.session.mu.Lock()
	msgs, shrank := r.v.session.compactor.Reactive(ctx, r.v.session.dto)
	if shrank {
		r.v.session.recordBoundaryLocked(msgs)
		r.v.session.dto = msgs
	}
	r.v.session.mu.Unlock()
	return shrank
}

type reactiveExhaustedError struct{ err error }

func (e *reactiveExhaustedError) Error() string {
	return "prompt too long after reactive compaction: " + e.err.Error()
}
func (e *reactiveExhaustedError) Unwrap() error { return e.err }

// --- deferred middleware (spec §7) ---

type deferredMiddleware struct {
	adk.TypedBaseChatModelAgentMiddleware[*schema.Message]

	infos    []*schema.ToolInfo // all registry tool infos, registry order
	deferred map[string]bool
	unlock   *tools.UnlockSet
}

// BeforeModelRewriteState withholds the schemas of locked deferred tools from
// the model's tool list; unlocked deferred tools are added back. The access
// tools (SearchExtraTools/ExecuteExtraTool) are never deferred and always stay.
func (d *deferredMiddleware) BeforeModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, mc *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	if len(d.deferred) == 0 {
		return ctx, state, nil
	}
	out := make([]*schema.ToolInfo, 0, len(d.infos))
	for _, ti := range d.infos {
		if d.deferred[ti.Name] && d.unlock != nil && !d.unlock.Has(ti.Name) {
			continue
		}
		out = append(out, ti)
	}
	state.ToolInfos = out
	return ctx, state, nil
}

// --- gate middleware (spec §6) ---

type gateMiddleware struct {
	adk.TypedBaseChatModelAgentMiddleware[*schema.Message]

	session  *Session
	rs       *runState
	reg      *tools.Registry
	unlock   *tools.UnlockSet
	deferred map[string]bool
	hooks    HookRunner
	mode     tools.Mode
	sched    *toolScheduler
	tcTpl    tools.ToolContext
}

// WrapInvokableToolCall is the guard/intercept/steer blocking point. The
// returned endpoint NEVER returns a non-nil Go error: the eino ToolsNode turns
// tool errors into run-fatal failures, whereas tool failures must reach the
// model as error tool_result blocks (norma semantics).
func (g *gateMiddleware) WrapInvokableToolCall(ctx context.Context, endpoint adk.InvokableToolCallEndpoint, tCtx *adk.ToolContext) (adk.InvokableToolCallEndpoint, error) {
	t, ok := g.reg.Get(tCtx.Name)
	if !ok {
		return endpoint, nil // not kernel-managed; pass through untouched
	}
	return func(ctx context.Context, args string, opts ...tool.Option) (string, error) {
		text, isErr, extras := g.execOne(ctx, t, tCtx.CallID, args)
		g.session.recordToolResult(g.rs, tCtx.CallID, text, isErr, extras)
		return text, nil
	}, nil
}

// execOne resolves, permission-checks, and runs a single tool call — norma
// harness execOne ordering, verbatim. It never panics; failures become error
// results.
func (g *gateMiddleware) execOne(ctx context.Context, t tools.CoreTool, callID, args string) (text string, isErr bool, extras []acllm.Message) {
	fail := func(msg string) (string, bool, []acllm.Message) { return msg, true, nil }

	// 0. Deferred hard gate (V5 双保险): a locked deferred tool is not callable
	// directly — the model must go through ExecuteExtraTool after its skill
	// loaded (the access tool runs the same check internally).
	if g.deferred[t.Name()] && g.unlock != nil && !g.unlock.Has(t.Name()) {
		return fail("Error: tool " + t.Name() + " is not unlocked in this session — load the skill that provides it first.")
	}

	input := tools.ArgsFromEino(args)

	// 1. Schema validation (FR-04.5). The eino ToolsNode parses JSON but does
	//    not schema-validate; a tool may opt out (Spec.RawInput).
	if r, ok := t.(interface{ AcceptsRawInput() bool }); !ok || !r.AcceptsRawInput() {
		if err := tools.ValidateInput(t.InputSchema(), input); err != nil {
			return fail("Error: invalid tool input: " + err.Error())
		}
	}

	// 2. Permission pipeline (bypass passes through; an "ask" verdict with no
	//    interactive callback denies).
	pc := tools.Context{Mode: g.mode, WorkingDir: g.tcTpl.WorkingDir}
	dec := tools.Evaluate(ctx, tools.Request{
		ToolName:     t.Name(),
		Input:        input,
		IsReadOnly:   t.IsReadOnly(input),
		ToolDecision: t.CheckPermissions(ctx, input, pc),
		Ctx:          pc,
	})
	if dec.Behavior != tools.Allow {
		msg := dec.Message
		if msg == "" {
			msg = "denied"
		}
		return fail("Tool call was not permitted: " + msg)
	}
	if len(dec.UpdatedInput) > 0 {
		input = dec.UpdatedInput
	}

	// 3. PreToolUse hook. Block → no execution; the message becomes the tool
	//    error result (guard/intercept's minute-long synchronous approval wait
	//    happens right here, semantics unchanged).
	if g.hooks != nil {
		if block, msg, updated := g.hooks.PreToolUse(ctx, t.Name(), input); block {
			return fail("Blocked by hook: " + msg)
		} else if len(updated) > 0 {
			input = updated
		}
	}

	// 4. Execute under the concurrency discipline: safe tools run alongside
	//    each other, a non-safe tool requires exclusive access (norma FIFO +
	//    exclusivity), bounded by MaxConcurrency.
	tc := g.tcTpl
	tc.ToolUseID = callID
	ctx = tools.WithToolContext(ctx, &tc)
	safe := t.IsConcurrencySafe(input)
	g.sched.acquire(safe)
	res, callErr := safeToolCall(ctx, t, input, &tc)
	g.sched.release(safe)
	if callErr != nil {
		res = tools.Errorf("Error: " + callErr.Error())
	}

	// 5. Global output cap at the single post-tool choke point (idempotent).
	text = tools.FlattenResultEino(&tc, res)

	// 6. PostToolUse audit (result JSON-encoded, as the hook registry expects).
	if g.hooks != nil {
		raw, _ := json.Marshal(text)
		g.hooks.PostToolUse(ctx, t.Name(), input, string(raw), res.IsError)
	}

	if len(res.Content) == 0 {
		text = "(no output)"
	}
	return text, res.IsError, res.Extra
}

// safeToolCall invokes the tool with guardPanic semantics: a panicking tool
// becomes an error, never a crashed run.
func safeToolCall(ctx context.Context, t tools.CoreTool, input json.RawMessage, tc *tools.ToolContext) (res tools.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = tools.Result{}
			err = fmt.Errorf("tool %s panicked: %v", t.Name(), r)
		}
	}()
	return t.Call(ctx, input, tc)
}

// toolScheduler enforces norma's concurrency rule with an RWMutex over a
// MaxConcurrency semaphore: concurrency-safe tools share the read side, a
// non-safe tool takes the write side (exclusive access).
type toolScheduler struct {
	ex  sync.RWMutex
	sem chan struct{}
}

func newToolScheduler(maxConcurrency int) *toolScheduler {
	if maxConcurrency <= 0 {
		maxConcurrency = 10
	}
	return &toolScheduler{sem: make(chan struct{}, maxConcurrency)}
}

func (s *toolScheduler) acquire(safe bool) {
	s.sem <- struct{}{}
	if safe {
		s.ex.RLock()
	} else {
		s.ex.Lock()
	}
}

func (s *toolScheduler) release(safe bool) {
	if safe {
		s.ex.RUnlock()
	} else {
		s.ex.Unlock()
	}
	<-s.sem
}

// countBoundaries counts compact-boundary markers in the DTO.
func countBoundaries(msgs []acllm.Message) int {
	n := 0
	for _, m := range msgs {
		if acllm.IsBoundaryMarker(m) {
			n++
		}
	}
	return n
}

// unknownToolResult is the ToolsNode handler for hallucinated tool names: an
// error tool_result instead of a run-fatal failure (norma execOne semantics).
// The ToolsNode attaches the real call id to the resulting tool message; the
// pump persists it into the DTO (the gate never saw that call).
func unknownToolResult() func(ctx context.Context, name, input string) (string, error) {
	return func(_ context.Context, name string, _ string) (string, error) {
		return fmt.Sprintf("Error: unknown tool %q", name), nil
	}
}
