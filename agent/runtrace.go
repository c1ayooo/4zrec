package agent

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/c1ayooo/4zrec/acllm"
	"github.com/c1ayooo/4zrec/askernel"
	"github.com/c1ayooo/4zrec/db"
	"github.com/c1ayooo/4zrec/intercept"
)

// Run-scoped intercept-trace correlation (see capture.go).
//
// norma's harness ran the event loop and tool execution on ONE goroutine, so
// recording a tool_use into the intercept Trace (Trace.Start) always preceded
// the guard's review claim (intercept.WithCall) — the audit got the tool_use id
// and exact correlation. askernel executes tools on the kernel's goroutines
// while the event pump drains concurrently, so the pump's KindToolUse event can
// lose that race and the review would record correlation=unavailable.
//
// Fix: start the trace from the one seam that is guaranteed to run BEFORE the
// guard's review — the PreToolUse hook chain itself. The agent constructors
// wrap their hook runner with traceHooks (withRunTrace); the wrapper reads the
// run's Trace from ctx (intercept.WithTrace ran before Prompt) and correlates
// the pending tool_use straight out of the DTO master history, which the kernel
// writes synchronously before its ToolsNode executes anything.

// sessionRef lets the wrapped hooks reach the Session's DTO history. The Session
// is built after the Options that carry the hooks, so the reference is filled in
// by captureRunSession right before the first Prompt.
type sessionRef struct {
	s atomic.Pointer[askernel.Session]
}

func (r *sessionRef) mark(s *askernel.Session) {
	if r != nil && s != nil {
		r.s.CompareAndSwap(nil, s)
	}
}

func (r *sessionRef) session() *askernel.Session {
	if r == nil {
		return nil
	}
	return r.s.Load()
}

// withRunTrace wraps opts.Hooks so tool calls are correlated into the run's
// intercept trace before the guard claims them, and their results recorded as
// soon as execution finishes. A nil hook runner needs no wrapping (nothing
// consumes the trace without a review).
func withRunTrace(opts *askernel.Options, ref *sessionRef) {
	if opts.Hooks == nil {
		return
	}
	opts.Hooks = &traceHooks{prev: opts.Hooks, ref: ref, state: &traceState{
		started:  map[string]bool{},
		inflight: map[string][]string{},
	}}
}

// traceState tracks which tool_use ids this run already correlated, and the
// started-but-not-yet-finished ids per (tool, input) so PostToolUse can bind
// the execution result without a tool_use id (the askernel hook signatures
// carry none).
type traceState struct {
	mu       sync.Mutex
	started  map[string]bool
	inflight map[string][]string
}

// traceHooks decorates a hook runner with the pre-review trace correlation and
// the post-execution result recording. Both run on the kernel's tool-execution
// path — strictly before the review claim and strictly after the result exists,
// so no event-pump race is involved.
type traceHooks struct {
	prev  askernel.HookRunner
	ref   *sessionRef
	state *traceState
}

func (h *traceHooks) PreToolUse(ctx context.Context, name string, input json.RawMessage) (bool, string, json.RawMessage) {
	if t := intercept.TraceFrom(ctx); t != nil {
		if s := h.ref.session(); s != nil {
			h.state.mu.Lock()
			var fresh []string
			for _, id := range pendingToolUseIDs(s.Messages(), name, string(input)) {
				if h.state.started[id] {
					continue
				}
				h.state.started[id] = true
				fresh = append(fresh, id)
			}
			if len(fresh) > 0 {
				key := name + "\x00" + string(input)
				h.state.inflight[key] = append(h.state.inflight[key], fresh...)
			}
			h.state.mu.Unlock()
			for _, id := range fresh {
				t.Start(id, name, input)
			}
		}
	}
	return h.prev.PreToolUse(ctx, name, input)
}

func (h *traceHooks) PostToolUse(ctx context.Context, name string, input json.RawMessage, result string, isErr bool) {
	if t := intercept.TraceFrom(ctx); t != nil {
		h.state.mu.Lock()
		key := name + "\x00" + string(input)
		var id string
		if q := h.state.inflight[key]; len(q) > 0 {
			id, h.state.inflight[key] = q[0], q[1:]
		}
		h.state.mu.Unlock()
		if id != "" {
			// The kernel hands PostToolUse the flattened output JSON-encoded.
			var out string
			_ = json.Unmarshal([]byte(result), &out)
			t.Append(db.InterceptContextEntry{Kind: "tool_result", ToolUseID: id, Text: out, IsError: isErr})
			t.Complete(id, out, isErr)
		}
	}
	h.prev.PostToolUse(ctx, name, input, result, isErr)
}

func (h *traceHooks) Stop(ctx context.Context, messages []acllm.Message) (bool, []string, string) {
	return h.prev.Stop(ctx, messages)
}

// pendingToolUseIDs returns the ids of the conversation's tool_use blocks that
// match (name, input) and have no tool_result yet — i.e. the calls currently
// reaching execution. All matches are started (never guessed between them): a
// single match correlates exactly; several leave the ambiguity marking to
// intercept.WithCall, exactly like norma's digest correlation.
func pendingToolUseIDs(msgs []acllm.Message, name, input string) []string {
	answered := map[string]int{} // tool_use id → position of its tool_result
	type pending struct {
		id   string
		name string
		in   string
		pos  int
	}
	var calls []pending
	for i := range msgs {
		for _, b := range msgs[i].Content {
			switch b.Type {
			case acllm.BlockToolUse:
				calls = append(calls, pending{id: b.ID, name: b.Name, in: string(b.Input), pos: i})
			case acllm.BlockToolResult:
				if _, ok := answered[b.ToolUseID]; !ok {
					answered[b.ToolUseID] = i
				}
			}
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range calls {
		if c.name != name || c.in != input || seen[c.id] {
			continue
		}
		if pos, done := answered[c.id]; done && pos >= c.pos {
			continue // already executed
		}
		seen[c.id] = true
		out = append(out, c.id)
	}
	return out
}
