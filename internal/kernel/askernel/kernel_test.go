package askernel

// Kernel-level tests (spec §10 test contract), driven by the fake model:
// single text turn, tool call turn + transcript, PreToolUse deny, empty-turn
// nudge with cap, settlement re-run, deferred unlock before/after, resume
// rebuild, and forced compaction.

import (
	"context"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/platform/llm/acllm"
	"github.com/c1ayooo/4zrec/internal/kernel/compaction"
	"github.com/c1ayooo/4zrec/internal/toolface/tools"
	"github.com/c1ayooo/4zrec/internal/kernel/transcript"
	"github.com/cloudwego/eino/schema"
)

func newTestSession(t *testing.T, m *fakeModel, opts func(*Options)) *Session {
	t.Helper()
	o := Options{Model: m}
	if opts != nil {
		opts(&o)
	}
	return NewSession(o)
}

// (a) A single text turn yields KindText deltas and a completed KindResult
// with cumulative usage.
func TestKernelSingleTextTurn(t *testing.T) {
	m := &fakeModel{usage: &schema.TokenUsage{PromptTokens: 100, CompletionTokens: 10}}
	m.script(schema.AssistantMessage("hello world", nil))
	s := newTestSession(t, m, nil)
	defer s.Close()

	c := drainPrompt(s, context.Background(), "hi")
	if len(c.errs) != 0 {
		t.Fatalf("errors: %v", c.errs)
	}
	if got := c.texts(); got != "hello world" {
		t.Errorf("text = %q, want %q", got, "hello world")
	}
	var usageSeen bool
	for _, ev := range c.events {
		if ev.Kind == KindUsage && ev.Usage != nil {
			usageSeen = true
			if ev.Usage.InputTokens != 100 || ev.Usage.OutputTokens != 10 {
				t.Errorf("usage = %+v, want input 100 output 10", ev.Usage)
			}
		}
	}
	if !usageSeen {
		t.Errorf("no KindUsage event; kinds = %v", c.kinds())
	}
	if c.terminal == nil {
		t.Fatalf("no terminal")
	}
	if c.terminal.Reason != ReasonCompleted {
		t.Errorf("reason = %v, want completed", c.terminal.Reason)
	}
	if c.terminal.Turns != 1 {
		t.Errorf("turns = %d, want 1", c.terminal.Turns)
	}
	if c.terminal.Text != "hello world" {
		t.Errorf("terminal text = %q", c.terminal.Text)
	}
	if c.terminal.Usage.OutputTokens != 10 {
		t.Errorf("terminal usage = %+v", c.terminal.Usage)
	}
	if len(s.Messages()) != 2 {
		t.Errorf("DTO = %d messages, want 2 (user + assistant)", len(s.Messages()))
	}
}

// (b) A tool call turn yields KindToolUse then KindToolResult, and the
// transcript file carries the assistant tool_use + user tool_result records.
func TestKernelToolCallTurnWritesTranscript(t *testing.T) {
	ran := 0
	echo := simpleTool("echo", "echo ran", func() { ran++ })
	m := &fakeModel{}
	m.script(toolCallMsg("call1", "echo", "{}"), schema.AssistantMessage("all done", nil))

	store := transcript.NewStore(t.TempDir())
	s := newTestSession(t, m, func(o *Options) {
		o.Tools = []tools.CoreTool{echo}
		o.Transcript = store
	})
	defer s.Close()

	c := drainPrompt(s, context.Background(), "hi")
	if len(c.errs) != 0 {
		t.Fatalf("errors: %v", c.errs)
	}
	if ran != 1 {
		t.Fatalf("tool ran %d times, want 1", ran)
	}

	var sawUse, sawResult bool
	for _, ev := range c.events {
		switch ev.Kind {
		case KindToolUse:
			sawUse = true
			if ev.ToolUse == nil || ev.ToolUse.Name != "echo" || ev.ToolUse.ID != "call1" {
				t.Errorf("tool_use event = %+v", ev.ToolUse)
			}
		case KindToolResult:
			sawResult = true
			if ev.ToolResult == nil || ev.ToolResult.ToolUseID != "call1" || ev.ToolResult.IsError {
				t.Errorf("tool_result event = %+v", ev.ToolResult)
			}
			if !strings.Contains(ev.ToolResult.Content[0].Text, "echo ran") {
				t.Errorf("tool_result text = %v", ev.ToolResult.Content)
			}
		}
	}
	if !sawUse || !sawResult {
		t.Errorf("missing events: sawUse=%v sawResult=%v kinds=%v", sawUse, sawResult, c.kinds())
	}

	recs, err := store.Load(store.MainPath(s.SessionID()))
	if err != nil {
		t.Fatalf("load transcript: %v", err)
	}
	var nUser, nAssistant, nUse, nResult int
	for _, r := range recs {
		if r.Type != "message" || r.Message == nil {
			continue
		}
		if r.Message.Role == acllm.RoleUser {
			nUser++
			for _, b := range r.Message.Content {
				if b.Type == acllm.BlockToolResult {
					nResult++
					if b.IsError {
						t.Errorf("tool_result recorded as error: %+v", b)
					}
				}
			}
		}
		if r.Message.Role == acllm.RoleAssistant {
			nAssistant++
			nUse += len(r.Message.ToolUses())
		}
	}
	if nUser != 2 || nAssistant != 2 || nUse != 1 || nResult != 1 {
		t.Errorf("transcript = users %d assistants %d tool_use %d tool_result %d; records:\n%s",
			nUser, nAssistant, nUse, nResult, transcriptDump(recs))
	}
}

func transcriptDump(recs []transcript.Record) string {
	var b strings.Builder
	for _, r := range recs {
		if r.Message != nil {
			b.WriteString(string(r.Message.Role) + ":" + r.Message.Text() + "\n")
		}
	}
	return b.String()
}

// (c) A PreToolUse block: the tool is not executed and the model's follow-up
// call sees the block message as the tool error result.
func TestKernelPreToolUseBlock(t *testing.T) {
	ran := 0
	echo := simpleTool("echo", "echo ran", func() { ran++ })
	hooks := NewRegistry().On(PreToolUse, func(ctx context.Context, ev Event) Result {
		return Result{Decision: "block", Message: "blocked by platform governance"}
	})
	m := &fakeModel{}
	m.script(toolCallMsg("call1", "echo", "{}"), schema.AssistantMessage("recovered", nil))
	s := newTestSession(t, m, func(o *Options) {
		o.Tools = []tools.CoreTool{echo}
		o.Hooks = hooks
	})
	defer s.Close()

	c := drainPrompt(s, context.Background(), "hi")
	if ran != 0 {
		t.Errorf("blocked tool executed %d times, want 0", ran)
	}
	if c.terminal == nil || c.terminal.Reason != ReasonCompleted {
		t.Fatalf("terminal = %+v", c.terminal)
	}
	// The model's second call sees the block text as the tool result.
	second := m.inputOf(1)
	if !inputContains(second, "Blocked by hook: blocked by platform governance") {
		t.Errorf("model follow-up input missing block message: %+v", second)
	}
	// And the DTO/transcript record carries IsError.
	s.mu.Lock()
	dto := append([]acllm.Message(nil), s.dto...)
	s.mu.Unlock()
	found := false
	for _, msg := range dto {
		for _, b := range msg.Content {
			if b.Type == acllm.BlockToolResult && b.IsError &&
				strings.Contains(b.Content[0].Text, "Blocked by hook") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no error tool_result block in DTO: %+v", dto)
	}
}

// (d) The empty-turn nudge: a run ending with an empty assistant turn gets a
// continuation user message injected and one more bounded run; the cap is
// respected (worker-style NudgeLimit=2 → exactly 2 nudges, 3 model calls).
func TestKernelEmptyTurnNudge(t *testing.T) {
	m := &fakeModel{}
	m.script(
		schema.AssistantMessage("", nil),
		schema.AssistantMessage("", nil),
		schema.AssistantMessage("", nil),
	)
	s := newTestSession(t, m, func(o *Options) { o.NudgeLimit = 2 })
	defer s.Close()

	c := drainPrompt(s, context.Background(), "hi")
	if c.terminal == nil || c.terminal.Reason != ReasonCompleted {
		t.Fatalf("terminal = %+v", c.terminal)
	}
	if got := m.callsMade(); got != 3 {
		t.Errorf("model calls = %d, want 3 (cap 2 nudges)", got)
	}
	// The nudged model calls see the nudge as the last user message.
	for i := 1; i <= 2; i++ {
		input := m.inputOf(i)
		if len(input) == 0 || !strings.Contains(input[len(input)-1].Content, "empty response") {
			t.Errorf("call %d input missing nudge: %+v", i, input)
		}
	}
	// The DTO retains both nudges (transcript-recorded, norma parity).
	nudges := 0
	for _, msg := range s.Messages() {
		if strings.Contains(msg.Text(), "empty response") {
			nudges++
		}
	}
	if nudges != 2 {
		t.Errorf("nudge messages in DTO = %d, want 2", nudges)
	}
}

// (e) Settlement: MaxTurns=1 over a script of tool-call turns → the settlement
// re-run happens on the injected wrap-up prompt and the terminal keeps
// ReasonMaxTurns.
func TestKernelSettlement(t *testing.T) {
	ran := 0
	echo := simpleTool("echo", "echo ran", func() { ran++ })
	m := &fakeModel{}
	m.script(
		toolCallMsg("c1", "echo", "{}"),
		toolCallMsg("c2", "echo", "{}"),
		schema.AssistantMessage("settled", nil),
	)
	s := newTestSession(t, m, func(o *Options) {
		o.Tools = []tools.CoreTool{echo}
		o.MaxTurns = 1
		o.Settlement = &Settlement{Prompt: "wrap up now", MaxTurns: 2}
	})
	defer s.Close()

	c := drainPrompt(s, context.Background(), "go")
	if c.terminal == nil {
		t.Fatalf("no terminal; events: %v", c.kinds())
	}
	if c.terminal.Reason != ReasonMaxTurns {
		t.Errorf("reason = %v, want max_turns", c.terminal.Reason)
	}
	if c.terminal.Text != "settled" {
		t.Errorf("text = %q, want settled", c.terminal.Text)
	}
	if ran != 2 {
		t.Errorf("tool ran %d times, want 2 (primary + settlement)", ran)
	}
	if m.callsMade() != 3 {
		t.Errorf("model calls = %d, want 3 (1 primary + 2 settlement)", m.callsMade())
	}
	// The settlement prompt was injected as a user turn for the wrap-up run.
	third := m.inputOf(2)
	if !inputContains(third, "wrap up now") {
		t.Errorf("settlement call missing wrap-up prompt: %+v", third)
	}
}

// (f) Deferred tools: locked → schema withheld from every model binding and
// both direct and ExecuteExtraTool calls hard-gated; after unlock.Add the
// schema is bound again and ExecuteExtraTool succeeds.
func TestKernelDeferredUnlock(t *testing.T) {
	secret := simpleTool("secret", "SECRET-OK", nil)
	m := &fakeModel{}
	m.script(
		toolCallMsg("d1", "secret", "{}"), // direct call, locked
		toolCallMsg("d2", tools.ExecuteExtraToolName, `{"tool_name":"secret","params":{}}`), // gated by the access tool
		schema.AssistantMessage("try failed", nil),
		toolCallMsg("d3", tools.ExecuteExtraToolName, `{"tool_name":"secret","params":{}}`), // after unlock
		schema.AssistantMessage("ok now", nil),
	)
	unlock := tools.NewUnlockSet() // nothing unlocked yet (skill-gated disclosure)
	s := newTestSession(t, m, func(o *Options) {
		o.Tools = []tools.CoreTool{secret}
		o.DeferredTools = []string{"secret"}
		o.Unlock = unlock
		o.SystemPrompt = []string{"base prompt"}
	})
	defer s.Close()

	c1 := drainPrompt(s, context.Background(), "first")
	if c1.terminal == nil || c1.terminal.Reason != ReasonCompleted {
		t.Fatalf("prompt1 terminal = %+v", c1.terminal)
	}
	blocks := c1.toolResultBlocks()
	if len(blocks) != 2 {
		t.Fatalf("prompt1 tool results = %d, want 2", len(blocks))
	}
	for _, b := range blocks {
		if !b.IsError {
			t.Errorf("locked call not an error: %+v", b)
		}
		if !strings.Contains(b.Content[0].Text, "not unlocked") {
			t.Errorf("locked call text = %q", b.Content[0].Text)
		}
	}
	// The deferred block is appended to the system prompt.
	if !inputContains(m.inputOf(0), "<available-deferred-tools>") {
		t.Errorf("system prompt missing deferred block")
	}
	// Locked: no binding of the first three calls carried the secret schema.
	for i, bind := range m.boundOf(3) {
		if bindNames(bind)["secret"] {
			t.Errorf("binding %d carried the locked secret schema", i)
		}
		if !bindNames(bind)[tools.SearchExtraToolsName] || !bindNames(bind)[tools.ExecuteExtraToolName] {
			t.Errorf("binding %d missing the access tools: %v", i, bindNames(bind))
		}
	}

	// Host unlocks (UI/skill load) and prompts again.
	unlock.Add("secret")
	c2 := drainPrompt(s, context.Background(), "second")
	blocks = c2.toolResultBlocks()
	if len(blocks) != 1 {
		t.Fatalf("prompt2 tool results = %d, want 1", len(blocks))
	}
	if blocks[0].IsError || !strings.Contains(blocks[0].Content[0].Text, "SECRET-OK") {
		t.Errorf("unlocked call = %+v", blocks[0])
	}
	newBindings := m.boundOf(m.callsMade())[3:]
	for i, bind := range newBindings {
		if !bindNames(bind)["secret"] {
			t.Errorf("post-unlock binding %d missing secret schema: %v", i, bindNames(bind))
		}
	}
}

// (g) Resume: run once, then a fresh Session + Resume rebuilds the full DTO
// master history and continues appending to the same transcript file.
func TestKernelResume(t *testing.T) {
	m := &fakeModel{}
	m.script(schema.AssistantMessage("first answer", nil), schema.AssistantMessage("second answer", nil))
	store := transcript.NewStore(t.TempDir())
	s1 := newTestSession(t, m, func(o *Options) { o.Transcript = store })
	id := s1.SessionID()
	c := drainPrompt(s1, context.Background(), "first question")
	if c.terminal == nil || c.terminal.Reason != ReasonCompleted {
		t.Fatalf("first run terminal = %+v", c.terminal)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2 := newTestSession(t, m, func(o *Options) { o.Transcript = store; o.SessionID = id })
	if err := s2.Resume(id); err != nil {
		t.Fatalf("resume: %v", err)
	}
	msgs := s2.Messages()
	if len(msgs) != 2 || msgs[0].Text() != "first question" || msgs[1].Text() != "first answer" {
		t.Errorf("resumed history = %+v", msgs)
	}
	c2 := drainPrompt(s2, context.Background(), "second question")
	if c2.terminal == nil || c2.terminal.Reason != ReasonCompleted {
		t.Fatalf("second run terminal = %+v", c2.terminal)
	}
	if c2.terminal.Text != "second answer" {
		t.Errorf("second answer = %q", c2.terminal.Text)
	}
	recs, err := store.Load(store.MainPath(id))
	if err != nil {
		t.Fatalf("reload transcript: %v", err)
	}
	if len(recs) != 4 {
		t.Errorf("transcript records = %d, want 4 (2 per prompt, same file)", len(recs))
	}
}

// (h) Compaction: a tiny ContextWindow forces a boundary before the second
// model call; the model receives the boundary-stripped working set with the
// summary, the full DTO history is retained, and the boundary reaches the
// transcript.
func TestKernelCompactionBoundary(t *testing.T) {
	big := strings.Repeat("x", 6000)
	read := simpleTool("Read", big, nil)
	m := &fakeModel{}
	m.script(toolCallMsg("r1", "Read", "{}"), schema.AssistantMessage("noted the file", nil))
	summaries := 0
	store := transcript.NewStore(t.TempDir())
	s := newTestSession(t, m, func(o *Options) {
		o.Tools = []tools.CoreTool{read}
		o.Transcript = store
		o.Compaction = &compaction.Config{ContextWindow: 200, MaxOutputTokens: 8, KeepRecent: 2}
		o.CompactionSummarizer = func(ctx context.Context, msgs []acllm.Message) (string, error) {
			summaries++
			return "the conversation summary", nil
		}
	})
	defer s.Close()

	c := drainPrompt(s, context.Background(), "read it")
	if c.terminal == nil || c.terminal.Reason != ReasonCompleted {
		t.Fatalf("terminal = %+v", c.terminal)
	}
	if summaries != 1 {
		t.Errorf("summarizer calls = %d, want 1", summaries)
	}
	// The second model call got the summary message and no boundary marker.
	second := m.inputOf(1)
	if !inputContains(second, "This session is being continued from a previous conversation") ||
		!inputContains(second, "the conversation summary") {
		t.Errorf("second call missing summary: %+v", second)
	}
	for _, msg := range second {
		if len(msg.Extra) > 0 {
			if _, ok := msg.Extra[acllm.ExtraBoundary]; ok {
				t.Errorf("boundary marker leaked to the model")
			}
		}
	}
	// The DTO retains the full history: 6 messages = user, assistant tool_use,
	// user tool_result, assistant answer + inserted boundary + summary.
	s.mu.Lock()
	n := len(s.dto)
	s.mu.Unlock()
	if n != 6 {
		t.Errorf("DTO length = %d, want 6 (full history incl. boundary+summary)", n)
	}
	// The transcript carries the boundary observability record plus the
	// post-boundary working set (boundary marker, summary, kept tail).
	recs, err := store.Load(store.MainPath(s.SessionID()))
	if err != nil {
		t.Fatalf("load transcript: %v", err)
	}
	nBoundary := 0
	for _, r := range recs {
		if r.Type == "boundary" {
			nBoundary++
			if r.Boundary == nil || r.Boundary.Trigger != "auto" {
				t.Errorf("boundary record = %+v", r.Boundary)
			}
		}
	}
	if nBoundary != 1 {
		t.Errorf("boundary records = %d, want 1", nBoundary)
	}
}

// Guarded panics and Go errors both become error tool results the model can
// react to — never a crashed run.
func TestKernelToolPanicAndError(t *testing.T) {
	bad := panickingTool("panic_tool")
	worse := failingTool("fail_tool")
	m := &fakeModel{}
	m.script(
		schema.AssistantMessage("", []schema.ToolCall{
			{ID: "p1", Function: schema.FunctionCall{Name: "panic_tool", Arguments: "{}"}},
			{ID: "f1", Function: schema.FunctionCall{Name: "fail_tool", Arguments: "{}"}},
		}),
		schema.AssistantMessage("handled", nil),
	)
	s := newTestSession(t, m, func(o *Options) {
		o.Tools = []tools.CoreTool{bad, worse}
	})
	defer s.Close()

	c := drainPrompt(s, context.Background(), "go")
	if c.terminal == nil || c.terminal.Reason != ReasonCompleted {
		t.Fatalf("terminal = %+v", c.terminal)
	}
	blocks := c.toolResultBlocks()
	if len(blocks) != 2 {
		t.Fatalf("tool results = %d, want 2", len(blocks))
	}
	byID := map[string]acllm.ContentBlock{}
	for _, b := range blocks {
		byID[b.ToolUseID] = b
	}
	if !byID["p1"].IsError || !strings.Contains(byID["p1"].Content[0].Text, "panicked") {
		t.Errorf("panic result = %+v", byID["p1"])
	}
	if !byID["f1"].IsError || !strings.Contains(byID["f1"].Content[0].Text, "boom failure") {
		t.Errorf("error result = %+v", byID["f1"])
	}
}

// A model error maps to model_error; cancellation maps to aborted_streaming.
func TestKernelTerminalMapping(t *testing.T) {
	t.Run("model_error", func(t *testing.T) {
		m := &fakeModel{}
		m.failTurn(errBoom)
		s := newTestSession(t, m, nil)
		defer s.Close()
		c := drainPrompt(s, context.Background(), "hi")
		if c.terminal == nil || c.terminal.Reason != ReasonModelError {
			t.Fatalf("terminal = %+v", c.terminal)
		}
	})
	t.Run("aborted_streaming", func(t *testing.T) {
		m := &fakeModel{}
		m.script(schema.AssistantMessage("never in time", nil))
		ctx, cancel := context.WithCancel(context.Background())
		s := newTestSession(t, m, nil)
		defer s.Close()
		cancel()
		c := drainPrompt(s, ctx, "hi")
		if c.terminal == nil || c.terminal.Reason != ReasonAbortedStreaming {
			t.Fatalf("terminal = %+v", c.terminal)
		}
	})
}
