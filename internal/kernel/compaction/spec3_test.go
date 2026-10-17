package compaction

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/platform/llm/acllm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// captureModel records each request and yields a scripted reply, optionally
// failing the first failN Generate/Stream calls with failErr (default: an
// overflow error). It is the fake model.BaseChatModel backing the Summarizer.
type captureModel struct {
	reqs    [][]*schema.Message // the exact request messages of each call
	maxToks []int               // the resolved MaxTokens of each call
	reply   string
	failN   int
	failErr error
	calls   int
}

// record logs the request and returns the scripted failure (if any).
func (p *captureModel) record(msgs []*schema.Message, opts ...model.Option) error {
	p.calls++
	p.reqs = append(p.reqs, msgs)
	o := model.GetCommonOptions(&model.Options{}, opts...)
	mt := 0
	if o.MaxTokens != nil {
		mt = *o.MaxTokens
	}
	p.maxToks = append(p.maxToks, mt)
	if p.calls <= p.failN {
		e := p.failErr
		if e == nil {
			e = errors.New("prompt is too long")
		}
		return e
	}
	return nil
}

func (p *captureModel) Generate(_ context.Context, msgs []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	if err := p.record(msgs, opts...); err != nil {
		return nil, err
	}
	return schema.AssistantMessage(p.reply, nil), nil
}

func (p *captureModel) Stream(_ context.Context, msgs []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	if err := p.record(msgs, opts...); err != nil {
		return nil, err
	}
	sr, sw := schema.Pipe[*schema.Message](2)
	go func() {
		defer sw.Close()
		sw.Send(schema.AssistantMessage(p.reply, nil), nil)
	}()
	return sr, nil
}

func asstText(s string) acllm.Message {
	return acllm.Message{Role: acllm.RoleAssistant, Content: []acllm.ContentBlock{acllm.TextBlock(s)}}
}

// --- MicroCompact / AutoCompact are covered in compaction_test.go; these cover
// the three-mechanism spec surface (COMPACTION-SPEC-3.md). ---

func TestReactiveRunsAutoCompactOnly(t *testing.T) {
	c := New(smallWindow(), func(context.Context, []acllm.Message) (string, error) { return "DIGEST", nil })
	var msgs []acllm.Message
	for range 8 {
		msgs = append(msgs, bigMsg(acllm.RoleUser, 4000))
	}
	out, ok := c.Reactive(context.Background(), msgs)
	if !ok {
		t.Fatal("reactive should shrink the API view")
	}
	if acllm.LastBoundaryIndex(out) < 0 {
		t.Fatal("reactive must insert a boundary (it runs AutoCompact)")
	}
	// Non-destructive: full history retained + boundary + summary, no snip removal.
	if len(out) != len(msgs)+2 {
		t.Fatalf("len(out)=%d, want %d (history + boundary + summary)", len(out), len(msgs)+2)
	}
}

func TestReactiveNoSummarizerReturnsFalse(t *testing.T) {
	c := New(smallWindow(), nil) // summarize == nil → AutoCompact cannot run
	msgs := []acllm.Message{bigMsg(acllm.RoleUser, 4000), bigMsg(acllm.RoleUser, 4000)}
	if _, ok := c.Reactive(context.Background(), msgs); ok {
		t.Fatal("with no summarizer, reactive cannot shrink (no snip fallback)")
	}
}

func TestCountPrefersLastInputTokens(t *testing.T) {
	c := New(Config{ContextWindow: 200000}, nil)
	msgs := []acllm.Message{bigMsg(acllm.RoleUser, 4000)}
	if got := c.count(msgs, 12345); got != 12345 {
		t.Fatalf("count should prefer lastInputTokens=12345, got %d", got)
	}
	if est := c.count(msgs, 0); est <= 0 {
		t.Fatal("estimation fallback should be > 0")
	}
}

func TestBufferKeyedOnEffectiveWindow(t *testing.T) {
	// Raw window 410k is above the 400k tier, but effectiveWindow 390k is below it.
	c := New(Config{ContextWindow: 410000, MaxOutputTokens: 20000}, nil)
	if c.buffer() != 13000 {
		t.Fatalf("buffer=%d, want 13000 (keyed on effectiveWindow=390000)", c.buffer())
	}
	c2 := New(Config{ContextWindow: 420000, MaxOutputTokens: 20000}, nil) // eff=400000
	if c2.buffer() != 30000 {
		t.Fatalf("buffer=%d, want 30000", c2.buffer())
	}
}

func TestMaxTurnGrowthMinCap(t *testing.T) {
	c := New(Config{ContextWindow: 200000, MaxOutputTokens: 64000}, nil)
	// reserved = min(64000, 20000) = 20000 → growth = 20000 + 15000.
	if c.maxTurnGrowth() != 35000 {
		t.Fatalf("maxTurnGrowth=%d, want 35000", c.maxTurnGrowth())
	}
}

func TestSummaryUsesContinuationPreamble(t *testing.T) {
	c := New(smallWindow(), func(context.Context, []acllm.Message) (string, error) { return "DIGEST", nil })
	var msgs []acllm.Message
	for range 8 {
		msgs = append(msgs, bigMsg(acllm.RoleUser, 4000))
	}
	out, ok := c.autoCompact(context.Background(), msgs, 100, "auto")
	if !ok {
		t.Fatal("autoCompact did not run")
	}
	if api := acllm.MessagesForAPI(out); !strings.HasPrefix(api[0].Text(), "This session is being continued") {
		t.Fatalf("summary should carry the continuation preamble, got %q", api[0].Text())
	}
}

func TestFormatCompactSummary(t *testing.T) {
	raw := "<analysis>\nscratch thoughts\n</analysis>\n\n<summary>\nThe outcome.\n</summary>"
	got := formatCompactSummary(raw)
	if strings.Contains(got, "analysis") || strings.Contains(got, "scratch") {
		t.Fatalf("<analysis> not stripped: %q", got)
	}
	if got != "Summary:\nThe outcome." {
		t.Fatalf("got %q, want %q", got, "Summary:\nThe outcome.")
	}
}

func TestGroupByAPIRoundAndTruncate(t *testing.T) {
	msgs := []acllm.Message{acllm.UserText("u0"), asstText("a1"), acllm.UserText("u1"), asstText("a2")}
	if g := groupByAPIRound(msgs); len(g) != 3 {
		t.Fatalf("groups=%d, want 3 ([u0][a1 u1][a2])", len(g))
	}
	out, ok := truncateHeadForPTLRetry(msgs)
	if !ok {
		t.Fatal("should truncate (≥2 groups)")
	}
	if out[0].Text() != ptlRetryMarker {
		t.Fatalf("result starting with an assistant must be marker-prefixed, got %q", out[0].Text())
	}
	if _, ok := truncateHeadForPTLRetry([]acllm.Message{acllm.UserText("only")}); ok {
		t.Fatal("a single group cannot be truncated")
	}
}

func TestPairForReplayDropsDangling(t *testing.T) {
	msgs := []acllm.Message{
		{Role: acllm.RoleAssistant, Content: []acllm.ContentBlock{{Type: acllm.BlockToolUse, ID: "x", Name: "Read"}}}, // no result
		acllm.UserText("keep me"),
		{Role: acllm.RoleUser, Content: []acllm.ContentBlock{acllm.ToolResultText("y", "orphan", false)}}, // no use
	}
	out := pairForReplay(msgs)
	if len(out) != 1 || out[0].Text() != "keep me" {
		t.Fatalf("dangling tool blocks should be dropped, got %+v", out)
	}
}

func TestModelSummarizerReplaysRealMessages(t *testing.T) {
	m := &captureModel{reply: "<summary>DONE</summary>"}
	s := NewModelSummarizer(m, 8000, false)
	head := []acllm.Message{acllm.UserText("hello"), asstText("hi")}
	got, err := s(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Summary:\nDONE" {
		t.Fatalf("summary format: %q", got)
	}
	if len(m.reqs) != 1 {
		t.Fatalf("calls=%d, want 1", len(m.reqs))
	}
	req := m.reqs[0]
	// Request shape: system prompt + the replayed head + the summary request.
	if len(req) != 4 {
		t.Fatalf("request has %d messages, want 4 (system + head + summary request)", len(req))
	}
	if req[0].Role != schema.System || req[0].Content != summarySystemPrompt {
		t.Fatalf("system prompt not set: %+v", req[0])
	}
	if req[1].Role != schema.User || req[1].Content != "hello" {
		t.Fatalf("real messages not replayed: %+v", req[1])
	}
	if req[2].Role != schema.Assistant || req[2].Content != "hi" {
		t.Fatalf("real messages not replayed: %+v", req[2])
	}
	if !strings.Contains(req[3].Content, "CRITICAL: Respond with TEXT ONLY") {
		t.Fatal("summary-request prompt must be the last message")
	}
	if m.maxToks[0] != 8000 { // min(20000, 8000)
		t.Fatalf("maxTokens=%d, want 8000", m.maxToks[0])
	}
}

func TestModelSummarizerCapsAt20k(t *testing.T) {
	m := &captureModel{reply: "<summary>X</summary>"}
	_, _ = NewModelSummarizer(m, 0, false)(context.Background(), []acllm.Message{acllm.UserText("hi")})
	if m.maxToks[0] != compactMaxOutputTokens {
		t.Fatalf("maxTokens=%d, want %d", m.maxToks[0], compactMaxOutputTokens)
	}
}

func TestModelSummarizerPTLRetry(t *testing.T) {
	m := &captureModel{reply: "<summary>OK</summary>", failN: 1} // first call overflows
	s := NewModelSummarizer(m, 0, false)
	head := []acllm.Message{acllm.UserText("u0"), asstText("a1"), acllm.UserText("u1"), asstText("a2")}
	got, err := s(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Summary:\nOK" {
		t.Fatalf("got %q", got)
	}
	if len(m.reqs) != 2 {
		t.Fatalf("want 2 calls (overflow + truncated retry), got %d", len(m.reqs))
	}
	// The retry dropped the oldest API-round group (u0) and prepended the marker.
	// reqs[1] = [system, marker, a1, u1, a2, summary request].
	retry := m.reqs[1][1:]
	if retry[0].Content != ptlRetryMarker {
		t.Fatalf("retry should start with the PTL marker, got %q", retry[0].Content)
	}
	for _, msg := range retry {
		if msg.Content == "u0" {
			t.Fatal("retry should have dropped the oldest group (u0)")
		}
	}
}

func TestModelSummarizerStreamingRetry(t *testing.T) {
	m := &captureModel{reply: "<summary>R</summary>", failN: 1, failErr: errors.New("network blip")}
	s := NewModelSummarizer(m, 0, false)
	got, err := s(context.Background(), []acllm.Message{acllm.UserText("hi")})
	if err != nil {
		t.Fatal(err)
	}
	if got != "Summary:\nR" {
		t.Fatalf("got %q", got)
	}
	if len(m.reqs) != 2 { // transient failure retried once within streamSummary
		t.Fatalf("want 2 stream attempts, got %d", len(m.reqs))
	}
}

func TestModelSummarizerNonOverflowErrorSurfaces(t *testing.T) {
	// A persistent non-overflow error exhausts streaming retries and surfaces.
	m := &captureModel{reply: "x", failN: 99, failErr: errors.New("boom")}
	if _, err := NewModelSummarizer(m, 0, false)(context.Background(), []acllm.Message{acllm.UserText("hi")}); err == nil {
		t.Fatal("expected error to surface")
	}
	if len(m.reqs) != maxStreamingRetries {
		t.Fatalf("want %d stream attempts, got %d", maxStreamingRetries, len(m.reqs))
	}
}
