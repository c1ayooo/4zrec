package llmpool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/acllm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// fakeModel is a scripted chat model: script[i] is what the i-th call does —
// fail establishment, emit chunks and then (optionally) fail mid-stream.
type fakeModel struct {
	name  string
	mu    sync.Mutex
	calls int
	// streams scripts per Stream call; gens per Generate call. The last entry
	// repeats once the script runs out, so a model defined as "always succeeds" /
	// "always 402" keeps behaving that way across repeated calls.
	streams []streamScript
	gens    []genScript
	// lastBound records the tool set of the most recent call through this model
	// or any WithTools view of it (nil = called unbound).
	lastBound []*schema.ToolInfo
	// withToolsErr, when set, is returned by every WithTools call.
	withToolsErr error

	// base links a WithTools-derived view back to the model it came from, so
	// script indexes and call counts are shared with the original.
	base *fakeModel
	// myTools is the tool set this view was bound with (views only).
	myTools []*schema.ToolInfo
}

// streamScript is one Stream call's behavior.
type streamScript struct {
	establishErr error             // Stream() itself fails (nothing handed out)
	chunks       []*schema.Message // chunks emitted in order
	streamErr    error             // error after the chunks (mid-stream / first-Recv)
}

// genScript is one Generate call's behavior.
type genScript struct {
	msg *schema.Message
	err error
}

// root resolves the shared accounting owner (base model) of a view chain.
func (f *fakeModel) root() *fakeModel {
	if f.base != nil {
		return f.base
	}
	return f
}

// beginCall records a call (and the tool set it ran with) on the shared script
// owner and returns the script entry index to execute.
func (f *fakeModel) beginCall(tools []*schema.ToolInfo) int {
	r := f.root()
	r.mu.Lock()
	n := r.calls
	r.calls++
	r.lastBound = tools
	r.mu.Unlock()
	return n
}

func (f *fakeModel) Generate(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	n := f.beginCall(f.myTools)
	g, ok := at(f.gens, n)
	if !ok {
		return nil, fmt.Errorf("fakeModel %q: no generate script", f.name)
	}
	return g.msg, g.err
}

func (f *fakeModel) Stream(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	n := f.beginCall(f.myTools)
	s, ok := at(f.streams, n)
	if !ok {
		return nil, fmt.Errorf("fakeModel %q: no stream script", f.name)
	}
	if s.establishErr != nil {
		return nil, s.establishErr
	}
	sr, sw := schema.Pipe[*schema.Message](len(s.chunks) + 1)
	go func() {
		defer sw.Close()
		for _, c := range s.chunks {
			sw.Send(c, nil)
		}
		if s.streamErr != nil {
			sw.Send(nil, s.streamErr)
		}
	}()
	return sr, nil
}

// WithTools implements model.ToolCallingChatModel: it returns a view sharing the
// receiver's script, remembering the bound tools. The receiver itself is not
// mutated — the pool's lazy binding is observable through lastBound only once a
// bound view actually runs.
func (f *fakeModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	r := f.root()
	r.mu.Lock()
	werr := r.withToolsErr
	r.mu.Unlock()
	if werr != nil {
		return nil, werr
	}
	return &fakeModel{name: r.name, streams: r.streams, gens: r.gens, base: r, myTools: tools}, nil
}

// boundTools reports the tool set of the most recent call through this model or
// any view of it (nil = unbound).
func (f *fakeModel) boundTools() []*schema.ToolInfo {
	r := f.root()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastBound
}

// callCount counts every call made through this model and its WithTools views.
func (f *fakeModel) callCount() int {
	r := f.root()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// at returns script entry n, repeating the last one once the script runs out.
func at[T any](s []T, n int) (T, bool) {
	var zero T
	if len(s) == 0 {
		return zero, false
	}
	if n >= len(s) {
		n = len(s) - 1
	}
	return s[n], true
}

// ok builds a model that always succeeds with one text chunk.
func okModel(name, text string) *fakeModel {
	return &fakeModel{name: name, streams: []streamScript{{chunks: textChunks(text)}}, gens: []genScript{{msg: textMsg(text)}}}
}

// failModel builds a model that fails establishment (before any chunk) with the
// given HTTP status, on every call.
func failModel(name string, status int) *fakeModel {
	return &fakeModel{name: name, streams: []streamScript{
		{establishErr: fmt.Errorf("openai, status code: %d, message: nope", status)},
	}, gens: []genScript{{err: fmt.Errorf("openai, status code: %d, message: nope", status)}}}
}

// dropFirstRecvModel fails the FIRST Recv after a 200-style establishment —
// the gateway accepted the request then dropped before any output.
func dropFirstRecvModel(name string, status int) *fakeModel {
	return &fakeModel{name: name, streams: []streamScript{
		{streamErr: fmt.Errorf("openai, status code: %d, message: stream dropped", status)},
	}}
}

func textChunks(texts ...string) []*schema.Message {
	out := make([]*schema.Message, 0, len(texts))
	for _, t := range texts {
		out = append(out, textMsg(t))
	}
	return out
}

func textMsg(t string) *schema.Message {
	return &schema.Message{Role: schema.Assistant, Content: t}
}

// usageMsg is a usage-only chunk: it does NOT commit output.
func usageMsg() *schema.Message {
	return &schema.Message{Role: schema.Assistant, ResponseMeta: &schema.ResponseMeta{
		Usage: &schema.TokenUsage{CompletionTokens: 3},
	}}
}

// toolMsg is a tool-call chunk: it commits output.
func toolMsg(name string) *schema.Message {
	return &schema.Message{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
		{ID: "t1", Type: "function", Function: schema.FunctionCall{Name: name, Arguments: "{}"}},
	}}
}

func member(id int64, name string, rank int, m model.ToolCallingChatModel) *Member {
	return &Member{ID: id, Name: name, Model: "m" + name, Rank: rank, Prov: m}
}

// drain consumes a stream, returning the concatenated text and terminal error.
func drain(sr *schema.StreamReader[*schema.Message]) (string, error) {
	if sr == nil {
		return "", nil
	}
	defer sr.Close()
	var sb strings.Builder
	for {
		chunk, err := sr.Recv()
		if errors.Is(err, io.EOF) {
			return sb.String(), nil
		}
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(chunk.Content)
	}
}

func TestFailoverOnNoCredit(t *testing.T) {
	a, b := failModel("a", 402), okModel("b", "hello")
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, NewRegistry(nil, nil))

	got, err := drain(streamOrFail(t, p, context.Background()))
	if err != nil {
		t.Fatalf("expected failover to succeed, got %v", err)
	}
	if got != "hello" {
		t.Fatalf("text = %q, want %q", got, "hello")
	}
	if a.callCount() != 1 || b.callCount() != 1 {
		t.Fatalf("calls: a=%d b=%d, want 1/1", a.callCount(), b.callCount())
	}
}

// A 402 is deterministic: one failure must open the breaker, so the NEXT request
// skips that profile entirely instead of paying for another round-trip.
func TestHardFailureTripsBreakerImmediately(t *testing.T) {
	a, b := failModel("a", 402), okModel("b", "x")
	reg := NewRegistry(nil, nil)
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, reg)

	_, _ = drain(streamOrFail(t, p, context.Background()))
	if !reg.IsOpen(1) {
		t.Fatal("402 should have tripped the breaker on the first failure")
	}
	_, _ = drain(streamOrFail(t, p, context.Background()))
	if a.callCount() != 1 {
		t.Fatalf("tripped profile was called again: calls=%d, want 1", a.callCount())
	}
	if b.callCount() != 2 {
		t.Fatalf("fallback calls=%d, want 2", b.callCount())
	}
}

// MANDATORY safe-window case 1: the member fails while still establishing — here
// after a 200-style acceptance but before any output chunk — so the pool must
// abandon it and serve the caller from the next member.
func TestFailoverBeforeFirstChunk(t *testing.T) {
	a := dropFirstRecvModel("a", 500)
	b := okModel("b", "hello")
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, NewRegistry(nil, nil))

	got, err := drain(streamOrFail(t, p, context.Background()))
	if err != nil {
		t.Fatalf("pre-first-chunk failure must fail over, got %v", err)
	}
	if got != "hello" {
		t.Fatalf("text=%q, want the fallback member's output", got)
	}
	if b.callCount() != 1 {
		t.Fatalf("fallback calls=%d, want 1", b.callCount())
	}
}

// MANDATORY safe-window case 2: the member fails AFTER its first chunk reached
// the caller — the partial output must be surfaced as-is and the backup must
// never be called (failing over would duplicate the assistant turn).
func TestNoFailoverAfterFirstChunk(t *testing.T) {
	a := &fakeModel{name: "a", streams: []streamScript{{
		chunks:    textChunks("partial"),
		streamErr: errors.New("openai, status code: 500, message: mid-stream drop"),
	}}}
	b := okModel("b", "full")
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, NewRegistry(nil, nil))

	got, err := drain(streamOrFail(t, p, context.Background()))
	if err == nil {
		t.Fatal("mid-stream error should surface, not be swallowed by a failover")
	}
	if got != "partial" {
		t.Fatalf("text = %q, want the partial output %q", got, "partial")
	}
	if b.callCount() != 0 {
		t.Fatalf("fell over to the backup after emitting output (calls=%d) — would duplicate the turn", b.callCount())
	}
}

// Empty keep-alive / usage-only chunks do not commit: a failure after them is
// still inside the safe window, and the buffered non-committing chunks from the
// abandoned member must not leak into the fallback's output.
func TestUsageOnlyChunksDoNotCommit(t *testing.T) {
	a := &fakeModel{name: "a", streams: []streamScript{{
		chunks:    []*schema.Message{usageMsg(), {}},
		streamErr: errors.New("openai, status code: 502, message: dropped"),
	}}}
	b := okModel("b", "clean")
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, NewRegistry(nil, nil))

	got, err := drain(streamOrFail(t, p, context.Background()))
	if err != nil {
		t.Fatalf("usage-only chunks must not commit: %v", err)
	}
	if got != "clean" {
		t.Fatalf("text=%q, want only the fallback output (no leaked frames)", got)
	}
}

// A clean end before any committing chunk is an empty-but-successful reply: the
// buffered usage chunks are flushed and the breaker records a pass.
func TestCleanEmptyStreamFlushesUsageAndPasses(t *testing.T) {
	a := &fakeModel{name: "a", streams: []streamScript{{chunks: []*schema.Message{usageMsg()}}}}
	reg := NewRegistry(nil, nil)
	p := New([]*Member{member(1, "a", 10, a)}, reg)

	sr, err := p.Stream(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer sr.Close()
	var last *schema.Message
	for {
		chunk, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("unexpected mid-stream error: %v", rerr)
		}
		last = chunk
	}
	if last == nil || last.ResponseMeta == nil || last.ResponseMeta.Usage == nil {
		t.Fatal("usage-only chunk was not flushed at clean end")
	}
	if reg.Get(1).Fails != 0 {
		t.Fatal("a clean (if empty) completion must record a pass, not a failure")
	}
}

// Cancelling a task must not burn a backup key, and must not be diagnosed as an
// LLM fault.
func TestNoFailoverOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &fakeModel{name: "a", streams: []streamScript{{establishErr: context.Canceled}}}
	b := okModel("b", "x")
	reg := NewRegistry(nil, nil)
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, reg)

	_, err := p.Stream(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if b.callCount() != 0 {
		t.Fatalf("failed over on cancellation (backup calls=%d)", b.callCount())
	}
	if reg.Get(1).Fails != 0 {
		t.Fatal("cancellation counted as a profile failure")
	}
}

// A mid-stream cancellation (after the first chunk) surfaces as-is too.
func TestNoFailoverOnMidStreamCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a := &fakeModel{name: "a", streams: []streamScript{{
		chunks:    textChunks("partial"),
		streamErr: context.Canceled,
	}}}
	b := okModel("b", "x")
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, NewRegistry(nil, nil))

	sr, err := p.Stream(ctx, nil)
	if err != nil {
		t.Fatalf("establishment failed: %v", err)
	}
	defer sr.Close()
	cancel()
	var got string
	for {
		chunk, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			if !errors.Is(rerr, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", rerr)
			}
			break
		}
		got += chunk.Content
	}
	if got != "partial" {
		t.Fatalf("text=%q, want the partial output", got)
	}
	if b.callCount() != 0 {
		t.Fatalf("failed over on mid-stream cancellation (backup calls=%d)", b.callCount())
	}
}

// A 400 fails identically everywhere: surface it, don't fail over, don't trip.
func TestNoFailoverOn400(t *testing.T) {
	a := failModel("a", 400)
	b := okModel("b", "x")
	reg := NewRegistry(nil, nil)
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, reg)

	_, err := p.Stream(context.Background(), nil)
	if err == nil || StatusOf(err) != 400 {
		t.Fatalf("err=%v, want the original 400", err)
	}
	if b.callCount() != 0 {
		t.Fatalf("failed over on a 400 (backup calls=%d)", b.callCount())
	}
	if reg.Get(1).Fails != 0 {
		t.Fatal("a 400 must not count as a profile failure")
	}
}

func TestShouldFailoverByStatus(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{400, false}, // bad/over-long request fails identically everywhere
		{401, true}, {402, true}, {403, true}, {404, true},
		{408, true}, {429, true}, {500, true}, {503, true},
		{200, false},
	}
	for _, c := range cases {
		err := fmt.Errorf("openai, status code: %d, message: body", c.status)
		if got := shouldFailover(context.Background(), err); got != c.want {
			t.Errorf("status %d: shouldFailover=%v, want %v", c.status, got, c.want)
		}
		// The acllm typed shape and the old "status NNN" prose must classify alike.
		typed := fmt.Errorf("wrap: %w", &acllm.StatusError{StatusCode: c.status, Body: "body"})
		if got := shouldFailover(context.Background(), typed); got != c.want {
			t.Errorf("typed status %d: shouldFailover=%v, want %v", c.status, got, c.want)
		}
		legacy := fmt.Errorf("anthropic: status %d: body", c.status)
		if got := shouldFailover(context.Background(), legacy); got != c.want {
			t.Errorf("legacy status %d: shouldFailover=%v, want %v", c.status, got, c.want)
		}
	}
	// A transport error carries no status and must fail over.
	if !shouldFailover(context.Background(), errors.New("dial tcp: connection reset by peer")) {
		t.Error("network error should fail over")
	}
}

func TestHardVsSoftClassification(t *testing.T) {
	for _, s := range []int{401, 402, 403, 404} {
		if !isHardFailure(fmt.Errorf("error, status code: %d, message: x", s)) {
			t.Errorf("status %d should be a hard failure", s)
		}
	}
	for _, s := range []int{408, 429, 500, 502, 503} {
		if isHardFailure(fmt.Errorf("error, status code: %d, message: x", s)) {
			t.Errorf("status %d should be transient, not hard", s)
		}
	}
}

// 429 is transient: the SDK already retried, but we shouldn't write a profile off
// until it fails repeatedly.
func TestSoftFailureNeedsRepeats(t *testing.T) {
	reg := NewRegistry(nil, nil)
	for i := 1; i < softTripAfter; i++ {
		if reg.Trip(1, "429", false) {
			t.Fatalf("tripped after %d transient failures, want %d", i, softTripAfter)
		}
	}
	if !reg.Trip(1, "429", false) {
		t.Fatalf("should trip on failure #%d", softTripAfter)
	}
	if !reg.IsOpen(1) {
		t.Fatal("breaker should be open")
	}
}

// A success must fully clear the counters, so an intermittent profile never
// accumulates its way to a trip.
func TestPassResetsCounters(t *testing.T) {
	reg := NewRegistry(nil, nil)
	reg.Trip(1, "429", false)
	reg.Trip(1, "429", false)
	reg.Pass(1)
	if got := reg.Get(1).Fails; got != 0 {
		t.Fatalf("fails=%d after Pass, want 0", got)
	}
	if reg.Trip(1, "429", false) {
		t.Fatal("tripped immediately after a success — counters were not reset")
	}
}

func TestBackoffLadderGrows(t *testing.T) {
	reg := NewRegistry(nil, nil)
	var prev time.Duration
	for i := range 4 {
		reg.Reset(1)
		st := State{Trips: i}
		reg.Restore(1, st)
		reg.Trip(1, "402", true)
		d := time.Until(reg.Get(1).OpenUntil)
		// Non-decreasing, with a second of slack: the ladder plateaus at its last
		// rung, and each Trip stamps its own time.Now().
		if i > 0 && d < prev-time.Second {
			t.Fatalf("trip #%d cools for %v, shorter than the previous %v", i+1, d, prev)
		}
		prev = d
	}
	if prev < 25*time.Minute {
		t.Fatalf("ladder tops out at %v, want ~30m", prev)
	}
}

// A member whose context window can't hold the request is a guaranteed 400 —
// skip it rather than spend a round-trip proving it.
func TestSkipsMembersTooSmallForRequest(t *testing.T) {
	small, big := okModel("small", "s"), okModel("big", "b")
	ms := member(1, "small", 10, small)
	ms.WindowTokens = 1000
	mb := member(2, "big", 5, big)
	mb.WindowTokens = 1_000_000
	p := New([]*Member{ms, mb}, NewRegistry(nil, nil))

	req := []*schema.Message{schema.UserMessage(strings.Repeat("x", 100_000))}
	got, err := drain(streamOrFail(t, p, context.Background(), req...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "b" {
		t.Fatalf("text=%q, want the large-window member to serve it", got)
	}
	if small.callCount() != 0 {
		t.Fatalf("sent a request to a member that can't hold it (calls=%d)", small.callCount())
	}
}

// CJK text runs ~1.5 tokens per character — far denser than ASCII's ~3.5
// bytes per token. A Chinese-heavy request that a plain byte count calls
// small enough must still be recognized as too big for the small member:
// routing it there means a guaranteed length-400, which never fails over.
func TestSkipsMembersTooSmallForCJKRequest(t *testing.T) {
	small, big := okModel("small", "s"), okModel("big", "b")
	ms := member(1, "small", 10, small)
	ms.WindowTokens = 8000
	mb := member(2, "big", 5, big)
	mb.WindowTokens = 1_000_000
	p := New([]*Member{ms, mb}, NewRegistry(nil, nil))

	// 6000 Chinese characters ≈ 9000 real tokens (over the 8000 window), but
	// only ≈5140 under a bytes/3.5 estimate.
	req := []*schema.Message{schema.UserMessage(strings.Repeat("资", 6000))}
	got, err := drain(streamOrFail(t, p, context.Background(), req...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "b" {
		t.Fatalf("text=%q, want the large-window member to serve it", got)
	}
	if small.callCount() != 0 {
		t.Fatalf("sent a CJK request to a member that cannot hold it (calls=%d)", small.callCount())
	}
}

// Everything tripped: probing the head beats stalling the engine outright.
func TestAllTrippedStillProbesHead(t *testing.T) {
	a, b := okModel("a", "a"), okModel("b", "b")
	reg := NewRegistry(nil, nil)
	reg.Trip(1, "402", true)
	reg.Trip(2, "402", true)
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, reg)

	got, err := drain(streamOrFail(t, p, context.Background()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "a" || a.callCount() != 1 {
		t.Fatalf("text=%q a.calls=%d — want the head probed as a last resort", got, a.callCount())
	}
}

func TestExhaustedChainReportsClearly(t *testing.T) {
	a, b := failModel("a", 402), failModel("b", 402)
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, NewRegistry(nil, nil))

	_, err := p.Stream(context.Background(), nil)
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("err = %v, want it to wrap ErrExhausted", err)
	}
}

// Equal-rank members take turns leading, so duplicate keys share the load.
func TestEqualRankRotates(t *testing.T) {
	a, b := okModel("a", "a"), okModel("b", "b")
	head := member(1, "head", RankActive, failModel("head", 402))
	p := New([]*Member{head, member(2, "a", 5, a), member(3, "b", 5, b)}, NewRegistry(nil, nil))

	first := map[string]int{}
	for range 4 {
		txt, _ := drain(streamOrFail(t, p, context.Background()))
		first[txt]++
	}
	if first["a"] == 0 || first["b"] == 0 {
		t.Fatalf("same-rank members did not rotate: %v", first)
	}
}

// The head keeps its own rank and never joins a rotation group.
func TestHeadAlwaysFirst(t *testing.T) {
	head := okModel("head", "H")
	p := New([]*Member{
		member(1, "head", RankActive, head),
		member(2, "a", 5, okModel("a", "a")),
		member(3, "b", 5, okModel("b", "b")),
	}, NewRegistry(nil, nil))
	for range 5 {
		if txt, _ := drain(streamOrFail(t, p, context.Background())); txt != "H" {
			t.Fatalf("head was not tried first, got %q", txt)
		}
	}
}

// A single-member chain must behave exactly like the bare model.
func TestSingleMemberPassthrough(t *testing.T) {
	a := okModel("a", "solo")
	p := New([]*Member{member(1, "a", RankActive, a)}, NewRegistry(nil, nil))
	got, err := drain(streamOrFail(t, p, context.Background()))
	if err != nil || got != "solo" {
		t.Fatalf("got %q / %v, want solo / nil", got, err)
	}
}

func TestNewEmptyChainIsNil(t *testing.T) {
	if New(nil, nil) != nil {
		t.Fatal("empty chain should yield a nil pool so callers use the bare model")
	}
}

// An expired cooling-off window must not keep a profile out of the chain.
func TestExpiredWindowIsClosed(t *testing.T) {
	reg := NewRegistry(nil, nil)
	reg.Restore(1, State{Trips: 1, OpenUntil: time.Now().Add(-time.Second)})
	if reg.IsOpen(1) {
		t.Fatal("expired window should read as closed")
	}
}

// Generate fails over with the same policy as Stream: 402 → next member, and a
// completed Generate clears the breaker.
func TestGenerateFailsOverAndPasses(t *testing.T) {
	a, b := failModel("a", 402), okModel("b", "hi")
	reg := NewRegistry(nil, nil)
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, reg)

	msg, err := p.Generate(context.Background(), nil)
	if err != nil || msg.Content != "hi" {
		t.Fatalf("msg=%v err=%v, want hi / nil", msg, err)
	}
	if a.callCount() != 1 || b.callCount() != 1 {
		t.Fatalf("calls a=%d b=%d, want 1/1", a.callCount(), b.callCount())
	}
	if reg.Get(2).Fails != 0 {
		t.Fatal("successful fallback did not record a pass")
	}

	// Generate never fails over on cancel either.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a2 := &fakeModel{name: "a2", gens: []genScript{{err: context.Canceled}}}
	p2 := New([]*Member{member(3, "a2", 10, a2), member(4, "b2", 5, okModel("b2", "x"))}, NewRegistry(nil, nil))
	if _, err := p2.Generate(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate err=%v, want context.Canceled", err)
	}
}

// WithTools must return a view that binds the tools to every member lazily —
// without mutating the original pool or its member models.
func TestWithToolsBindsMembersLazily(t *testing.T) {
	a, b := okModel("a", "a"), okModel("b", "b")
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, NewRegistry(nil, nil))
	tools := []*schema.ToolInfo{{Name: "search", Desc: "web search"}}
	bound, err := p.WithTools(tools)
	if err != nil {
		t.Fatal(err)
	}
	if bound == model.ToolCallingChatModel(p) {
		t.Fatal("WithTools must not return the same pool")
	}
	if a.boundTools() != nil || a.callCount() != 0 {
		t.Fatalf("WithTools bound or called the member eagerly: tools=%v calls=%d — must bind lazily",
			a.boundTools(), a.callCount())
	}
	sr, err := bound.Stream(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drain(sr); err != nil {
		t.Fatal(err)
	}
	if got := a.boundTools(); len(got) != 1 || got[0].Name != "search" {
		t.Fatalf("bound member tools = %v, want the search tool", got)
	}
	if b.callCount() != 0 {
		t.Fatal("fallback member was called although the head committed")
	}
	// The original pool stays unbound.
	sr2, err := p.Stream(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drain(sr2); err != nil {
		t.Fatal(err)
	}
	if a.boundTools() != nil {
		t.Fatalf("original pool members got tool-bound: %v", a.boundTools())
	}
}

// streamOrFail calls p.Stream and treats a returned error as a test failure —
// helpers for the many tests that exercise the success path.
func streamOrFail(t *testing.T, p *Pool, ctx context.Context, input ...*schema.Message) *schema.StreamReader[*schema.Message] {
	t.Helper()
	sr, err := p.Stream(ctx, input)
	if err != nil {
		t.Fatalf("Stream failed: %v", err)
	}
	return sr
}

// The commits-output predicate: visible output commits; bookkeeping frames don't.
func TestMessageCommitsOutput(t *testing.T) {
	committing := []*schema.Message{
		textMsg("hi"),
		{Role: schema.Assistant, ReasoningContent: "thinking..."},
		toolMsg("read_file"),
		{Role: schema.Assistant, MultiContent: []schema.ChatMessagePart{{Type: schema.ChatMessagePartTypeText, Text: "img alt"}}},
	}
	for _, chunk := range committing {
		if !MessageCommitsOutput(chunk) {
			t.Errorf("chunk %+v must commit output", chunk)
		}
	}
	nonCommitting := []*schema.Message{
		nil,
		{}, // empty keep-alive
		usageMsg(),
	}
	for _, chunk := range nonCommitting {
		if MessageCommitsOutput(chunk) {
			t.Errorf("chunk %+v must NOT commit output", chunk)
		}
	}
}
