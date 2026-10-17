package acllm

// Tests for the retry decorator: norma's two layers (transport/model failures
// with MaxRetries+RetryInterval; empty completions with
// EmptyResponseRetries+EmptyResponseInterval), the never-retry-cancellation
// rule, status classification, and WithTools passthrough.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// fakeModel is a programmable ToolCallingChatModel with a shared call counter
// (WithTools derives copies that keep counting the same state).
type fakeModel struct {
	st       *fakeState
	gen      func(call int) (*schema.Message, error)
	streamFn func(call int) (*schema.StreamReader[*schema.Message], error)
	tools    []*schema.ToolInfo
}

type fakeState struct {
	mu    sync.Mutex
	calls int
	tools []*schema.ToolInfo
}

// newFakeModel builds a fake with its counter state initialized. For custom
// streamFn cases construct the struct literal with st: &fakeState{}.
func newFakeModel(gen func(call int) (*schema.Message, error)) *fakeModel {
	return &fakeModel{st: &fakeState{}, gen: gen}
}

func (f *fakeModel) count() int { return f.st.calls }

func (f *fakeModel) lastTools() []*schema.ToolInfo {
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	return f.st.tools
}

func (f *fakeModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	f.st.mu.Lock()
	f.st.calls++
	call := f.st.calls
	f.st.mu.Unlock()
	return f.gen(call)
}

func (f *fakeModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	f.st.mu.Lock()
	f.st.calls++
	call := f.st.calls
	f.st.mu.Unlock()
	if f.streamFn != nil {
		return f.streamFn(call)
	}
	sr, sw := schema.Pipe[*schema.Message](1)
	go func() {
		defer sw.Close()
		sw.Send(schema.AssistantMessage("ok", nil), nil)
	}()
	return sr, nil
}

func (f *fakeModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	f.st.mu.Lock()
	f.st.tools = tools // record on the shared state so the original sees it
	f.st.mu.Unlock()
	c := *f
	c.st = f.st // shared counters
	c.tools = tools
	return &c, nil
}

func fastRetryConfig() Config {
	return Config{
		MaxRetries:            3,
		RetryInterval:         time.Millisecond,
		EmptyResponseRetries:  2,
		EmptyResponseInterval: time.Millisecond,
	}
}

func TestRetryTransportFailsTwiceThenSucceeds(t *testing.T) {
	fm := newFakeModel(func(call int) (*schema.Message, error) {
		if call <= 2 {
			return nil, errors.New("connection reset")
		}
		return schema.AssistantMessage("recovered", nil), nil
	})
	rm := newRetryModel(fm, fastRetryConfig())
	msg, err := rm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if msg.Content != "recovered" {
		t.Fatalf("content = %q", msg.Content)
	}
	if fm.count() != 3 {
		t.Errorf("calls = %d, want 3 (two failures + success)", fm.count())
	}
}

func TestRetryEmptyThenFull(t *testing.T) {
	fm := newFakeModel(func(call int) (*schema.Message, error) {
		if call <= 2 {
			return schema.AssistantMessage("", nil), nil // empty: no content/tool calls/reasoning
		}
		m := schema.AssistantMessage("finally", nil)
		m.ReasoningContent = "thought about it"
		return m, nil
	})
	rm := newRetryModel(fm, fastRetryConfig())
	msg, err := rm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if msg.Content != "finally" || msg.ReasoningContent == "" {
		t.Fatalf("message = %+v", msg)
	}
	if fm.count() != 3 {
		t.Errorf("calls = %d, want 3 (two empties + full)", fm.count())
	}
}

func TestRetryEmptyExhaustsReturnsEmpty(t *testing.T) {
	fm := newFakeModel(func(call int) (*schema.Message, error) {
		return schema.AssistantMessage("", nil), nil
	})
	rm := newRetryModel(fm, Config{EmptyResponseRetries: 1, EmptyResponseInterval: time.Millisecond})
	msg, err := rm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if msg == nil || !isEmptyAssistant(msg) {
		t.Fatalf("want the empty message back, got %+v", msg)
	}
	if fm.count() != 2 {
		t.Errorf("calls = %d, want 2 (initial + 1 empty retry)", fm.count())
	}
}

func TestRetryNeverRetriesCancellation(t *testing.T) {
	fm := newFakeModel(func(call int) (*schema.Message, error) {
		return nil, context.Canceled
	})
	rm := newRetryModel(fm, fastRetryConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rm.Generate(ctx, []*schema.Message{schema.UserMessage("hi")}); err == nil {
		t.Fatal("want error")
	}
	if fm.count() != 1 {
		t.Errorf("calls = %d, want 1 (cancellation never retried)", fm.count())
	}

	// Also: error wrapping context.Canceled is classified as cancellation.
	fm2 := newFakeModel(func(call int) (*schema.Message, error) {
		return nil, fmtWrapped(context.DeadlineExceeded)
	})
	rm2 := newRetryModel(fm2, fastRetryConfig())
	if _, err := rm2.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err == nil {
		t.Fatal("want error")
	}
	if fm2.count() != 1 {
		t.Errorf("calls = %d, want 1 (deadline never retried)", fm2.count())
	}
}

type wrappedErr struct{ err error }

func (w *wrappedErr) Error() string { return "wrapped: " + w.err.Error() }
func (w *wrappedErr) Unwrap() error { return w.err }

func fmtWrapped(err error) error { return &wrappedErr{err} }

func TestRetryStatusClassification(t *testing.T) {
	// 503 is transient → retried.
	fm := newFakeModel(func(call int) (*schema.Message, error) {
		if call == 1 {
			return nil, &StatusError{StatusCode: 503, Body: "overloaded"}
		}
		return schema.AssistantMessage("ok", nil), nil
	})
	rm := newRetryModel(fm, fastRetryConfig())
	if _, err := rm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if fm.count() != 2 {
		t.Errorf("503 calls = %d, want 2", fm.count())
	}

	// 401 is not → returned as-is.
	fm2 := newFakeModel(func(int) (*schema.Message, error) {
		return nil, &StatusError{StatusCode: 401, Body: "bad key"}
	})
	rm2 := newRetryModel(fm2, fastRetryConfig())
	_, err := rm2.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	var se *StatusError
	if !errors.As(err, &se) || se.StatusCode != 401 {
		t.Fatalf("want 401 StatusError, got %v", err)
	}
	if fm2.count() != 1 {
		t.Errorf("401 calls = %d, want 1", fm2.count())
	}
}

func TestRetryMaxRetriesZeroMeansDefault(t *testing.T) {
	// Default 3 retries: a persistently failing call is attempted 4 times.
	fm := newFakeModel(func(int) (*schema.Message, error) {
		return nil, errors.New("down")
	})
	rm := newRetryModel(fm, Config{RetryInterval: time.Millisecond})
	if _, err := rm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err == nil {
		t.Fatal("want error")
	}
	if fm.count() != 4 {
		t.Errorf("calls = %d, want 4 (1 + default 3 retries)", fm.count())
	}

	// Negative disables retrying entirely.
	fm2 := newFakeModel(func(int) (*schema.Message, error) { return nil, errors.New("down") })
	rm2 := newRetryModel(fm2, Config{MaxRetries: -1})
	if _, err := rm2.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err == nil {
		t.Fatal("want error")
	}
	if fm2.count() != 1 {
		t.Errorf("calls = %d, want 1 (retry disabled)", fm2.count())
	}
}

func TestRetryStreamEstablishmentOnly(t *testing.T) {
	calls := 0
	fm := &fakeModel{st: &fakeState{}, streamFn: func(call int) (*schema.StreamReader[*schema.Message], error) {
		calls = call
		if call <= 2 {
			return nil, errors.New("connect reset")
		}
		sr, sw := schema.Pipe[*schema.Message](1)
		go func() {
			defer sw.Close()
			sw.Send(schema.AssistantMessage("streamed", nil), nil)
		}()
		return sr, nil
	}}
	rm := newRetryModel(fm, fastRetryConfig())
	sr, err := rm.Stream(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	msg, err := sr.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	sr.Close()
	if msg.Content != "streamed" {
		t.Errorf("content = %q", msg.Content)
	}
	if calls != 3 {
		t.Errorf("stream attempts = %d, want 3", calls)
	}
}

func TestRetryWithToolsPassthrough(t *testing.T) {
	fm := newFakeModel(func(call int) (*schema.Message, error) {
		if call == 1 {
			return nil, errors.New("flaky")
		}
		return schema.AssistantMessage("ok", nil), nil
	})
	rm := newRetryModel(fm, fastRetryConfig())
	tool, err := ToolSchemaToInfo(ToolSchema{Name: "t", Description: "d"})
	if err != nil {
		t.Fatalf("ToolSchemaToInfo: %v", err)
	}
	derived, err := rm.WithTools([]*schema.ToolInfo{tool})
	if err != nil {
		t.Fatalf("WithTools: %v", err)
	}
	msg, err := derived.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if msg.Content != "ok" {
		t.Fatalf("content = %q", msg.Content)
	}
	if fm.count() != 2 {
		t.Errorf("calls = %d, want 2 — the derived model must keep retrying", fm.count())
	}
	last := fm.lastTools()
	if len(last) != 1 || last[0].Name != "t" {
		t.Errorf("tools not passed through: %v", last)
	}
}

// smoke: the decorator stack built by the factory still retries end-to-end.
func TestFactoryDecoratedModelRetries(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"overloaded"}`))
			return
		}
		sse(w, openAISSEBody)
	}))
	defer srv.Close()
	temp := 0.5
	cm, err := NewChatModel(context.Background(), Config{
		Format:        FormatOpenAI,
		BaseURL:       srv.URL + "/v1",
		APIKey:        "k",
		Model:         "gpt-test",
		Temperature:   &temp,
		MaxRetries:    3,
		RetryInterval: time.Millisecond,
		HTTPClient:    &http.Client{},
	})
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}
	full := collectStream(t, mustStream(t, cm))
	if full.Content != "Hi" {
		t.Fatalf("content = %q", full.Content)
	}
	if calls != 3 {
		t.Errorf("requests = %d, want 3", calls)
	}
}

func mustStream(t *testing.T, m model.ToolCallingChatModel) *schema.StreamReader[*schema.Message] {
	t.Helper()
	sr, err := m.Stream(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	return sr
}
