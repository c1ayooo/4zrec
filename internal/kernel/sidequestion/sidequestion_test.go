package sidequestion

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/platform/llm/acllm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// fakeModel is a configurable model.ToolCallingChatModel.
type fakeModel struct {
	generate func(context.Context, []*schema.Message, []model.Option) (*schema.Message, error)
	stream   func(context.Context, []*schema.Message, []model.Option) (*schema.StreamReader[*schema.Message], error)
}

func (p fakeModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	return p.generate(ctx, input, opts)
}
func (p fakeModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return p.stream(ctx, input, opts)
}
func (p fakeModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) { return p, nil }

// failoverModel stands in for the routing pool: members are tried in order,
// failing over only while nothing has been streamed (llmpool's safe window).
type failoverModel struct{ members []model.ToolCallingChatModel }

func (f failoverModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	var lastErr error
	for _, m := range f.members {
		msg, err := m.Generate(ctx, input, opts...)
		if err == nil {
			return msg, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (f failoverModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	var lastErr error
	for _, m := range f.members {
		sr, err := m.Stream(ctx, input, opts...)
		if err == nil {
			return sr, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (f failoverModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	derived := make([]model.ToolCallingChatModel, 0, len(f.members))
	for _, m := range f.members {
		d, err := m.WithTools(tools)
		if err != nil {
			return nil, err
		}
		derived = append(derived, d)
	}
	return failoverModel{members: derived}, nil
}

func assistantSchema(text string) *schema.Message {
	return schema.AssistantMessage(text, nil)
}

func toolCallSchema(id, name, args string) *schema.Message {
	return schema.AssistantMessage("", []schema.ToolCall{{ID: id, Function: schema.FunctionCall{Name: name, Arguments: args}}})
}

func usageOfTokens(prompt int) *schema.ResponseMeta {
	return &schema.ResponseMeta{Usage: &schema.TokenUsage{PromptTokens: prompt}}
}

func fixture() ModelCall {
	temp := 0.3
	return ModelCall{System: []string{"system"}, Temperature: &temp, MaxTokens: 128, Stop: []string{"END"}, Messages: []acllm.Message{
		acllm.UserText("<system-reminder>date</system-reminder>"), acllm.UserText("read asset"),
		{Role: acllm.RoleAssistant, Content: []acllm.ContentBlock{{Type: acllm.BlockThinking, Thinking: "reason", Signature: "signed"}, {Type: acllm.BlockToolUse, ID: "tool-1", Name: "read", Input: json.RawMessage(`{"url":"fixture"}`)}}},
		{Role: acllm.RoleUser, Content: []acllm.ContentBlock{acllm.ToolResultText("tool-1", "verified asset", false)}},
	}, Tools: []acllm.ToolSchema{{Name: "read", InputSchema: map[string]any{"properties": map[string]any{"url": map[string]any{"type": "string"}}}}}}
}

// snapshotSink collects published snapshots safely across the goroutines that
// now complete stream checkpoints.
type snapshotSink struct {
	mu    sync.Mutex
	items []Snapshot
}

func (s *snapshotSink) publish(snap Snapshot) {
	s.mu.Lock()
	s.items = append(s.items, snap)
	s.mu.Unlock()
}

func (s *snapshotSink) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

func (s *snapshotSink) last() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[len(s.items)-1]
}

func (s *snapshotSink) waitFor(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for s.len() < n {
		if time.Now().After(deadline) {
			t.Fatalf("snapshots never reached %d (have %d)", n, s.len())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCheckpointDeepCopyAndBoundaries(t *testing.T) {
	var sink snapshotSink
	p := Bind(fakeModel{generate: func(context.Context, []*schema.Message, []model.Option) (*schema.Message, error) {
		return assistantSchema("finished"), nil
	}}, Model{Model: "actual"})
	ctx, decorated, _ := Attach(WithPublisher(t.Context(), sink.publish), Parent{ConversationID: 1}, p)
	req := fixture()
	input := callInput(req)
	if _, err := decorated.Generate(ctx, input); err != nil {
		t.Fatal(err)
	}
	sink.waitFor(t, 2)
	if got := sink.last().Request.Messages; got[len(got)-1].Text() != "finished" {
		t.Fatalf("checkpoints: %+v", sink.last())
	}
	before := sink.len()
	snapshotJSON := func() string {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		b, _ := json.Marshal(sink.items)
		return string(b)
	}
	frozen := snapshotJSON()
	req.System[0] = "mutated"
	*req.Temperature = 2
	req.Stop[0] = "bad"
	req.Messages[2].Content[1].Input[2] = 'X'
	req.Messages[3].Content[0].Content[0].Text = "mutated"
	req.Tools[0].InputSchema["properties"].(map[string]any)["url"].(map[string]any)["type"] = "number"
	if snapshotJSON() != frozen {
		t.Fatal("published checkpoint aliases structured input")
	}
	// Auxiliary/compaction calls lack the model-attempt marker.
	_, _ = p.Generate(ctx, []*schema.Message{schema.UserMessage("summary request")})
	if sink.len() != before {
		t.Fatal("auxiliary completion replaced snapshot")
	}
	terminal := fixture().Messages[1:]
	terminal = append(terminal, acllm.Message{Role: acllm.RoleAssistant, Content: []acllm.ContentBlock{acllm.TextBlock("terminal answer")}})
	Finish(ctx, terminal)
	last := sink.last()
	if last.Request.Messages[0].Text() != "<system-reminder>date</system-reminder>" || len(last.Request.Messages) != 5 {
		t.Fatalf("terminal/reminder duplication: %+v", last.Request.Messages)
	}
	if !strings.Contains(string(mustJSON(t, last)), "verified asset") {
		t.Fatal("terminal lost paired tool result")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestSnapshotExcludesPartialStreamAndSelectsPoolMember(t *testing.T) {
	var sink snapshotSink
	failed := Bind(fakeModel{stream: func(context.Context, []*schema.Message, []model.Option) (*schema.StreamReader[*schema.Message], error) {
		return nil, errors.New("HTTP 503 unavailable")
	}}, Model{Model: "failed"})
	good := Bind(fakeModel{stream: func(context.Context, []*schema.Message, []model.Option) (*schema.StreamReader[*schema.Message], error) {
		return schema.StreamReaderFromArray([]*schema.Message{assistantSchema("complete")}), nil
	}}, Model{Model: "selected"})
	pool := failoverModel{members: []model.ToolCallingChatModel{failed, good}}
	ctx, decorated, _ := Attach(WithPublisher(t.Context(), sink.publish), Parent{ConversationID: 2}, pool)
	sr, err := decorated.Stream(ctx, callInput(fixture()))
	if err != nil {
		t.Fatal(err)
	}
	chunks := 0
	for {
		_, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatal(rerr)
		}
		chunks++
		if chunks == 1 {
			// Both members publish their request-start checkpoint synchronously
			// before the stream reader is handed out. The unbuffered pipe keeps
			// the pump in lockstep with the consumer, so the completed-reply
			// checkpoint cannot exist yet.
			if n := sink.len(); n != 2 || sink.last().Model.Model != "selected" {
				t.Fatalf("start checkpoints wrong: n=%d model=%q", n, sink.last().Model.Model)
			}
		}
	}
	sr.Close()
	sink.waitFor(t, 3)
	if last := sink.last(); last.Model.Model != "selected" || last.Request.Messages[len(last.Request.Messages)-1].Text() != "complete" {
		t.Fatalf("wrong selected model/checkpoint: %+v", last)
	}
	count := sink.len()
	sr, err = decorated.Stream(ctx, callInput(fixture()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sr.Recv(); err != nil {
		t.Fatal(err)
	}
	sr.Close() // consumer stop: partial reply must not be published
	sink.waitFor(t, count+2)
	if n := sink.len(); n != count+2 || len(sink.last().Request.Messages) != len(fixture().Messages) {
		t.Fatalf("consumer stop published partial reply: %d snapshots", n)
	}
}

func TestBuildRequestCompactionToolPairingAndBudget(t *testing.T) {
	s := Snapshot{Request: fixture(), Model: Model{WindowTokens: 100000}}
	s.Request.Messages = append(s.Request.Messages, acllm.BoundaryMessage(acllm.BoundaryMeta{Trigger: "auto"}), acllm.UserText("compressed summary"), s.Request.Messages[3])
	history := []Exchange{}
	for i := 0; i < 25; i++ {
		history = append(history, Exchange{Question: strings.Repeat("q", 100), Answer: "answer", Status: "completed"})
	}
	r, err := BuildRequest(s, history, "current question")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Messages) != 42 || r.Messages[0].Text() != "compressed summary" {
		t.Fatalf("history cap/compaction: %d %+v", len(r.Messages), r.Messages[0])
	}
	for _, m := range r.Messages {
		for _, b := range m.Content {
			if b.Type == acllm.BlockToolResult {
				t.Fatal("orphan tool result survived")
			}
		}
	}
	s.Model.WindowTokens = 1000
	r, err = BuildRequest(s, history, "current question")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Messages) >= 42 || len(r.Messages) < 2 {
		t.Fatal("budget did not reduce side history")
	}
	s.Model.WindowTokens = 10
	if _, err = BuildRequest(s, nil, "question"); err == nil {
		t.Fatal("oversized base accepted")
	}
}

func TestServiceNoToolsAndUsageOnFailure(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{true: "stream", false: "atomic"}[streaming], func(t *testing.T) {
			var mu sync.Mutex
			calls := 0
			count := func() { mu.Lock(); calls++; mu.Unlock() }
			p := fakeModel{
				generate: func(context.Context, []*schema.Message, []model.Option) (*schema.Message, error) {
					count()
					msg := toolCallSchema("new", "run_shell", `{"command":"touch forbidden"}`)
					msg.ResponseMeta = usageOfTokens(11)
					return msg, nil
				},
				stream: func(context.Context, []*schema.Message, []model.Option) (*schema.StreamReader[*schema.Message], error) {
					count()
					start := assistantSchema("")
					start.ResponseMeta = usageOfTokens(11)
					tool := toolCallSchema("new", "run_shell", `{"command":"touch forbidden"}`)
					return schema.StreamReaderFromArray([]*schema.Message{start, tool}), nil
				},
			}
			before := fixture()
			req, _ := CloneRequest(before)
			out, err := (SideQuestionService{p}).Answer(t.Context(), req, streaming, nil)
			mu.Lock()
			n := calls
			mu.Unlock()
			if err != nil || n != 1 || !out.ToolUse || !strings.Contains(out.Text, "不能执行工具") || out.Usage.InputTokens != 11 {
				t.Fatalf("answer %+v calls=%d err=%v", out, n, err)
			}
			if !reflect.DeepEqual(before, req) {
				t.Fatal("service mutated main context")
			}
		})
	}
	p := fakeModel{stream: func(context.Context, []*schema.Message, []model.Option) (*schema.StreamReader[*schema.Message], error) {
		start := assistantSchema("partial")
		start.ResponseMeta = usageOfTokens(12)
		sr, sw := schema.Pipe[*schema.Message](4)
		go func() {
			defer sw.Close()
			sw.Send(start, nil)
			sw.Send(nil, errors.New("broken"))
		}()
		return sr, nil
	}}
	out, err := (SideQuestionService{p}).Answer(t.Context(), fixture(), true, nil)
	if err == nil || out.Text != "partial" || out.Usage.InputTokens != 12 {
		t.Fatalf("lost failure usage/partial: %+v %v", out, err)
	}
}

func TestMainSideConcurrencyAndIndependentCancellation(t *testing.T) {
	for _, cancelMain := range []bool{false, true} {
		t.Run(map[bool]string{true: "stop-main", false: "stop-side"}[cancelMain], func(t *testing.T) {
			started := make(chan struct{}, 2)
			p := fakeModel{stream: func(ctx context.Context, _ []*schema.Message, _ []model.Option) (*schema.StreamReader[*schema.Message], error) {
				sr, sw := schema.Pipe[*schema.Message](2)
				go func() {
					defer sw.Close()
					started <- struct{}{}
					start := assistantSchema("")
					start.ResponseMeta = usageOfTokens(7)
					sw.Send(start, nil)
					<-ctx.Done()
					sw.Send(nil, ctx.Err())
				}()
				return sr, nil
			}}
			mainCtx, stopMain := context.WithCancel(t.Context())
			defer stopMain()
			sideCtx, stopSide := context.WithCancel(t.Context())
			defer stopSide()
			var sink snapshotSink
			bound := Bind(p, Model{Model: "blocking"})
			mainCtx, decorated, _ := Attach(WithPublisher(mainCtx, sink.publish), Parent{ConversationID: 3}, bound)
			mainDone, sideDone := make(chan struct{}), make(chan Answer, 1)
			go func() {
				defer close(mainDone)
				sr, err := decorated.Stream(mainCtx, callInput(fixture()))
				if err != nil {
					return
				}
				for {
					if _, err := sr.Recv(); err != nil {
						break
					}
				}
				sr.Close()
			}()
			go func() { a, _ := (SideQuestionService{bound}).Answer(sideCtx, fixture(), true, nil); sideDone <- a }()
			for i := 0; i < 2; i++ {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("main and side did not execute concurrently")
				}
			}
			if cancelMain {
				stopMain()
				select {
				case <-mainDone:
				case <-time.After(time.Second):
					t.Fatal("main cancellation stuck")
				}
				select {
				case <-sideDone:
					t.Fatal("main cancellation stopped side")
				default:
				}
				stopSide()
			} else {
				stopSide()
				select {
				case a := <-sideDone:
					if a.Usage.InputTokens != 7 {
						t.Fatal("cancelled usage lost")
					}
				case <-time.After(time.Second):
					t.Fatal("side cancellation stuck")
				}
				select {
				case <-mainDone:
					t.Fatal("side cancellation stopped main")
				default:
				}
				stopMain()
			}
		})
	}
}
