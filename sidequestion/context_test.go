package sidequestion

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/acllm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

func replayFixture(history []Exchange, memory *Memory) Replay {
	return Replay{Memory: *memory, Load: func(_ context.Context, after int64) ([]Exchange, error) {
		var page []Exchange
		for _, e := range history {
			if e.Ordinal > after && e.Status == "completed" {
				page = append(page, e)
			}
			if len(page) == 20 {
				break
			}
		}
		return page, nil
	}, Save: func(_ context.Context, value Memory) error { *memory = value; return nil }}
}

// isSummaryCall detects the summarizer's completion by its system prompt: the
// eino seam has no per-request thinking override (norma's Thinking="disabled"
// marker), so the summary instruction itself is the discriminator. Summary
// requests also carry no tools, so they are the first system segment only.
func isSummaryCall(input []*schema.Message) bool {
	return len(input) > 0 && input[0].Role == schema.System && strings.HasPrefix(input[0].Content, "你只生成供独立旁路问答使用的简短摘要")
}

// callFromInput reconstructs enough of the snapshot view for fake-side budget
// assertions: DTO messages plus the effective max_tokens option.
func callFromInput(input []*schema.Message, opts []model.Option) ModelCall {
	common := model.GetCommonOptions(&model.Options{}, opts...)
	call := ModelCall{Messages: acllm.FromSchema(input)}
	for _, m := range input {
		if m.Role == schema.System {
			call.System = append(call.System, m.Content)
		}
	}
	if common.MaxTokens != nil {
		call.MaxTokens = *common.MaxTokens
	}
	return call
}

func TestSideTwentyExchangeBoundaryAndRestart(t *testing.T) {
	for _, n := range []int{19, 20, 21, 50} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			var history []Exchange
			for i := 1; i <= n; i++ {
				history = append(history, Exchange{Ordinal: int64(i), Question: fmt.Sprintf("question-%d", i), Answer: "historical answer", Status: "completed", SnapshotAt: time.Unix(int64(i), 0)})
			}
			history[0].Answer = "EARLY-DECISION-ALPHA"
			var inputs [][]*schema.Message
			summaries := 0
			p := fakeModel{generate: func(_ context.Context, input []*schema.Message, _ []model.Option) (*schema.Message, error) {
				if isSummaryCall(input) {
					summaries++
					if !strings.Contains(input[1].Content, "EARLY-DECISION-ALPHA") {
						t.Fatal("rolling update lost prior summary")
					}
					msg := assistantSchema("EARLY-DECISION-ALPHA; historical discussion, not current evidence")
					msg.ResponseMeta = usageOfTokens(11)
					return msg, nil
				}
				inputs = append(inputs, input)
				msg := assistantSchema("answer")
				msg.ResponseMeta = usageOfTokens(7)
				return msg, nil
			}}
			snap := Snapshot{Request: fixture(), Model: Model{WindowTokens: 200000}}
			var memory Memory
			out, info, err := (SideQuestionService{p}).Respond(t.Context(), snap, "what was my first decision?", replayFixture(history, &memory), ContextOptions{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if info.RecentExchanges != min(n, 20) || memory.Through != int64(max(0, n-20)) {
				t.Fatalf("boundary: %+v %+v", info, memory)
			}
			if out.Usage.InputTokens != 11*summaries+7 {
				t.Fatal("summary usage missing")
			}
			if !strings.Contains(string(mustJSON(t, inputs[0])), "EARLY-DECISION-ALPHA") {
				t.Fatal("first-round decision absent after round 20")
			}
			before := summaries
			_, _, err = (SideQuestionService{p}).Respond(t.Context(), snap, "continue after restart", replayFixture(history, &memory), ContextOptions{}, nil)
			if err != nil || summaries != before {
				t.Fatalf("persisted summary not reused: %v", err)
			}
		})
	}
}

func TestSideBudgetCountsContentNotJSONCharacters(t *testing.T) {
	snap := Snapshot{Request: fixture(), Model: Model{WindowTokens: 200000}}
	snap.Request.MaxTokens = 32768
	snap.Request.Messages = append(snap.Request.Messages, acllm.UserText(strings.Repeat("<script>const result = api.response;</script>\n", 5500)))
	before := mustJSON(t, snap)
	if len(before) < 200000 {
		t.Fatal("fixture too small to exercise regression")
	}
	req, err := BuildRequest(snap, nil, "progress?")
	if err != nil {
		t.Fatalf("valid code-heavy snapshot rejected: %v", err)
	}
	if req.MaxTokens != 8192 || EstimateInputTokens(req) >= 200000 {
		t.Fatalf("budget: %d %d", req.MaxTokens, EstimateInputTokens(req))
	}
	if string(before) != string(mustJSON(t, snap)) {
		t.Fatal("snapshot mutated")
	}
	baseline := EstimateInputTokens(ModelCall{Messages: []acllm.Message{acllm.UserText("x")}})
	if EstimateInputTokens(ModelCall{Messages: []acllm.Message{acllm.UserText("x")}, System: []string{strings.Repeat("中", 3000)}, Tools: fixture().Tools}) <= baseline+3000 {
		t.Fatal("system/schema/CJK omitted")
	}
}

func TestSideLongExchangeAndSnapshotCompactionAreBounded(t *testing.T) {
	for _, hugeHistory := range []bool{true, false} {
		t.Run(fmt.Sprint(hugeHistory), func(t *testing.T) {
			snap := Snapshot{Request: fixture(), Model: Model{WindowTokens: 32000}}
			var history []Exchange
			if hugeHistory {
				history = []Exchange{{Ordinal: 1, Question: "earlier", Answer: strings.Repeat("历史依据ABC", 14000), Status: "completed"}}
			} else {
				snap.Request.Messages = append([]acllm.Message{acllm.UserText(strings.Repeat("old tool evidence 中文", 9000))}, snap.Request.Messages...)
			}
			original := mustJSON(t, snap)
			calls, answers := 0, 0
			var final ModelCall
			p := fakeModel{generate: func(_ context.Context, input []*schema.Message, opts []model.Option) (*schema.Message, error) {
				if isSummaryCall(input) {
					calls++
					r := callFromInput(input, opts)
					if len(r.System) != 1 || EstimateInputTokens(r)+r.MaxTokens > 32000 || !utf8.ValidString(r.Messages[0].Text()) {
						t.Fatal("unsafe summary request")
					}
					msg := assistantSchema("goal, evidence and unresolved questions")
					msg.ResponseMeta = &schema.ResponseMeta{Usage: &schema.TokenUsage{CompletionTokens: 3}}
					return msg, nil
				}
				answers++
				final = callFromInput(input, opts)
				msg := assistantSchema("done")
				msg.ResponseMeta = &schema.ResponseMeta{Usage: &schema.TokenUsage{CompletionTokens: 5}}
				return msg, nil
			}}
			var memory Memory
			out, info, err := (SideQuestionService{p}).Respond(t.Context(), snap, "progress?", replayFixture(history, &memory), ContextOptions{}, nil)
			if err != nil || calls < 2 || calls > 12 || answers != 1 || out.Usage.OutputTokens != 3*calls+5 {
				t.Fatalf("calls=%d answers=%d info=%+v err=%v", calls, answers, info, err)
			}
			if info.EstimatedInputTokens > info.InputBudget {
				t.Fatal("oversized final request")
			}
			if !reflect.DeepEqual(final.Messages, acllm.MessagesForAPI(final.Messages)) {
				t.Fatal("tool pairing broken")
			}
			if !strings.Contains(string(mustJSON(t, final)), "verified asset") {
				t.Fatal("recent tool evidence discarded")
			}
			if string(original) != string(mustJSON(t, snap)) {
				t.Fatal("main snapshot modified")
			}
			before := calls
			_, _, err = (SideQuestionService{p}).Respond(t.Context(), snap, "another question", replayFixture(history, &memory), ContextOptions{}, nil)
			if err != nil || calls != before {
				t.Fatalf("summary cache not reused: %v", err)
			}
			if !hugeHistory {
				snap.Version++
				_, _, err = (SideQuestionService{p}).Respond(t.Context(), snap, "new snapshot", replayFixture(history, &memory), ContextOptions{}, nil)
				if err != nil || calls == before {
					t.Fatalf("stale snapshot cache reused: %v", err)
				}
			}
		})
	}
}

func TestSideOverflowRecoveryOnceAndFailureUsage(t *testing.T) {
	for _, twice := range []bool{false, true} {
		t.Run(fmt.Sprint(twice), func(t *testing.T) {
			answers, summaries := 0, 0
			p := fakeModel{generate: func(_ context.Context, input []*schema.Message, _ []model.Option) (*schema.Message, error) {
				if isSummaryCall(input) {
					summaries++
					msg := assistantSchema("summary")
					msg.ResponseMeta = usageOfTokens(3)
					return msg, nil
				}
				answers++
				if answers == 1 || twice {
					msg := assistantSchema("")
					msg.ResponseMeta = usageOfTokens(5)
					return msg, errors.New("context_length_exceeded")
				}
				msg := assistantSchema("recovered")
				msg.ResponseMeta = usageOfTokens(7)
				return msg, nil
			}}
			snap := Snapshot{Request: fixture(), Model: Model{WindowTokens: 32000}}
			snap.Request.Messages = append([]acllm.Message{acllm.UserText(strings.Repeat("old context ", 2000))}, snap.Request.Messages...)
			out, info, err := (SideQuestionService{p}).Respond(t.Context(), snap, "question", Replay{}, ContextOptions{}, nil)
			if answers != 2 || summaries != 1 || !info.OverflowRetried || (err != nil) != twice {
				t.Fatalf("retry limit: %d %d %+v %v", answers, summaries, info, err)
			}
			want := 15
			if twice {
				want = 13
			}
			if out.Usage.InputTokens != want {
				t.Fatalf("usage=%+v", out.Usage)
			}
		})
	}
	// A stream that already exposed text must never replay it as a fresh answer.
	count := 0
	p := fakeModel{stream: func(context.Context, []*schema.Message, []model.Option) (*schema.StreamReader[*schema.Message], error) {
		count++
		sr, sw := schema.Pipe[*schema.Message](4)
		go func() {
			defer sw.Close()
			sw.Send(assistantSchema("partial"), nil)
			sw.Send(nil, errors.New("context_length_exceeded"))
		}()
		return sr, nil
	}}
	out, _, err := (SideQuestionService{p}).Respond(t.Context(), Snapshot{Request: fixture(), Model: Model{Streaming: true}}, "q", Replay{}, ContextOptions{}, nil)
	if err == nil || out.Text != "partial" || count != 1 {
		t.Fatal("partial stream retried")
	}
}

func TestSideSummaryCancellationAndFailureDoNotAdvanceMemory(t *testing.T) {
	for _, mode := range []string{"cancel", "error", "empty", "truncated", "too-large", "tool", "save-failed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			p := fakeModel{generate: func(_ context.Context, input []*schema.Message, _ []model.Option) (*schema.Message, error) {
				calls++
				usage := usageOfTokens(9)
				if !isSummaryCall(input) {
					t.Fatal("failed summary continued to answer")
				}
				msg := assistantSchema("summary")
				switch mode {
				case "cancel":
					cancel()
				case "error":
					msg = assistantSchema("")
					msg.ResponseMeta = usage
					return msg, errors.New("unavailable")
				case "empty":
					msg = assistantSchema("")
				case "truncated":
					msg = assistantSchema("partial")
					msg.ResponseMeta = &schema.ResponseMeta{FinishReason: "length", Usage: usage.Usage}
					return msg, nil
				case "too-large":
					msg = assistantSchema(strings.Repeat("中", 5000))
				case "tool":
					msg := toolCallSchema("forbidden", "Bash", "{}")
					msg.ResponseMeta = usage
					return msg, nil
				}
				msg.ResponseMeta = usage
				return msg, nil
			}}
			var history []Exchange
			for i := 1; i <= 21; i++ {
				history = append(history, Exchange{Ordinal: int64(i), Question: "q", Answer: "a", Status: "completed"})
			}
			var memory Memory
			replay := replayFixture(history, &memory)
			if mode == "save-failed" {
				replay.Save = func(context.Context, Memory) error { return errors.New("cleared") }
			}
			out, _, err := (SideQuestionService{p}).Respond(ctx, Snapshot{Request: fixture()}, "q", replay, ContextOptions{}, nil)
			if err == nil || calls != 1 || memory.Through != 0 || out.Usage.InputTokens != 9 {
				t.Fatalf("failed preparation: %+v %+v %v", memory, out, err)
			}
		})
	}
}

func TestSideSummaryCallCapAndStaticBudget(t *testing.T) {
	calls := 0
	p := fakeModel{generate: func(_ context.Context, input []*schema.Message, _ []model.Option) (*schema.Message, error) {
		calls++
		if !isSummaryCall(input) {
			t.Fatal("oversized request answered")
		}
		msg := assistantSchema("bounded summary")
		msg.ResponseMeta = &schema.ResponseMeta{Usage: &schema.TokenUsage{CompletionTokens: 1}}
		return msg, nil
	}}
	snap := Snapshot{Model: Model{WindowTokens: 32000}, Request: fixture()}
	snap.Request.Messages = []acllm.Message{acllm.UserText(strings.Repeat("x", 1200000))}
	out, _, err := (SideQuestionService{p}).Respond(t.Context(), snap, "q", Replay{}, ContextOptions{}, nil)
	if err == nil || calls != 12 || out.Usage.OutputTokens != 12 {
		t.Fatalf("summary cap calls=%d err=%v", calls, err)
	}
	calls = 0
	snap.Request.System = []string{strings.Repeat("x", 200000)}
	_, _, err = (SideQuestionService{p}).Respond(t.Context(), snap, "q", Replay{}, ContextOptions{}, nil)
	if !errors.Is(err, ErrContextBudget) || calls != 0 {
		t.Fatalf("static oversized budget: calls=%d err=%v", calls, err)
	}
}

func TestSideTwentyLongRepliesRespectSmallWindow(t *testing.T) {
	var history []Exchange
	for i := 1; i <= 20; i++ {
		history = append(history, Exchange{Ordinal: int64(i), Question: fmt.Sprintf("question-%d", i), Answer: strings.Repeat("evidence ", 3000), Status: "completed"})
	}
	calls := 0
	p := fakeModel{generate: func(_ context.Context, input []*schema.Message, opts []model.Option) (*schema.Message, error) {
		if r := callFromInput(input, opts); EstimateInputTokens(r)+r.MaxTokens > 32000 {
			t.Fatal("request exceeds small model window")
		}
		if isSummaryCall(input) {
			calls++
			return assistantSchema("historical objectives and evidence"), nil
		}
		return assistantSchema("answer"), nil
	}}
	var memory Memory
	_, info, err := (SideQuestionService{p}).Respond(t.Context(), Snapshot{Request: fixture(), Model: Model{WindowTokens: 32000}}, "current status?", replayFixture(history, &memory), ContextOptions{}, nil)
	if err != nil || !info.HistorySummarized || calls > 12 || memory.Through != 20 {
		t.Fatalf("20 long replies: calls=%d info=%+v memory=%+v err=%v", calls, info, memory, err)
	}
}

func TestSideOverflowWithoutReductionDoesNotRepeatAnswer(t *testing.T) {
	answers, summaries := 0, 0
	p := fakeModel{generate: func(_ context.Context, input []*schema.Message, _ []model.Option) (*schema.Message, error) {
		if isSummaryCall(input) {
			summaries++
			msg := assistantSchema(strings.Repeat("longer summary ", 100))
			msg.ResponseMeta = usageOfTokens(3)
			return msg, nil
		}
		answers++
		msg := assistantSchema("")
		msg.ResponseMeta = usageOfTokens(5)
		return msg, errors.New("context_length_exceeded")
	}}
	snapshot := Snapshot{Request: ModelCall{MaxTokens: 128, Messages: []acllm.Message{acllm.UserText("tiny")}}}
	out, _, err := (SideQuestionService{p}).Respond(t.Context(), snapshot, "question", Replay{}, ContextOptions{}, nil)
	if err == nil || !strings.Contains(err.Error(), "未能进一步缩减") || answers != 1 || summaries != 1 || out.Usage.InputTokens != 8 {
		t.Fatalf("no-progress recovery: %d %d %+v %v", answers, summaries, out, err)
	}
}
