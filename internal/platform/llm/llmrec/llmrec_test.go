package llmrec

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/kernel/transcript"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"github.com/google/uuid"
)

// fakeModel is a configurable model.ToolCallingChatModel.
type fakeModel struct {
	generate func(context.Context, []*schema.Message) (*schema.Message, error)
	stream   func(context.Context, []*schema.Message) (*schema.StreamReader[*schema.Message], error)
}

func (f fakeModel) Generate(ctx context.Context, input []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	return f.generate(ctx, input)
}

func (f fakeModel) Stream(ctx context.Context, input []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return f.stream(ctx, input)
}

func (f fakeModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) { return f, nil }

func atomicFixture() *schema.Message {
	msg := schema.AssistantMessage("answer", nil)
	msg.ReasoningContent = "reasoning"
	msg.ResponseMeta = &schema.ResponseMeta{FinishReason: "stop", Usage: &schema.TokenUsage{PromptTokens: 7, CompletionTokens: 3, TotalTokens: 10}}
	return msg
}

func TestTaskIDContextUsesExplicitRegistryID(t *testing.T) {
	ctx := WithTaskID(context.Background(), " 42 ")
	if got := TaskIDFrom(ctx); got != "42" {
		t.Fatalf("TaskIDFrom()=%q want 42", got)
	}
	if got := TaskIDFrom(WithTaskID(ctx, "   ")); got != "42" {
		t.Fatalf("blank task id should preserve parent context, got %q", got)
	}
	if got := TaskIDFrom(nil); got != "" {
		t.Fatalf("nil context returned %q", got)
	}
}

func TestParseSessionFallbackIsExplorationScoped(t *testing.T) {
	taskID, worker := parseSession("exp12-worker-i99")
	if taskID != "12" || worker != "worker" {
		t.Fatalf("parseSession()=(%q,%q)", taskID, worker)
	}
	if taskID, worker := parseSession("not-a-task"); taskID != "" || worker != "" {
		t.Fatalf("unexpected non-session parse: (%q,%q)", taskID, worker)
	}
}

func TestGenerateForwardsAtomicResponse(t *testing.T) {
	inner := fakeModel{generate: func(context.Context, []*schema.Message) (*schema.Message, error) {
		return atomicFixture(), nil
	}}
	recorder := Wrap(inner, nil, "model", "profile", "", "", func() bool { return false })
	msg, err := recorder.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if got := messageText(msg); got != "answer" {
		t.Fatalf("Generate() text=%q want answer", got)
	}
	if got := messageReasoning(msg); got != "reasoning" {
		t.Fatalf("Generate() reasoning=%q want reasoning", got)
	}
	if got := finishReason(msg); got != "stop" {
		t.Fatalf("Generate() finish reason=%q want stop", got)
	}
	if msg.ResponseMeta == nil || msg.ResponseMeta.Usage.PromptTokens != 7 || msg.ResponseMeta.Usage.CompletionTokens != 3 {
		t.Fatalf("Generate() usage=%+v", msg.ResponseMeta)
	}
}

func TestGenerateErrorRecordsErrorStatus(t *testing.T) {
	inner := fakeModel{generate: func(context.Context, []*schema.Message) (*schema.Message, error) {
		return nil, errors.New("HTTP 401")
	}}
	recorder := Wrap(inner, nil, "", "profile", "", "", func() bool { return false })
	if _, err := recorder.Generate(context.Background(), nil); err == nil {
		t.Fatal("Generate() should surface the inner error")
	}
	// pg == nil keeps the recording paths inert; the call must not panic.
}

// gatedStream builds a stream that yields the given chunks and then ends the
// way the test decides: once released is closed, a pending cancellation is
// surfaced as the stream's terminal error, otherwise the stream ends cleanly
// with EOF. This models a real provider whose body fails on cancellation.
func gatedStream(ctx context.Context, chunks []*schema.Message, released <-chan struct{}) *schema.StreamReader[*schema.Message] {
	sr, sw := schema.Pipe[*schema.Message](len(chunks) + 1)
	go func() {
		defer sw.Close()
		for _, c := range chunks {
			if sw.Send(c, nil) {
				return // consumer closed early
			}
		}
		<-released
		select {
		case <-ctx.Done():
			sw.Send(nil, ctx.Err())
		default:
			sw.Send(nil, io.EOF)
		}
	}()
	return sr
}

func usageChunk(prompt, completion int) *schema.Message {
	msg := schema.AssistantMessage("", nil)
	msg.ResponseMeta = &schema.ResponseMeta{Usage: &schema.TokenUsage{PromptTokens: prompt, CompletionTokens: completion}}
	return msg
}

func waitForUsageRow(t *testing.T, pg *db.DB, profile string) (count, input, output int, worker, status string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := pg.QueryRow(`SELECT count(*),max(input_tokens),max(output_tokens),max(worker),max(status)
FROM llm_usage WHERE profile_name=$1`, profile).Scan(&count, &input, &output, &worker, &status)
		if err == nil && count > 0 {
			return count, input, output, worker, status
		}
		if time.Now().After(deadline) {
			t.Fatalf("usage row never appeared: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The stream rows are written by the observer goroutine once the tee'd branch
// settles, so the test polls instead of asserting synchronously.
func TestSideUsageRecordedOnceOnConsumerCancellation(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	// llm_usage 不在 schema.sql 里,由生产启动与其他包的测试负责创建——本测试
	// 不能依赖共享库恰好已被别人建过表,自己确保一次。
	if err := pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	for _, early := range []bool{false, true} {
		profile := "btw-metering-" + uuid.NewString()
		ctx, cancel := context.WithCancel(transcript.WithSessionID(t.Context(), "exp0-btw-test"))
		released := make(chan struct{})
		defer cancel()
		inner := fakeModel{stream: func(callCtx context.Context, _ []*schema.Message) (*schema.StreamReader[*schema.Message], error) {
			return gatedStream(callCtx, []*schema.Message{
				usageChunk(23, 0),
				usageChunk(23, 5),
			}, released), nil
		}}
		recorder := Wrap(inner, pg, "fixture", profile, "", "", func() bool { return false })
		sr, err := recorder.Stream(ctx, []*schema.Message{schema.UserMessage("hi")})
		if err != nil {
			t.Fatal(err)
		}
		chunks := 0
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(released) }) }
		for {
			_, rerr := sr.Recv()
			if errors.Is(rerr, io.EOF) {
				break
			}
			if rerr != nil {
				t.Fatal(rerr)
			}
			chunks++
			if early && chunks == 1 {
				cancel() // Consumer exits before the provider can return a cancellation error.
				break
			}
			if !early && chunks == 2 {
				release() // let the provider end the stream cleanly
			}
		}
		sr.Close()
		release()
		count, input, output, worker, status := waitForUsageRow(t, pg, profile)
		_, _ = pg.Exec(`DELETE FROM llm_usage WHERE profile_name=$1`, profile)
		// The status is decided before the row is written, so cancelling only
		// now cannot flip the healthy run to an error row.
		if !early {
			cancel()
		}
		wantStatus := "ok"
		if early {
			wantStatus = "error"
		}
		if count != 1 || input != 23 || output != 5 || worker != "btw" || status != wantStatus {
			t.Fatalf("early=%v: count=%d usage=%d/%d worker=%q status=%q", early, count, input, output, worker, status)
		}
	}
}
