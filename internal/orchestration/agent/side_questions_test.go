package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/kernel/sidequestion"
	"github.com/c1ayooo/4zrec/internal/kernel/transcript"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// sideAgentModel is a scripted chat model: call 1 asks to Read the fixture file,
// later calls answer "main finished" (and, after a reset, ask to Read a
// nonexistent path — the side executor must refuse to run it).
type sideAgentModel struct {
	calls int
	path  string
}

func (p *sideAgentModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return p, nil
}

func (p *sideAgentModel) Generate(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
	p.calls++
	if p.calls == 1 {
		input, _ := json.Marshal(map[string]string{"file_path": p.path})
		return schema.AssistantMessage("", []schema.ToolCall{
			{ID: "fixture-read", Function: schema.FunctionCall{Name: "Read", Arguments: string(input)}},
		}), nil
	}
	return schema.AssistantMessage("main finished", nil), nil
}

func (p *sideAgentModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := p.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}

func TestSideActualChatCheckpointToolResultAndTranscriptIsolation(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{true: "stream", false: "atomic"}[streaming], func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "asset.txt")
			if err := os.WriteFile(file, []byte("controlled-homepage-result"), 0600); err != nil {
				t.Fatal(err)
			}
			p := &sideAgentModel{path: file}
			bound := sidequestion.Bind(p, sidequestion.Model{Model: "fixture", Streaming: streaming})
			store := transcript.NewStore(filepath.Join(dir, "transcripts"))
			chat := NewChatAgent(bound, "fixture", dir, store, 100000)
			chat.SetNonStreaming(func() bool { return !streaming })
			var snapMu sync.Mutex
			var snapshots []sidequestion.Snapshot
			var activities []db.Activity
			// The publisher fires from the kernel's stream-pump goroutine too, so
			// the append must be mutex-guarded for the race detector (and reality).
			ctx := sidequestion.WithPublisher(t.Context(), func(s sidequestion.Snapshot) {
				snapMu.Lock()
				defer snapMu.Unlock()
				snapshots = append(snapshots, s)
			})
			if _, err := chat.Chat(ctx, "mainagent", "conv-987654", "Read the local fixture", 5, time.Minute, false, func(a db.Activity) { activities = append(activities, a) }); err != nil {
				t.Fatal(err)
			}
			if len(snapshots) < 3 {
				t.Fatalf("actual Chat missed capture hooks: %d", len(snapshots))
			}
			// The streaming path's final checkpoint save lands on the tee-pump
			// goroutine just after the kernel hands the stream's EOF to the
			// consumer — let it settle before taking the baseline.
			waitSnapshotsStable(t, &snapMu, &snapshots)
			last := snapshots[len(snapshots)-1]
			raw, _ := json.Marshal(last)
			if last.Parent.ConversationID != 987654 || !strings.Contains(string(raw), "controlled-homepage-result") || !strings.Contains(string(raw), "main finished") {
				t.Fatalf("missing real tool result/final reply: %s", raw)
			}
			before, err := os.ReadFile(store.MainPath("conv-987654"))
			if err != nil {
				t.Fatal(err)
			}
			count := len(activities)
			tools := 0
			for _, a := range activities {
				if a.Kind == "tool_use" {
					tools++
				}
			}
			if tools != 1 {
				t.Fatalf("main fixture tool executions: %d", tools)
			}
			req, err := sidequestion.BuildRequest(last, nil, "side-only-question")
			if err != nil {
				t.Fatal(err)
			}
			// Reset the fake to request another Read; the side executor cannot run it.
			p.calls = 0
			p.path = filepath.Join(dir, "nonexistent")
			answer, err := (sidequestion.SideQuestionService{Provider: bound}).Answer(t.Context(), req, streaming, nil)
			if err != nil || !answer.ToolUse || p.calls != 1 || !strings.Contains(answer.Text, "不能执行工具") {
				t.Fatalf("tool denial %+v %v", answer, err)
			}
			after, err := os.ReadFile(store.MainPath("conv-987654"))
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) || len(activities) != count {
				t.Fatal("side question modified main transcript/activity")
			}
			waitSnapshotsStable(t, &snapMu, &snapshots)
			if len(snapshots) == 0 || snapshots[len(snapshots)-1].Version != last.Version {
				t.Fatal("side request replaced main checkpoint")
			}
			for _, snap := range snapshots {
				b, _ := json.Marshal(snap)
				if strings.Contains(string(b), "side-only-question") {
					t.Fatal("side question leaked into a captured checkpoint")
				}
			}
		})
	}
}

// waitSnapshotsStable polls until the publisher has gone quiet for a few
// consecutive checks (bounded), so asynchronous checkpoint saves have landed
// before the caller compares baselines.
func waitSnapshotsStable(t *testing.T, mu *sync.Mutex, out *[]sidequestion.Snapshot) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	stable := 0
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(*out)
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		n2 := len(*out)
		mu.Unlock()
		if n2 == n {
			stable++
			if stable >= 3 {
				return
			}
			continue
		}
		stable = 0
	}
}
