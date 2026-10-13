package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/askernel"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/artex/tools"
	"github.com/cloudwego/eino/schema"
)

// The capture layer's behavioral gold standard, run through the FULL kernel
// against a scripted fake model: the cumulative token usage reported by the
// model turns that DID complete is persisted on the result activity even when
// the run ends abnormally (provider failure / cancellation).
//
// Usage events ride completed model turns (the kernel folds them from the
// assembled assistant message), so the failing/interrupted call is scripted as
// the SECOND model turn: turn 1 is a no-op tool call that completes and reports
// usage (and forces a follow-up model call); turn 2 fails (or hangs until
// cancelled).
func TestCaptureRunPersistsUsageOnProviderFailure(t *testing.T) {
	m := &fakeChatModel{}
	m.usage = &schema.TokenUsage{PromptTokens: 16, PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 3, CacheWriteTokens: 2}, CompletionTokens: 7}
	m.script(toolCallTurn("nop-1"))
	m.failTurn(errFakeProvider)

	var activities []db.Activity
	_, _, err := captureRun(context.Background(), askernel.Options{Model: m, Tools: []actool.CoreTool{nopTool(nil)}, MaxTurns: 3}, "test", func(a db.Activity) {
		activities = append(activities, a)
	})
	if !errors.Is(err, errFakeProvider) {
		t.Fatalf("captureRun error=%v, want %v", err, errFakeProvider)
	}
	assertCapturedResultUsage(t, activities, 11, 7, 3, 2)
}

func TestCaptureRunPersistsUsageOnCancellation(t *testing.T) {
	m := &fakeChatModel{}
	m.usage = &schema.TokenUsage{PromptTokens: 22, PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 5, CacheWriteTokens: 4}, CompletionTokens: 9}
	// Turn 1 (tool call) completes and reports usage; turn 2 hangs until the
	// context is cancelled. The test cancels only after turn 1's tool ran, so
	// the sequence is deterministic.
	ran := make(chan struct{})
	m.script(toolCallTurn("nop-1"))
	m.hangTurn()

	ctx, cancel := context.WithCancel(context.Background())
	var activities []db.Activity
	done := make(chan error, 1)
	go func() {
		_, _, err := captureRun(ctx, askernel.Options{Model: m, Tools: []actool.CoreTool{nopTool(ran)}, MaxTurns: 3}, "test", func(a db.Activity) {
			activities = append(activities, a)
		})
		done <- err
	}()
	<-ran
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("captureRun error=%v, want context canceled", err)
	}
	assertCapturedResultUsage(t, activities, 13, 9, 5, 4)
}

// toolCallTurn scripts one assistant turn that invokes the nop tool.
func toolCallTurn(id string) *schema.Message {
	return schema.AssistantMessage("", []schema.ToolCall{
		{ID: id, Function: schema.FunctionCall{Name: "Nop", Arguments: `{}`}},
	})
}

// nopTool is a do-nothing tool; onRan, when non-nil, is closed on each run so a
// test can synchronize with the kernel's tool execution.
func nopTool(onRan chan struct{}) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "Nop", Description: "no-op", Schema: obj(map[string]any{}),
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision {
			return actool.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			if onRan != nil {
				close(onRan)
			}
			return actool.Text("ok"), nil
		},
	})
}

func assertCapturedResultUsage(t *testing.T, activities []db.Activity, input, output, read, write int) {
	t.Helper()
	results := 0
	for _, activity := range activities {
		if activity.Kind != "result" {
			continue
		}
		results++
		if activity.InputTokens == nil || *activity.InputTokens != input ||
			activity.OutputTokens == nil || *activity.OutputTokens != output ||
			activity.CacheReadTokens == nil || *activity.CacheReadTokens != read ||
			activity.CacheWriteTokens == nil || *activity.CacheWriteTokens != write {
			t.Fatalf("result usage=%+v, want input=%d output=%d read=%d write=%d", activity, input, output, read, write)
		}
	}
	if results != 1 {
		t.Fatalf("result activity count=%d, activities=%+v", results, activities)
	}
}
