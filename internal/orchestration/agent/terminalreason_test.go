package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/c1ayooo/4zrec/internal/platform/llm/acllm"
	"github.com/c1ayooo/4zrec/internal/kernel/askernel"
)

func TestReasonHintCoversEveryTerminalReason(t *testing.T) {
	all := []askernel.TerminalReason{
		askernel.ReasonCompleted, askernel.ReasonBlockingLimit, askernel.ReasonImageError,
		askernel.ReasonModelError, askernel.ReasonAbortedStreaming, askernel.ReasonAbortedTools,
		askernel.ReasonPromptTooLong, askernel.ReasonStopHookPrevented, askernel.ReasonHookStopped,
		askernel.ReasonMaxTurns, askernel.ReasonTimeout,
	}
	for _, reason := range all {
		if strings.TrimSpace(reasonHint[reason]) == "" {
			t.Errorf("terminal reason %q has no explanation", reason)
		}
	}
}

func TestAbortCausePropagatesThroughRunContextChain(t *testing.T) {
	type key struct{}
	execCtx, cancelExec := context.WithCancelCause(context.Background())
	workCtx, cancelWork := context.WithCancelCause(execCtx)
	defer cancelWork(nil)
	valued := context.WithValue(workCtx, key{}, "task-1")
	runCtx, cancelRun := context.WithTimeoutCause(valued, time.Hour, AbortRunHardTimeout)
	defer cancelRun()

	cancelExec(AbortPausedByUser)
	code, _, text, ok := AbortReason(runCtx)
	if !ok || code != "paused_by_user" {
		t.Fatalf("code=%q ok=%v, want paused_by_user", code, ok)
	}
	if !strings.Contains(text, "frontier") {
		t.Fatalf("cause detail did not propagate: %q", text)
	}
}

func TestAbortReasonFallbacks(t *testing.T) {
	if _, _, _, ok := AbortReason(context.Background()); ok {
		t.Fatal("live context must not report an abort reason")
	}
	plain, cancel := context.WithCancel(context.Background())
	cancel()
	if code, _, _, ok := AbortReason(plain); !ok || code != "canceled_no_cause" {
		t.Fatalf("code=%q ok=%v, want canceled_no_cause", code, ok)
	}
	timed, cancelTimed := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelTimed()
	<-timed.Done()
	if code, _, _, _ := AbortReason(timed); code != "deadline_exceeded" {
		t.Fatalf("code=%q, want deadline_exceeded", code)
	}
}

func TestTerminalTextAbortedNamesCauseAndHangingTool(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(AbortKilledByPlanner)
	trace := &runTrace{startedAt: time.Now().Add(-90 * time.Second)}
	trace.start("tu_1", "Bash", `{"command":"nmap -p- 10.0.0.1"}`)
	term := &askernel.Terminal{
		Reason: askernel.ReasonAbortedTools,
		Err:    context.Canceled,
		Turns:  7,
		Usage:  acllm.Usage{InputTokens: 1200, OutputTokens: 340},
	}
	summary, detail := terminalText(ctx, term, trace)
	if !strings.Contains(summary, "规划者") || strings.Contains(summary, "\n") {
		t.Fatalf("unexpected summary: %q", summary)
	}
	for _, want := range []string{"killed_by_planner", "aborted_tools", "7 轮", "Bash", "未返回结果", "1200"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail missing %q:\n%s", want, detail)
		}
	}
}

func TestTerminalTextDirectContextCancellationKeepsCause(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(AbortChatStoppedByUser)
	summary, detail := terminalText(ctx, &askernel.Terminal{Err: context.Canceled}, &runTrace{startedAt: time.Now()})
	if !strings.Contains(summary, "用户停止") || !strings.Contains(detail, "chat_stopped_by_user") {
		t.Fatalf("direct context cancellation lost cause: %q\n%s", summary, detail)
	}
	if !strings.Contains(detail, "context_canceled") {
		t.Fatalf("missing synthesized terminal label: %s", detail)
	}
}

func TestTerminalTextAbortedPreservesPartialOutput(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(AbortPausedByUser)
	summary, detail := terminalText(ctx, &askernel.Terminal{
		Reason: askernel.ReasonAbortedStreaming,
		Text:   "已经生成的半段回答",
	}, &runTrace{startedAt: time.Now()})
	if !strings.Contains(summary, "用户暂停") {
		t.Fatalf("abort summary lost cause: %q", summary)
	}
	if !strings.Contains(detail, "已经生成的半段回答") {
		t.Fatalf("abort detail lost partial output: %s", detail)
	}
}

func TestTerminalTextCompletedToolNotBlamed(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(AbortShutdown)
	trace := &runTrace{startedAt: time.Now()}
	trace.start("tu_1", "Read", `{"path":"/etc/hosts"}`)
	trace.done("tu_1")
	_, detail := terminalText(ctx, &askernel.Terminal{Reason: askernel.ReasonAbortedStreaming}, trace)
	if strings.Contains(detail, "未返回结果") || !strings.Contains(detail, "已正常返回") {
		t.Fatalf("completed tool was blamed:\n%s", detail)
	}
}

func TestTerminalTextNonAbortReasons(t *testing.T) {
	trace := &runTrace{startedAt: time.Now()}
	summary, _ := terminalText(context.Background(), &askernel.Terminal{Reason: askernel.ReasonMaxTurns}, trace)
	if !strings.Contains(summary, "运行预算上限") || strings.Contains(summary, "中断") {
		t.Fatalf("unexpected max_turns summary: %q", summary)
	}
	summary, detail := terminalText(context.Background(), &askernel.Terminal{
		Reason: askernel.ReasonModelError, Err: errors.New("429 rate limited"),
	}, trace)
	if !strings.Contains(summary, "model_error") || !strings.Contains(detail, "429 rate limited") {
		t.Fatalf("model_error detail incomplete: %q\n%s", summary, detail)
	}
}

func TestAbortCausesAreWellFormed(t *testing.T) {
	all := []*AbortCause{
		AbortPausedByUser, AbortPausedByOrchestrator, AbortTaskDeleted, AbortPausedOnReload,
		AbortGoalMet, AbortSettleDrainTimeout, AbortKilledByPlanner, AbortWorkPausedByUser,
		AbortWorkCancelledByUser, AbortWorkFinished, AbortPausedRaceGuard,
		AbortChatStoppedByUser, AbortChatPausedWithTask, AbortChatTurnFinished,
		AbortShutdown, AbortRunHardTimeout,
	}
	seen := map[string]bool{}
	for _, abort := range all {
		switch {
		case abort.Code == "" || seen[abort.Code]:
			t.Errorf("missing or duplicate code: %q", abort.Code)
		case abort.Short == "" || utf8.RuneCountInString(abort.Short) > 40:
			t.Errorf("%s has invalid short text: %q", abort.Code, abort.Short)
		case utf8.RuneCountInString(abort.Text) <= utf8.RuneCountInString(abort.Short):
			t.Errorf("%s detail must be longer than short text", abort.Code)
		}
		seen[abort.Code] = true
	}
}

func TestFirstLineCapsByRuneNotByte(t *testing.T) {
	if got := firstLine(strings.Repeat("恢复", 10), 5); got != "恢复恢复恢…" {
		t.Fatalf("firstLine split a Unicode character: %q", got)
	}
	if got := firstLine("头\n尾", 100); got != "头" {
		t.Fatalf("firstLine did not stop at newline: %q", got)
	}
}
