package compaction

import (
	"context"
	"errors"
	"testing"

	"github.com/c1ayooo/4zrec/acllm"
)

func toolUse(id, name string) acllm.Message {
	return acllm.Message{Role: acllm.RoleAssistant, Content: []acllm.ContentBlock{{Type: acllm.BlockToolUse, ID: id, Name: name}}}
}
func toolResult(id string) acllm.Message {
	return acllm.Message{Role: acllm.RoleUser, Content: []acllm.ContentBlock{acllm.ToolResultText(id, "body", false)}}
}

// --- pairForReplay ---

func TestPairForReplayKeepsPaired(t *testing.T) {
	msgs := []acllm.Message{acllm.UserText("q"), toolUse("a", "Read"), toolResult("a"), asstText("done")}
	out := pairForReplay(msgs)
	if len(out) != 4 {
		t.Fatalf("paired blocks must be kept, got %d: %+v", len(out), out)
	}
}

func TestPairForReplayDropsDanglingUse(t *testing.T) {
	msgs := []acllm.Message{asstText("hi"), toolUse("a", "Read")} // result missing
	out := pairForReplay(msgs)
	if len(out) != 1 || out[0].Text() != "hi" {
		t.Fatalf("dangling tool_use should be dropped: %+v", out)
	}
}

func TestPairForReplayDropsDanglingResult(t *testing.T) {
	msgs := []acllm.Message{acllm.UserText("q"), toolResult("z")} // use missing
	out := pairForReplay(msgs)
	if len(out) != 1 || out[0].Text() != "q" {
		t.Fatalf("dangling tool_result should be dropped: %+v", out)
	}
}

func TestPairForReplayKeepsSiblingTextOfDroppedResult(t *testing.T) {
	msgs := []acllm.Message{{Role: acllm.RoleUser, Content: []acllm.ContentBlock{
		acllm.TextBlock("keep"),
		acllm.ToolResultText("gone", "x", false), // dangling
	}}}
	out := pairForReplay(msgs)
	if len(out) != 1 || len(out[0].Content) != 1 || out[0].Content[0].Text != "keep" {
		t.Fatalf("sibling text should survive: %+v", out)
	}
}

// --- groupByAPIRound ---

func TestGroupByAPIRoundShapes(t *testing.T) {
	u := acllm.UserText("u")
	a := asstText("a")
	cases := []struct {
		name string
		in   []acllm.Message
		want int
	}{
		{"empty", nil, 0},
		{"one user", []acllm.Message{u}, 1},
		{"two user", []acllm.Message{u, u}, 1},
		{"one assistant", []acllm.Message{a}, 1},
		{"assistant then user", []acllm.Message{a, u}, 1},
		{"user then assistant", []acllm.Message{u, a}, 2},
		{"alternating", []acllm.Message{u, a, u, a}, 3},
		{"consecutive assistants", []acllm.Message{a, a}, 2},
	}
	for _, tc := range cases {
		if got := len(groupByAPIRound(tc.in)); got != tc.want {
			t.Errorf("%s: groups=%d, want %d", tc.name, got, tc.want)
		}
	}
}

// --- truncateHeadForPTLRetry ---

func TestTruncateSingleGroupFails(t *testing.T) {
	if _, ok := truncateHeadForPTLRetry([]acllm.Message{acllm.UserText("solo")}); ok {
		t.Fatal("a single group cannot be truncated")
	}
}

func TestTruncateDropsTwentyPercent(t *testing.T) {
	// 10 groups: [U] then 9 lone assistants.
	msgs := []acllm.Message{acllm.UserText("u0")}
	for range 9 {
		msgs = append(msgs, asstText("a"))
	}
	if len(groupByAPIRound(msgs)) != 10 {
		t.Fatalf("precondition: want 10 groups, got %d", len(groupByAPIRound(msgs)))
	}
	out, ok := truncateHeadForPTLRetry(msgs)
	if !ok {
		t.Fatal("should truncate")
	}
	// drop floor(10*0.2)=2 groups → 8 assistants remain, marker prepended.
	if out[0].Text() != ptlRetryMarker || len(out) != 1+8 {
		t.Fatalf("want marker + 8 messages, got len=%d first=%q", len(out), out[0].Text())
	}
}

func TestTruncateKeepsAtLeastOneGroup(t *testing.T) {
	out, ok := truncateHeadForPTLRetry([]acllm.Message{acllm.UserText("u"), asstText("a")}) // 2 groups
	if !ok {
		t.Fatal("should truncate 2 groups")
	}
	// drop 1 → [A] remains, marker prepended (result would start with assistant).
	if out[0].Text() != ptlRetryMarker || len(out) != 2 {
		t.Fatalf("want [marker, A], got %+v", out)
	}
}

func TestTruncateDoesNotDoubleMarker(t *testing.T) {
	msgs := []acllm.Message{acllm.UserText(ptlRetryMarker), acllm.UserText("u"), asstText("a"), acllm.UserText("u2"), asstText("a2")}
	out, ok := truncateHeadForPTLRetry(msgs)
	if !ok {
		t.Fatal("should truncate")
	}
	if out[0].Text() != ptlRetryMarker {
		t.Fatalf("first should be the (single) marker, got %q", out[0].Text())
	}
	if out[1].Text() == ptlRetryMarker {
		t.Fatal("marker must not be doubled")
	}
}

// --- formatCompactSummary ---

func TestFormatCompactSummaryCases(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain passthrough", "just text", "just text"},
		{"analysis stripped, no summary tags", "<analysis>secret</analysis>\nHello", "Hello"},
		{"summary extracted ignoring surroundings", "before <summary>THE BODY</summary> after", "Summary:\nTHE BODY"},
		{"multiline analysis then summary", "<analysis>l1\nl2</analysis>\n<summary>ok</summary>", "Summary:\nok"},
		{"blank lines collapsed", "<summary>a\n\n\n\nb</summary>", "Summary:\na\n\nb"},
	}
	for _, tc := range cases {
		if got := formatCompactSummary(tc.in); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// --- NewModelSummarizer maxOut cap ---

func TestModelSummarizerMaxOutCap(t *testing.T) {
	cases := []struct{ mo, want int }{
		{0, 20000},     // unset → cap
		{8000, 8000},   // below cap → passthrough
		{20000, 20000}, // at cap
		{25000, 20000}, // above cap → clamped
		{19999, 19999}, // just below cap
	}
	for _, tc := range cases {
		m := &captureModel{reply: "<summary>x</summary>"}
		_, _ = NewModelSummarizer(m, tc.mo, false)(context.Background(), []acllm.Message{acllm.UserText("hi")})
		if m.maxToks[0] != tc.want {
			t.Errorf("mo=%d: MaxTokens=%d, want %d", tc.mo, m.maxToks[0], tc.want)
		}
	}
}

// --- retry / cancellation edges ---

func TestSummarizerContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := &captureModel{reply: "x"}
	_, err := NewModelSummarizer(m, 0, false)(ctx, []acllm.Message{acllm.UserText("hi")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if m.calls != 0 {
		t.Fatalf("no stream should be issued on a cancelled ctx, calls=%d", m.calls)
	}
}

func TestSummarizerPTLExhausts(t *testing.T) {
	m := &captureModel{failN: 999} // every attempt overflows
	head := []acllm.Message{acllm.UserText("u0"), asstText("a1"), acllm.UserText("u1"), asstText("a2")}
	_, err := NewModelSummarizer(m, 0, false)(context.Background(), head)
	if err == nil || !IsOverflow(err) {
		t.Fatalf("persistent overflow should surface an overflow error, got %v", err)
	}
	if m.calls < 2 {
		t.Fatalf("should have retried after truncation, calls=%d", m.calls)
	}
}
