package noa

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/acllm"
)

func userText(s string) acllm.Message {
	return acllm.Message{Role: acllm.RoleUser, Content: []acllm.ContentBlock{acllm.TextBlock(s)}}
}

func assistantWith(blocks ...acllm.ContentBlock) acllm.Message {
	return acllm.Message{Role: acllm.RoleAssistant, Content: blocks}
}

func toolUse(id, name, input string) acllm.ContentBlock {
	return acllm.ContentBlock{Type: acllm.BlockToolUse, ID: id, Name: name, Input: json.RawMessage(input)}
}

func toolResult(useID, text string) acllm.Message {
	return acllm.Message{Role: acllm.RoleUser, Content: []acllm.ContentBlock{{
		Type: acllm.BlockToolResult, ToolUseID: useID,
		Content: []acllm.ContentBlock{acllm.TextBlock(text)},
	}}}
}

func TestProjectFlattensBlocks(t *testing.T) {
	msgs := []acllm.Message{
		userText("the task"),
		assistantWith(
			acllm.ContentBlock{Type: acllm.BlockThinking, Thinking: "let me look", Signature: "sig-abc"},
			acllm.TextBlock("I'll read it"),
			toolUse("t1", "Read", `{"file_path":"/x.go"}`),
		),
		toolResult("t1", "package main"),
	}
	cores, sc := Project(msgs)
	if len(cores) != 5 {
		t.Fatalf("got %d cores, want 5 (user, thinking, text, tool_use, tool_result)", len(cores))
	}
	want := []struct {
		role Role
		ct   ContentType
	}{
		{RoleUser, CTText},
		{RoleAssistant, CTReasoning},
		{RoleAssistant, CTText},
		{RoleAssistant, CTToolCall},
		{RoleTool, CTToolResult},
	}
	for i, w := range want {
		if cores[i].Role != w.role || cores[i].ContentType != w.ct {
			t.Errorf("core %d = %s/%s, want %s/%s", i, cores[i].Role, cores[i].ContentType, w.role, w.ct)
		}
	}
	if sc.Signatures[cores[1].ID] != "sig-abc" {
		t.Fatalf("thinking signature = %q, want it captured in the sidecar", sc.Signatures[cores[1].ID])
	}
	// A tool result carries no name of its own; it must be recovered from the call.
	if cores[4].ToolName != "Read" {
		t.Fatalf("tool result name = %q, want it resolved from the tool_use", cores[4].ToolName)
	}
}

// A message's identity must not depend on the tag, or the id would change every
// turn the tag is re-rendered.
func TestProjectStripsRefTagBeforeHashing(t *testing.T) {
	plain, _ := Project([]acllm.Message{userText("hello world")})
	tagged, _ := Project([]acllm.Message{userText("hello world\n<noa-ref id=\"m00001\" tokens=\"3\"/>")})
	if plain[0].ID != tagged[0].ID {
		t.Fatalf("id changed with the tag present: %q vs %q", plain[0].ID, tagged[0].ID)
	}
	if strings.Contains(tagged[0].Text, "noa-ref") {
		t.Fatalf("projected text still carries the tag: %q", tagged[0].Text)
	}
}

func TestProjectDisambiguatesIdenticalMessages(t *testing.T) {
	cores, _ := Project([]acllm.Message{userText("git status"), userText("git status")})
	if cores[0].ID == cores[1].ID {
		t.Fatal("two identical messages collapsed onto one id")
	}
	if strings.HasSuffix(cores[0].ID, "_1") {
		t.Fatalf("first occurrence = %q, want the bare hash so an unchanged history projects unchanged", cores[0].ID)
	}
	if !strings.HasSuffix(cores[1].ID, "_1") {
		t.Fatalf("second occurrence = %q, want an occurrence suffix", cores[1].ID)
	}
}

// Everything before a compaction boundary was already summarised into the
// message that follows it; re-projecting it would duplicate the content.
func TestProjectInheritsCompactionBoundary(t *testing.T) {
	msgs := []acllm.Message{
		userText("ancient history"),
		acllm.BoundaryMessage(acllm.BoundaryMeta{Trigger: "auto"}),
		userText("the summary of it"),
		userText("recent"),
	}
	cores, _ := Project(msgs)
	if len(cores) != 2 {
		t.Fatalf("got %d cores, want 2 — pre-boundary content must not be resurrected", len(cores))
	}
	if cores[0].Text != "the summary of it" {
		t.Fatalf("first core = %q, want projection to start after the boundary", cores[0].Text)
	}
}

func TestProjectSkipsBoundaryMarker(t *testing.T) {
	cores, _ := Project([]acllm.Message{acllm.BoundaryMessage(acllm.BoundaryMeta{}), userText("after")})
	if len(cores) != 1 {
		t.Fatalf("got %d cores, want only the real message", len(cores))
	}
}

func TestReassembleRoundTripsUnchanged(t *testing.T) {
	msgs := []acllm.Message{
		userText("the task"),
		assistantWith(
			acllm.ContentBlock{Type: acllm.BlockThinking, Thinking: "hmm", Signature: "sig-1"},
			toolUse("t1", "Read", `{"file_path":"/x.go"}`),
		),
		toolResult("t1", "contents"),
	}
	cores, sc := Project(msgs)
	out := Reassemble(cores, msgs, sc, ReassembleOptions{})

	if len(out) != len(msgs) {
		t.Fatalf("round trip produced %d messages, want %d", len(out), len(msgs))
	}
	if out[0].Text() != "the task" {
		t.Fatalf("user text = %q", out[0].Text())
	}
	if out[1].Content[0].Signature != "sig-1" {
		t.Fatalf("thinking signature = %q, want it restored verbatim — Anthropic validates it on replay",
			out[1].Content[0].Signature)
	}
	if string(out[1].Content[1].Input) != `{"file_path":"/x.go"}` {
		t.Fatalf("tool_use input = %q, want it unchanged", out[1].Content[1].Input)
	}
	if out[2].Content[0].Content[0].Text != "contents" {
		t.Fatalf("tool result = %q", out[2].Content[0].Content[0].Text)
	}
}

func TestReassembleDropsPrunedBlocks(t *testing.T) {
	msgs := []acllm.Message{
		userText("keep"),
		userText("drop"),
		userText("keep too"),
	}
	cores, sc := Project(msgs)
	kept := []CoreMessage{cores[0], cores[2]}
	out := Reassemble(kept, msgs, sc, ReassembleOptions{})
	if len(out) != 2 {
		t.Fatalf("got %d messages, want the pruned one dropped", len(out))
	}
	if out[0].Text() != "keep" || out[1].Text() != "keep too" {
		t.Fatalf("out = %q, %q", out[0].Text(), out[1].Text())
	}
}

// A partially pruned host message keeps only its surviving blocks.
func TestReassemblePartialMessageSurvival(t *testing.T) {
	msgs := []acllm.Message{
		assistantWith(acllm.TextBlock("explain"), toolUse("t1", "Read", `{}`)),
		toolResult("t1", "result"),
	}
	cores, sc := Project(msgs)
	// Drop the text block, keep the tool call and its result.
	out := Reassemble([]CoreMessage{cores[1], cores[2]}, msgs, sc, ReassembleOptions{})
	if len(out) != 2 {
		t.Fatalf("got %d messages, want 2", len(out))
	}
	if len(out[0].Content) != 1 || out[0].Content[0].Type != acllm.BlockToolUse {
		t.Fatalf("rebuilt assistant = %+v, want only the tool_use block", out[0].Content)
	}
}

func TestReassembleSyntheticBecomesUserMessage(t *testing.T) {
	msgs := []acllm.Message{userText("real")}
	cores, sc := Project(msgs)
	withSummary := []CoreMessage{
		{ID: SummaryMessageID("b1"), Role: RoleUser, ContentType: CTText,
			Text: SummaryHeader + "\nsummary body"},
		cores[0],
	}
	out := Reassemble(withSummary, msgs, sc, ReassembleOptions{})
	if len(out) != 2 {
		t.Fatalf("got %d messages, want the summary plus the real one", len(out))
	}
	if out[0].Role != acllm.RoleUser || !strings.HasPrefix(out[0].Text(), SummaryHeader) {
		t.Fatalf("summary message = %+v, want a user message carrying the header", out[0])
	}
}

// Rewritten tool arguments are only written back when they are still valid
// JSON; a malformed payload would break the call.
func TestReassembleRejectsInvalidToolInput(t *testing.T) {
	msgs := []acllm.Message{assistantWith(toolUse("t1", "Read", `{"file_path":"/x.go"}`)), toolResult("t1", "ok")}
	cores, sc := Project(msgs)
	cores[0].Text = `{"file_path": truncated...`
	out := Reassemble(cores, msgs, sc, ReassembleOptions{})
	if string(out[0].Content[0].Input) != `{"file_path":"/x.go"}` {
		t.Fatalf("input = %q, want the original kept when the rewrite is not valid JSON", out[0].Content[0].Input)
	}
}

func TestReassembleRepairsUnpairedToolBlocks(t *testing.T) {
	msgs := []acllm.Message{
		assistantWith(toolUse("t1", "Read", `{}`)),
		toolResult("t1", "result"),
	}
	cores, sc := Project(msgs)
	// Keep only the result — its call is gone.
	out := Reassemble([]CoreMessage{cores[1]}, msgs, sc, ReassembleOptions{})
	for _, m := range out {
		for _, b := range m.Content {
			if b.Type == acllm.BlockToolResult {
				t.Fatalf("an unpaired tool_result survived: %+v", b)
			}
		}
	}
}

func TestReassembleTagsUserAndToolResultOnly(t *testing.T) {
	msgs := []acllm.Message{
		userText("ask"),
		assistantWith(acllm.TextBlock("reply"), toolUse("t1", "Read", `{}`)),
		toolResult("t1", "output"),
	}
	cores, sc := Project(msgs)
	st := CreateInitialState("s", "/a")
	pt := ProcessTurn(ProcessTurnInput{Messages: cores, State: st, Config: DefaultConfig(200000)})

	out := Reassemble(pt.Messages, msgs, sc, ReassembleOptions{State: &pt.State, Tag: true})

	if !strings.Contains(out[0].Text(), "<noa-ref id=") {
		t.Fatalf("user message must carry a tag: %q", out[0].Text())
	}
	if strings.Contains(out[1].Text(), "noa-ref") {
		t.Fatalf("assistant message must NOT be tagged — the model echoes its own output: %q", out[1].Text())
	}
	body := out[2].Content[0].Content[0].Text
	if !strings.Contains(body, "<noa-ref id=") || !strings.Contains(body, `src="Read"`) {
		t.Fatalf("tool result tag = %q, want it tagged with its source tool", body)
	}
	// src exists only on tool output; its presence is the signal.
	if strings.Contains(out[0].Text(), "src=") {
		t.Fatalf("user text tag must omit src: %q", out[0].Text())
	}
}

// The tag number is frozen at first render: a moving number is a moving byte,
// and that invalidates the prefix cache from there on.
func TestReassembleTagTokensAreFrozen(t *testing.T) {
	msgs := []acllm.Message{userText(strings.Repeat("x", 400))}
	cores, sc := Project(msgs)
	st := CreateInitialState("s", "/a")
	pt := ProcessTurn(ProcessTurnInput{Messages: cores, State: st, Config: DefaultConfig(200000)})

	first := Reassemble(pt.Messages, msgs, sc, ReassembleOptions{State: &pt.State, Tag: true})
	firstTag := MessageRef(first[0])

	// Simulate a later truncation of the same message.
	shortened := append([]CoreMessage(nil), pt.Messages...)
	shortened[0].Text = "tiny"
	second := Reassemble(shortened, msgs, sc, ReassembleOptions{State: &pt.State, Tag: true})

	if MessageRef(second[0]) != firstTag {
		t.Fatalf("ref changed: %q -> %q", firstTag, MessageRef(second[0]))
	}
	if !strings.Contains(second[0].Text(), `tokens="100"`) {
		t.Fatalf("tag = %q, want the frozen token count (100) even though the body shrank", second[0].Text())
	}
}

func TestReassembleWithoutTagging(t *testing.T) {
	msgs := []acllm.Message{userText("ask")}
	cores, sc := Project(msgs)
	st := CreateInitialState("s", "/a")
	pt := ProcessTurn(ProcessTurnInput{Messages: cores, State: st, Config: DefaultConfig(200000)})
	out := Reassemble(pt.Messages, msgs, sc, ReassembleOptions{State: &pt.State, Tag: false})
	if strings.Contains(out[0].Text(), "noa-ref") {
		t.Fatalf("Tag=false must produce no tags: %q", out[0].Text())
	}
}

func TestStripRefTag(t *testing.T) {
	cases := map[string]string{
		"body\n<noa-ref id=\"m00001\" tokens=\"5\"/>": "body",
		// Only the trailing form is ever produced, so only it is stripped; a
		// leading one is left alone rather than risk eating user content that
		// opens with tag-shaped text.
		"<noa-ref id=\"m00001\" tokens=\"5\"/>\nbody":                 "<noa-ref id=\"m00001\" tokens=\"5\"/>\nbody",
		"body with no tag":                                            "body with no tag",
		"body\n<noa-ref id=\"m00042\" tokens=\"1.2K\" src=\"Read\"/>": "body",
	}
	for in, want := range cases {
		if got := StripRefTag(in); got != want {
			t.Errorf("StripRefTag(%q) = %q, want %q", in, got, want)
		}
	}
}

// The real contract: whatever Reassemble appends, Project removes — exactly.
func TestTagAppendStripRoundTrip(t *testing.T) {
	for _, body := range []string{
		"plain body",
		"body\nwith newlines\n",
		"中文正文 🔐",
		"",
		"body that mentions <noa-ref> in passing",
	} {
		tagged := AppendRefTag(body, RefTag("m00042", CoreMessage{ContentType: CTText}, 120))
		if got := StripRefTag(tagged); got != body {
			t.Errorf("round trip lost content:\n  body:   %q\n  tagged: %q\n  back:   %q", body, tagged, got)
		}
	}
}

// The regexes anchor on the id format as well as the element name, so a
// <noa-ref> appearing inside a file the agent read is left alone.
func TestStripRefTagLeavesForeignTagsAlone(t *testing.T) {
	in := "config:\n<noa-ref id=\"user-service\"/>"
	if got := StripRefTag(in); got != in {
		t.Fatalf("StripRefTag mangled a foreign tag: %q", got)
	}
}

// The archive tag must not be mistaken for a ref tag.
func TestStripRefTagLeavesArchiveTagAlone(t *testing.T) {
	in := SummaryHeader + "\nsummary\n\n" +
		ArchiveTag(CompressionBlock{BlockID: "b1", Tier: 1, StartRef: "m00001", EndRef: "m00009", ArchivePath: "/p.md"})
	if got := StripRefTag(in); got != in {
		t.Fatalf("StripRefTag stripped the archive tag: %q", got)
	}
}
