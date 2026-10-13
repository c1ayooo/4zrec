package acllm

import (
	"encoding/json"
	"testing"

	"github.com/cloudwego/eino/schema"
)

// The transcript on-disk shape is frozen from the norma era. This fixture is
// the exact JSON norma wrote; decoding must keep working byte-for-byte.
const normaShapedAssistant = `{"role":"assistant","content":[
  {"type":"thinking","thinking":"ponder the input","signature":"sig==1"},
  {"type":"text","text":"running scan"},
  {"type":"tool_use","id":"toolu_01","name":"Bash","input":{"command":"ls"}}]}`

const normaShapedToolResult = `{"role":"user","content":[
  {"type":"tool_result","tool_use_id":"toolu_01","content":[{"type":"text","text":"file.txt"}],"is_error":true}]}`

func TestGoldenNormaJSONShape(t *testing.T) {
	var m Message
	if err := json.Unmarshal([]byte(normaShapedAssistant), &m); err != nil {
		t.Fatalf("assistant decode: %v", err)
	}
	if len(m.Content) != 3 || m.Content[0].Signature != "sig==1" || m.Content[2].Name != "Bash" {
		t.Fatalf("assistant decoded wrong: %+v", m)
	}
	var r Message
	if err := json.Unmarshal([]byte(normaShapedToolResult), &r); err != nil {
		t.Fatalf("tool result decode: %v", err)
	}
	if r.Content[0].ToolUseID != "toolu_01" || !r.Content[0].IsError {
		t.Fatalf("tool result decoded wrong: %+v", r)
	}
	// Round-trip through encoding keeps the same field names.
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var again Message
	if err := json.Unmarshal(out, &again); err != nil || !again.Content[0].IsError {
		t.Fatalf("re-encode lost is_error: %s", out)
	}
}

func TestToSchemaAssistantRoundTrip(t *testing.T) {
	var m Message
	_ = json.Unmarshal([]byte(normaShapedAssistant), &m)
	sm := ToSchema([]Message{m})
	if len(sm) != 1 {
		t.Fatalf("want 1 schema message, got %d", len(sm))
	}
	a := sm[0]
	if a.Role != schema.Assistant || a.Content != "running scan" {
		t.Errorf("content wrong: %+v", a)
	}
	if a.ReasoningContent != "ponder the input" {
		t.Errorf("ReasoningContent = %q", a.ReasoningContent)
	}
	if a.Extra[ExtraThinkingSignature] != "sig==1" {
		t.Errorf("signature = %v", a.Extra[ExtraThinkingSignature])
	}
	if len(a.ToolCalls) != 1 || a.ToolCalls[0].Function.Name != "Bash" {
		t.Fatalf("tool calls wrong: %+v", a.ToolCalls)
	}
	back := FromSchema(sm)
	if len(back) != 1 || back[0].Role != RoleAssistant {
		t.Fatalf("round trip role wrong: %+v", back)
	}
	b := back[0]
	if b.Content[0].Type != BlockThinking || b.Content[0].Thinking != "ponder the input" || b.Content[0].Signature != "sig==1" {
		t.Errorf("thinking block lost: %+v", b.Content[0])
	}
	if b.Content[1].Type != BlockText || b.Content[1].Text != "running scan" {
		t.Errorf("text block lost: %+v", b.Content[1])
	}
	tb := b.Content[2]
	if tb.Type != BlockToolUse || tb.ID != "toolu_01" || tb.Name != "Bash" || string(tb.Input) != `{"command":"ls"}` {
		t.Errorf("tool_use block lost: %+v", tb)
	}
}

func TestToSchemaToolResultRoundTrip(t *testing.T) {
	var r Message
	_ = json.Unmarshal([]byte(normaShapedToolResult), &r)
	sm := ToSchema([]Message{r})
	if len(sm) != 1 || sm[0].Role != schema.Tool {
		t.Fatalf("want single tool message, got %+v", sm)
	}
	if sm[0].ToolCallID != "toolu_01" || sm[0].Content != "file.txt" {
		t.Errorf("tool message wrong: %+v", sm[0])
	}
	if sm[0].Extra[ExtraIsError] != true {
		t.Errorf("is_error marker lost: %v", sm[0].Extra)
	}
	back := FromSchema(sm)
	if len(back) != 1 || back[0].Role != RoleUser {
		t.Fatalf("tool result must come back as user message: %+v", back)
	}
	tb := back[0].Content[0]
	if tb.Type != BlockToolResult || tb.ToolUseID != "toolu_01" || !tb.IsError || tb.Content[0].Text != "file.txt" {
		t.Errorf("tool_result block lost: %+v", tb)
	}
}

func TestBoundarySchemaRoundTrip(t *testing.T) {
	meta := BoundaryMeta{Trigger: "auto", PreTokens: 123456, MessagesSummarized: 42}
	dto := BoundaryMessage(meta)
	sm := ToSchema([]Message{dto})
	if len(sm) != 1 {
		t.Fatalf("boundary must survive ToSchema: %+v", sm)
	}
	if _, ok := sm[0].Extra[ExtraBoundary]; !ok {
		t.Fatalf("boundary marker missing in schema message: %+v", sm[0])
	}
	back := FromSchema(sm)
	if len(back) != 1 || !IsBoundaryMarker(back[0]) {
		t.Fatalf("boundary must survive FromSchema: %+v", back)
	}
	got, ok := ParseBoundaryMeta(back[0])
	if !ok || got.Trigger != "auto" || got.PreTokens != 123456 || got.MessagesSummarized != 42 {
		t.Errorf("boundary meta lost: %+v ok=%v", got, ok)
	}
}

func TestMessagesForAPIDropsOrphansAndBoundaries(t *testing.T) {
	msgs := []Message{
		UserText("old task"),
		{Role: RoleAssistant, Content: []ContentBlock{{Type: BlockToolUse, ID: "t1", Name: "Bash", Input: json.RawMessage(`{}`)}}},
		{Role: RoleUser, Content: []ContentBlock{ToolResultText("t1", "out", false)}},
		BoundaryMessage(BoundaryMeta{Trigger: "auto", PreTokens: 100}),
		UserText("summary of before"),
		{Role: RoleAssistant, Content: []ContentBlock{{Type: BlockToolUse, ID: "t2", Name: "Bash", Input: json.RawMessage(`{}`)}}},
		// t2's result is beyond the cut → orphaned use must drop.
		{Role: RoleUser, Content: []ContentBlock{ToolResultText("t2", "later", false)}},
		BoundaryMessage(BoundaryMeta{Trigger: "auto", PreTokens: 200}),
		UserText("second summary"),
		{Role: RoleAssistant, Content: []ContentBlock{{Type: BlockToolUse, ID: "t3", Name: "Bash", Input: json.RawMessage(`{}`)}}},
		{Role: RoleUser, Content: []ContentBlock{ToolResultText("t3", "paired after boundary", false)}},
	}
	got := MessagesForAPI(msgs)
	for _, m := range got {
		if IsBoundaryMarker(m) {
			t.Errorf("boundary marker reached the API view")
		}
		for _, b := range m.Content {
			if b.Type == BlockToolUse && b.ID == "t2" {
				t.Errorf("orphaned tool_use reached the API view")
			}
		}
	}
	// The t3 pair sits whole within the working set and must survive.
	found := false
	for _, m := range got {
		for _, b := range m.Content {
			if b.Type == BlockToolResult && b.ToolUseID == "t3" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("paired tool_result t3 must survive the cut")
	}
}

func TestUsageNormalization(t *testing.T) {
	// claude-style: PromptTokens includes cache read+write (10+4+2=16).
	u := UsageFromToken(&schema.TokenUsage{
		PromptTokens: 16, CompletionTokens: 25,
		PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 4, CacheWriteTokens: 2},
	})
	if u != (Usage{InputTokens: 10, OutputTokens: 25, CacheReadTokens: 4, CacheWriteTokens: 2}) {
		t.Fatalf("claude-style usage wrong: %+v", u)
	}
	// openai-style: cached tokens are a subset of prompt_tokens.
	u2 := UsageFromToken(&schema.TokenUsage{PromptTokens: 10, CompletionTokens: 5,
		PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 3}})
	if u2 != (Usage{InputTokens: 7, OutputTokens: 5, CacheReadTokens: 3}) {
		t.Fatalf("openai-style usage wrong: %+v", u2)
	}
	round := UsageToToken(u)
	if round.PromptTokens != 16 || round.CompletionTokens != 25 {
		t.Fatalf("UsageToToken wrong: %+v", round)
	}
}

func TestEstimateTokens(t *testing.T) {
	msgs := []Message{UserText(strings_repeat(400))}
	if got := EstimateTokens(msgs); got != 100 {
		t.Fatalf("EstimateTokens = %d, want 100", got)
	}
}

func strings_repeat(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
