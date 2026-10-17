package acllm

// Tests for the self-built OpenAI Responses provider (FormatOpenAIResponses):
// SSE streaming and non-streaming /responses against a mock server, covering
// reasoning/text deltas, function_call assembly, usage round-trip, the
// stateless request shape, and WithTools plumbing.

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

func responsesSSEBody() string {
	frames := []string{
		`event: response.created` + "\n" + `data: {"type":"response.created"}`,
		`event: response.reasoning_summary_text.delta` + "\n" + `data: {"type":"response.reasoning_summary_text.delta","delta":"thinking…"}`,
		`event: response.output_text.delta` + "\n" + `data: {"type":"response.output_text.delta","delta":"Hello "}`,
		`event: response.output_text.delta` + "\n" + `data: {"type":"response.output_text.delta","delta":"world"}`,
		`event: response.output_item.added` + "\n" + `data: {"type":"response.output_item.added","item":{"type":"function_call","call_id":"call_1","name":"Read"}}`,
		`event: response.function_call_arguments.delta` + "\n" + `data: {"type":"response.function_call_arguments.delta","delta":"{\"file_path\":\"a\"}"}`,
		`event: response.completed` + "\n" + `data: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":11,"output_tokens":6,"input_tokens_details":{"cached_tokens":3}}}}`,
	}
	return strings.Join(frames, "\n\n") + "\n\n"
}

const responsesCompleteJSON = `{"status":"completed","output":[{"type":"reasoning","summary":[{"type":"summary_text","text":"hmm"}]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi"}]},{"type":"function_call","call_id":"c9","name":"Bash","arguments":"{\"command\":\"ls\"}"}],"usage":{"input_tokens":10,"output_tokens":5,"input_tokens_details":{"cached_tokens":2}}}`

func newResponsesMock(t *testing.T) (*httptest.Server, *recordingTransport, *http.Client) {
	tr, client := newRecordingClient()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("path = %q, want /responses", r.URL.Path)
		}
		if auth := r.Header.Get("authorization"); auth != "Bearer k" {
			t.Errorf("authorization = %q", auth)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if body["stream"] == true {
			sse(w, responsesSSEBody())
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(responsesCompleteJSON))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, tr, client
}

func responsesConfig(srv *httptest.Server, client *http.Client) Config {
	return Config{
		Format:     FormatOpenAIResponses,
		BaseURL:    srv.URL,
		APIKey:     "k",
		Model:      "gpt-test",
		HTTPClient: client,
	}
}

func TestResponsesStream(t *testing.T) {
	srv, tr, client := newResponsesMock(t)
	cm, err := NewChatModel(context.Background(), responsesConfig(srv, client))
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}
	cm, err = cm.WithTools([]*schema.ToolInfo{{Name: "Read", Desc: "read a file"}})
	if err != nil {
		t.Fatalf("WithTools: %v", err)
	}

	sr, err := cm.Stream(context.Background(), []*schema.Message{
		schema.SystemMessage("be brief"),
		schema.UserMessage("go"),
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var chunks []*schema.Message
	for {
		msg, err := sr.Recv()
		if err != nil {
			sr.Close()
			break
		}
		chunks = append(chunks, msg)
	}
	if len(chunks) < 4 {
		t.Fatalf("want >=4 chunks (deltas + final), got %d", len(chunks))
	}

	// Chunk order follows the fixture: reasoning delta, two text deltas, tool
	// call start, argument delta, final chunk with usage.
	if chunks[0].ReasoningContent != "thinking…" || chunks[0].Content != "" {
		t.Errorf("chunk0 = %+v, want reasoning delta", chunks[0])
	}
	if chunks[1].Content != "Hello " || chunks[1].ReasoningContent != "" {
		t.Errorf("chunk1 = %+v, want text delta %q", chunks[1], "Hello ")
	}
	if chunks[2].Content != "world" {
		t.Errorf("chunk2 content = %q, want world", chunks[2].Content)
	}
	full := collectStream(t, streamFrom(chunks))
	if full.Content != "Hello world" {
		t.Errorf("content = %q, want %q", full.Content, "Hello world")
	}
	if full.ReasoningContent != "thinking…" {
		t.Errorf("ReasoningContent = %q, want thinking…", full.ReasoningContent)
	}
	if len(full.ToolCalls) != 1 || full.ToolCalls[0].ID != "call_1" ||
		full.ToolCalls[0].Function.Name != "Read" || full.ToolCalls[0].Function.Arguments != `{"file_path":"a"}` {
		t.Errorf("tool calls = %+v", full.ToolCalls)
	}
	// Usage on the final chunk; PromptTokens = 11 (input incl. cache), cached 3.
	last := chunks[len(chunks)-1]
	if last.ResponseMeta == nil || last.ResponseMeta.Usage == nil {
		t.Fatal("no usage on final chunk")
	}
	u := last.ResponseMeta.Usage
	if u.PromptTokens != 11 || u.CompletionTokens != 6 || u.PromptTokenDetails.CachedTokens != 3 || u.TotalTokens != 17 {
		t.Errorf("usage = %+v, want 11/6 cached 3 total 17", u)
	}
	if got := UsageFromToken(u); got != (Usage{InputTokens: 8, OutputTokens: 6, CacheReadTokens: 3}) {
		t.Errorf("UsageFromToken round trip = %+v", got)
	}
	if last.ResponseMeta.FinishReason != "tool_calls" {
		t.Errorf("FinishReason = %q, want tool_calls", last.ResponseMeta.FinishReason)
	}

	// Request shape: stateless, instructions from system, tools flattened.
	b := tr.last()
	if b["store"] != false || b["stream"] != true {
		t.Errorf("store/stream = %v/%v, want false/true", b["store"], b["stream"])
	}
	if b["instructions"] != "be brief" {
		t.Errorf("instructions = %v", b["instructions"])
	}
	if b["model"] != "gpt-test" {
		t.Errorf("model = %v", b["model"])
	}
	tools, ok := b["tools"].([]any)
	if !ok || len(tools) != 1 || tools[0].(map[string]any)["name"] != "Read" {
		t.Errorf("tools = %v, want one Read tool", b["tools"])
	}
	input, ok := b["input"].([]any)
	if !ok || len(input) != 1 || input[0].(map[string]any)["content"] != "go" {
		t.Errorf("input = %v, want one user item", b["input"])
	}
}

// streamFrom wraps an in-memory chunk slice into a StreamReader for collectStream.
func streamFrom(chunks []*schema.Message) *schema.StreamReader[*schema.Message] {
	sr, sw := schema.Pipe[*schema.Message](len(chunks))
	go func() {
		defer sw.Close()
		for _, c := range chunks {
			sw.Send(c, nil)
		}
	}()
	return sr
}

func TestResponsesGenerate(t *testing.T) {
	srv, tr, client := newResponsesMock(t)
	temp := 0.3
	cfg := responsesConfig(srv, client)
	cfg.MaxTokens = 777
	cfg.Temperature = &temp
	cfg.ReasoningEffort = "low"
	cm, err := NewChatModel(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}

	msg, err := cm.Generate(context.Background(), []*schema.Message{
		schema.SystemMessage("sys"),
		schema.UserMessage("go"),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if msg.Content != "Hi" {
		t.Errorf("content = %q, want Hi", msg.Content)
	}
	if msg.ReasoningContent != "hmm" {
		t.Errorf("ReasoningContent = %q, want hmm", msg.ReasoningContent)
	}
	if len(msg.ToolCalls) != 1 || msg.ToolCalls[0].ID != "c9" || msg.ToolCalls[0].Function.Name != "Bash" ||
		msg.ToolCalls[0].Function.Arguments != `{"command":"ls"}` {
		t.Fatalf("tool calls = %+v", msg.ToolCalls)
	}
	if msg.ResponseMeta == nil || msg.ResponseMeta.FinishReason != "tool_calls" {
		t.Fatalf("meta = %+v", msg.ResponseMeta)
	}
	u := msg.ResponseMeta.Usage
	if u.PromptTokens != 10 || u.CompletionTokens != 5 || u.PromptTokenDetails.CachedTokens != 2 {
		t.Errorf("usage = %+v, want 10/5 cached 2", u)
	}
	if got := UsageFromToken(u); got != (Usage{InputTokens: 8, OutputTokens: 5, CacheReadTokens: 2}) {
		t.Errorf("UsageFromToken round trip = %+v", got)
	}

	// Non-streaming request shape: stream:false, per-call options applied,
	// reasoning effort mapped, tool_result history → function_call_output.
	b := tr.last()
	if b["stream"] != false || b["store"] != false {
		t.Errorf("stream/store = %v/%v, want false/false", b["stream"], b["store"])
	}
	if b["max_output_tokens"] != float64(777) {
		t.Errorf("max_output_tokens = %v, want 777", b["max_output_tokens"])
	}
	// Temperature rides as float32 through eino's common options; compare loosely.
	if temp, ok := b["temperature"].(float64); !ok || math.Abs(temp-0.3) > 1e-6 {
		t.Errorf("temperature = %v, want 0.3", b["temperature"])
	}
	reasoning, ok := b["reasoning"].(map[string]any)
	if !ok || reasoning["effort"] != "low" {
		t.Errorf("reasoning = %v, want effort low", b["reasoning"])
	}
	instructions, _ := b["instructions"].(string)
	if instructions != "sys" {
		t.Errorf("instructions = %q, want sys", instructions)
	}
}

func TestResponsesInputMapping(t *testing.T) {
	srv, tr, client := newResponsesMock(t)
	cm, err := NewChatModel(context.Background(), responsesConfig(srv, client))
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}
	// History with an assistant tool call and its result: function_call +
	// function_call_output items, thinking dropped, boundary carriers skipped.
	history := ToSchema([]Message{
		UserText("go"),
		{Role: RoleAssistant, Content: []ContentBlock{
			{Type: BlockThinking, Thinking: "SECRET"},
			TextBlock("calling"),
			{Type: BlockToolUse, ID: "c1", Name: "Bash", Input: []byte(`{"command":"ls"}`)},
		}},
		{Role: RoleUser, Content: []ContentBlock{ToolResultText("c1", "file.txt", false)}},
		BoundaryMessage(BoundaryMeta{Trigger: "auto", PreTokens: 1}),
		UserText("after boundary"),
	})
	if _, err := cm.Generate(context.Background(), history); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	input := tr.last()["input"].([]any)
	// user text, assistant text, function_call, function_call_output, user text.
	if len(input) != 5 {
		t.Fatalf("input items = %d: %v", len(input), input)
	}
	types := make([]string, len(input))
	for i, it := range input {
		m := it.(map[string]any)
		types[i], _ = m["type"].(string)
		if s, _ := m["content"].(string); strings.Contains(s, "SECRET") {
			t.Errorf("thinking leaked into item %d: %v", i, m)
		}
	}
	want := []string{"", "", "function_call", "function_call_output", ""}
	for i, w := range want {
		if types[i] != w {
			t.Errorf("item %d type = %q, want %q", i, types[i], w)
		}
	}
	fc := input[2].(map[string]any)
	if fc["call_id"] != "c1" || fc["name"] != "Bash" || fc["arguments"] != `{"command":"ls"}` {
		t.Errorf("function_call = %v", fc)
	}
	fco := input[3].(map[string]any)
	if fco["call_id"] != "c1" || fco["output"] != "file.txt" {
		t.Errorf("function_call_output = %v", fco)
	}
}

func TestResponsesErrorEvent(t *testing.T) {
	tr, client := newRecordingClient()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sse(w, "event: response.failed\ndata: {\"type\":\"response.failed\",\"error\":{\"message\":\"boom\"}}")
	}))
	defer srv.Close()
	cm, err := NewChatModel(context.Background(), Config{
		Format: FormatOpenAIResponses, BaseURL: srv.URL, APIKey: "k", Model: "m",
		HTTPClient: client, MaxRetries: -1, // no retry: assert the error surfaces as-is
	})
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}
	sr, err := cm.Stream(context.Background(), []*schema.Message{schema.UserMessage("go")})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var gotErr error
	for {
		_, err := sr.Recv()
		if err != nil {
			gotErr = err
			sr.Close()
			break
		}
	}
	if gotErr == nil || !strings.Contains(gotErr.Error(), "boom") {
		t.Fatalf("want stream error boom, got %v", gotErr)
	}
	if tr.count() != 1 {
		t.Errorf("stream error must not be retried, requests = %d", tr.count())
	}
}

// A caller's explicit model options win over the Config-derived defaults.
func TestResponsesCallerOptionWins(t *testing.T) {
	srv, tr, client := newResponsesMock(t)
	temp := 0.5
	cfg := responsesConfig(srv, client)
	cfg.Temperature = &temp
	cfg.MaxTokens = 100
	cm, err := NewChatModel(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}
	if _, err := cm.Generate(context.Background(), []*schema.Message{schema.UserMessage("go")},
		model.WithTemperature(0.9), model.WithMaxTokens(42)); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b := tr.last()
	if temp, ok := b["temperature"].(float64); !ok || math.Abs(temp-0.9) > 1e-6 {
		t.Errorf("caller options lost: temperature=%v max=%v", b["temperature"], b["max_output_tokens"])
	} else if b["max_output_tokens"] != float64(42) {
		t.Errorf("caller options lost: max_output_tokens=%v, want 42", b["max_output_tokens"])
	}
}
