package acllm

// Factory wire tests: NewChatModel against mock SSE/JSON endpoints for the
// eino-ext openai and claude adapters (pattern from spike/wire_providers_test.go),
// plus Config mapping assertions: per-call defaults, MaxTokensField selection,
// and the Anthropic thinking derivation.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// recordingTransport tees JSON request bodies for assertions.
type recordingTransport struct {
	base   http.RoundTripper
	bodies []map[string]any
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err == nil {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			t.bodies = append(t.bodies, m)
			req.Body = io.NopCloser(bytes.NewReader(raw))
		}
	}
	return t.base.RoundTrip(req)
}

func (t *recordingTransport) last() map[string]any {
	if len(t.bodies) == 0 {
		return nil
	}
	return t.bodies[len(t.bodies)-1]
}

func (t *recordingTransport) count() int { return len(t.bodies) }

func newRecordingClient() (*recordingTransport, *http.Client) {
	tr := &recordingTransport{base: http.DefaultTransport}
	return tr, &http.Client{Transport: tr}
}

func sse(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, e := range events {
		w.Write([]byte(e + "\n\n"))
	}
}

// collectStream folds a stream into one message (spike pattern).
func collectStream(t *testing.T, sr *schema.StreamReader[*schema.Message]) *schema.Message {
	t.Helper()
	var full *schema.Message
	for {
		msg, err := sr.Recv()
		if err != nil {
			sr.Close()
			break
		}
		if full == nil {
			full = msg
		} else {
			full, err = schema.ConcatMessages([]*schema.Message{full, msg})
			if err != nil {
				t.Fatalf("ConcatMessages: %v", err)
			}
		}
	}
	if full == nil {
		t.Fatal("no stream messages")
	}
	return full
}

// ---- openai fixtures ----

const openAISSEBody = `data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}]}

data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"gpt-test","choices":[{"index":0,"delta":{"reasoning_content":"chain-of-thought"}}]}

data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"gpt-test","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call1","type":"function","function":{"name":"echo","arguments":"{\"x\":1}"}}]}}]}

data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"gpt-test","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}

data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"gpt-test","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}

data: [DONE]

`

const openAICompleteJSON = `{"id":"1","object":"chat.completion","created":1,"model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there","reasoning_content":"deep thought","tool_calls":[{"id":"call1","type":"function","function":{"name":"echo","arguments":"{\"x\":2}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":12,"completion_tokens":7,"total_tokens":19}}`

func newOpenAIMock(t *testing.T) (*httptest.Server, *recordingTransport, *http.Client) {
	tr, client := newRecordingClient()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if body["stream"] == true {
			sse(w, openAISSEBody)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(openAICompleteJSON))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, tr, client
}

func openAIConfig(srv *httptest.Server, client *http.Client, mutate func(*Config)) Config {
	temp := 0.5
	cfg := Config{
		Format:      FormatOpenAI,
		BaseURL:     srv.URL + "/v1",
		APIKey:      "test-key",
		Model:       "gpt-test",
		MaxTokens:   512,
		Temperature: &temp,
		Stop:        []string{"END"},
		HTTPClient:  client,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

func TestFactoryOpenAIWire(t *testing.T) {
	srv, tr, client := newOpenAIMock(t)
	cm, err := NewChatModel(context.Background(), openAIConfig(srv, client, nil))
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}

	// Stream path: content / reasoning / tool call / usage, through the factory.
	sr, err := cm.Stream(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	full := collectStream(t, sr)
	if full.Content != "Hi" {
		t.Errorf("content = %q, want Hi", full.Content)
	}
	if full.ReasoningContent != "chain-of-thought" {
		t.Errorf("ReasoningContent = %q", full.ReasoningContent)
	}
	if len(full.ToolCalls) != 1 || full.ToolCalls[0].Function.Name != "echo" || full.ToolCalls[0].Function.Arguments != `{"x":1}` {
		t.Errorf("tool calls = %+v", full.ToolCalls)
	}
	if full.ResponseMeta == nil || full.ResponseMeta.Usage == nil ||
		full.ResponseMeta.Usage.PromptTokens != 10 || full.ResponseMeta.Usage.CompletionTokens != 5 {
		t.Fatalf("usage wrong: %+v", full.ResponseMeta)
	}

	// Config mapping reached the wire: model, per-call max_tokens/temperature/stop.
	b := tr.last()
	if b["model"] != "gpt-test" || b["stream"] != true {
		t.Fatalf("request body wrong: %v", b)
	}
	if b["max_tokens"] != float64(512) {
		t.Errorf("max_tokens = %v, want 512 (per-call default)", b["max_tokens"])
	}
	if b["temperature"] != 0.5 {
		t.Errorf("temperature = %v, want 0.5 (per-call default)", b["temperature"])
	}
	if stop, ok := b["stop"].([]any); !ok || len(stop) != 1 || stop[0] != "END" {
		t.Errorf("stop = %v, want [END]", b["stop"])
	}

	// Generate path (stream:false on the wire).
	msg, err := cm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if msg.Content != "Hi there" || msg.ReasoningContent != "deep thought" {
		t.Fatalf("generate message wrong: %+v", msg)
	}
	if len(msg.ToolCalls) != 1 || msg.ToolCalls[0].Function.Arguments != `{"x":2}` {
		t.Fatalf("generate tool calls wrong: %+v", msg.ToolCalls)
	}
	if msg.ResponseMeta == nil || msg.ResponseMeta.FinishReason != "tool_calls" ||
		msg.ResponseMeta.Usage.PromptTokens != 12 || msg.ResponseMeta.Usage.CompletionTokens != 7 {
		t.Fatalf("generate meta wrong: %+v", msg.ResponseMeta)
	}
	if tr.last()["stream"] == true {
		t.Errorf("Generate must not stream, got stream=%v", tr.last()["stream"])
	}

	// A caller's explicit option wins over the Config-derived default.
	if _, err := cm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")},
		model.WithTemperature(0.9)); err != nil {
		t.Fatalf("Generate override: %v", err)
	}
	if got := tr.last()["temperature"]; got != 0.9 {
		t.Errorf("caller temperature override lost: %v, want 0.9", got)
	}
}

func TestFactoryOpenAIMaxTokensField(t *testing.T) {
	srv, tr, client := newOpenAIMock(t)
	// max_completion_tokens: the cap is config-level in the adapter; no
	// per-call max_tokens default is injected (norma sends exactly one key).
	cm, err := NewChatModel(context.Background(), openAIConfig(srv, client, func(c *Config) {
		c.MaxTokens, c.MaxTokensField = 256, MaxTokensFieldCompletion
	}))
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}
	if _, err := cm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b := tr.last()
	if b["max_completion_tokens"] != float64(256) {
		t.Errorf("max_completion_tokens = %v, want 256", b["max_completion_tokens"])
	}
	if _, present := b["max_tokens"]; present {
		t.Errorf("max_tokens must not be sent alongside max_completion_tokens: %v", b)
	}

	// Default field: classic max_tokens via the per-call default.
	srv2, tr2, client2 := newOpenAIMock(t)
	cm2, err := NewChatModel(context.Background(), openAIConfig(srv2, client2, nil))
	if err != nil {
		t.Fatalf("NewChatModel(2): %v", err)
	}
	if _, err := cm2.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
		t.Fatalf("Generate(2): %v", err)
	}
	if b2 := tr2.last(); b2["max_tokens"] != float64(512) {
		t.Errorf("max_tokens = %v, want 512", b2["max_tokens"])
	}
}

// WithTools must flow through the factory decorators untouched.
func TestFactoryOpenAIWithTools(t *testing.T) {
	srv, tr, client := newOpenAIMock(t)
	cm, err := NewChatModel(context.Background(), openAIConfig(srv, client, nil))
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}
	info, err := ToolSchemaToInfo(ToolSchema{
		Name:        "echo",
		Description: "echo the input",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"x": map[string]any{"type": "number"}}},
	})
	if err != nil {
		t.Fatalf("ToolSchemaToInfo: %v", err)
	}
	withTools, err := cm.WithTools([]*schema.ToolInfo{info})
	if err != nil {
		t.Fatalf("WithTools: %v", err)
	}
	msg, err := withTools.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if msg.Content != "Hi there" {
		t.Fatalf("with-tools generate broken: %+v", msg)
	}
	tools, ok := tr.last()["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools missing in request: %v", tr.last())
	}
	fn := tools[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "echo" {
		t.Errorf("tool name = %v, want echo", fn["name"])
	}
}

// ---- anthropic fixtures ----

const anthropicSSEEvents = `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[],"usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":4,"cache_creation_input_tokens":2}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"pondering"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sigABC"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":25}}

event: message_stop
data: {"type":"message_stop"}

`

const anthropicCompleteJSON = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[{"type":"thinking","thinking":"pondering","signature":"sigABC"},{"type":"text","text":"Hello"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls"}}],"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":25,"cache_read_input_tokens":4,"cache_creation_input_tokens":2}}`

func newAnthropicMock(t *testing.T) (*httptest.Server, *recordingTransport, *http.Client) {
	tr, client := newRecordingClient()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/messages") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if body["stream"] == true {
			sse(w, anthropicSSEEvents)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(anthropicCompleteJSON))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, tr, client
}

func TestFactoryAnthropicWire(t *testing.T) {
	srv, tr, client := newAnthropicMock(t)
	cm, err := NewChatModel(context.Background(), Config{
		Format:       FormatAnthropic,
		BaseURL:      srv.URL,
		APIKey:       "test-key",
		Model:        "claude-test",
		ThinkingType: "enabled",
		MaxTokens:    8192,
		HTTPClient:   client,
	})
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}

	// Stream path.
	sr, err := cm.Stream(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	full := collectStream(t, sr)
	if full.Content != "Hello" {
		t.Errorf("content = %q, want Hello", full.Content)
	}
	if full.ReasoningContent != "pondering" {
		t.Errorf("ReasoningContent = %q", full.ReasoningContent)
	}
	if sig, ok := full.Extra[ExtraThinkingSignature]; !ok || sig != "sigABC" {
		t.Errorf("signature Extra = %v", sig)
	}
	if full.ResponseMeta == nil || full.ResponseMeta.Usage == nil {
		t.Fatal("no usage in streamed message")
	}
	u := full.ResponseMeta.Usage
	// PromptTokens = input 10 + cache-read 4 + cache-write 2.
	if u.PromptTokens != 16 || u.CompletionTokens != 25 ||
		u.PromptTokenDetails.CachedTokens != 4 || u.PromptTokenDetails.CacheWriteTokens != 2 {
		t.Fatalf("usage wrong: %+v", u)
	}

	// Config mapping: thinking derivation (half of max_tokens 8192, min 1024),
	// the always-required max_tokens (norma default), model.
	b := tr.last()
	th, ok := b["thinking"].(map[string]any)
	if !ok || th["type"] != "enabled" {
		t.Fatalf("thinking = %v, want enabled", b["thinking"])
	}
	if th["budget_tokens"] != float64(4096) {
		t.Errorf("budget_tokens = %v, want 4096 (8192/2)", th["budget_tokens"])
	}
	if b["max_tokens"] != float64(8192) {
		t.Errorf("max_tokens = %v, want 8192 (per-call default)", b["max_tokens"])
	}
	if b["model"] != "claude-test" {
		t.Errorf("model = %v", b["model"])
	}

	// Generate path.
	msg, err := cm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if msg.Content != "Hello" || msg.ReasoningContent != "pondering" {
		t.Fatalf("generate message wrong: %+v", msg)
	}
	if len(msg.ToolCalls) != 1 || msg.ToolCalls[0].ID != "toolu_1" || msg.ToolCalls[0].Function.Name != "Bash" ||
		msg.ToolCalls[0].Function.Arguments != `{"command":"ls"}` {
		t.Fatalf("generate tool calls wrong: %+v", msg.ToolCalls)
	}
	if msg.ResponseMeta == nil || msg.ResponseMeta.FinishReason != "tool_use" ||
		msg.ResponseMeta.Usage.PromptTokens != 16 || msg.ResponseMeta.Usage.CompletionTokens != 25 {
		t.Fatalf("generate meta wrong: %+v", msg.ResponseMeta)
	}
}

func TestFactoryAnthropicThinkingVariants(t *testing.T) {
	cases := []struct {
		name         string
		thinkingType string
		maxTokens    int
		wantThinking bool
		wantType     any
		wantBudget   any
	}{
		{"unset omits", "", 0, false, nil, nil},
		{"disabled omits", "disabled", 0, false, nil, nil},
		{"enabled derives budget", "enabled", 0, true, "enabled", float64(4096)},     // 8192 default / 2
		{"enabled small max", "enabled", 3000, true, "enabled", float64(1500)},       // 3000/2
		{"enabled tiny max floors", "enabled", 1000, true, "enabled", float64(1024)}, // min 1024
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, tr, client := newAnthropicMock(t)
			cm, err := NewChatModel(context.Background(), Config{
				Format:       FormatAnthropic,
				BaseURL:      srv.URL,
				APIKey:       "k",
				Model:        "claude-test",
				ThinkingType: tc.thinkingType,
				MaxTokens:    tc.maxTokens,
				HTTPClient:   client,
			})
			if err != nil {
				t.Fatalf("NewChatModel: %v", err)
			}
			if _, err := cm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
				t.Fatalf("Generate: %v", err)
			}
			b := tr.last()
			th, present := b["thinking"].(map[string]any)
			if tc.wantThinking {
				if !present || th["type"] != tc.wantType || th["budget_tokens"] != tc.wantBudget {
					t.Fatalf("thinking = %v, want type %v budget %v", b["thinking"], tc.wantType, tc.wantBudget)
				}
				wantMax := tc.maxTokens
				if wantMax <= 0 {
					wantMax = 8192
				}
				if b["max_tokens"] != float64(wantMax) {
					t.Errorf("max_tokens = %v, want %d", b["max_tokens"], wantMax)
				}
			} else if present {
				t.Fatalf("thinking must be omitted for %q, got %v", tc.thinkingType, b["thinking"])
			}
		})
	}
}
