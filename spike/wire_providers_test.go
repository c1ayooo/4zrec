package spike

// V1/V2/V7 spike: eino-ext claude & openai providers against mock wire
// endpoints — thinking/signature/usage mapping, custom HTTPClient injection,
// and request-body GetBody replayability (the quotaAwareCapture transport
// depends on it).

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudwego/eino-ext/components/model/claude"
	"github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// captureTransport records whether req.GetBody is replayable and tees bodies.
type captureTransport struct {
	base       http.RoundTripper
	getBodyOK  bool
	bodies     [][]byte
	statusCode int // if non-zero, rewrite the response status code
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.GetBody != nil {
		t.getBodyOK = true
		var buf bytes.Buffer
		if b, err := req.GetBody(); err == nil {
			buf.ReadFrom(b)
			t.bodies = append(t.bodies, buf.Bytes())
		}
	}
	resp, err := t.base.RoundTrip(req)
	if err == nil && t.statusCode != 0 {
		resp.StatusCode = t.statusCode
	}
	return resp, err
}

func sse(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, e := range events {
		w.Write([]byte(e + "\n\n"))
	}
}

func TestSpikeClaudeProviderWireMapping(t *testing.T) {
	var tr captureTransport
	tr.base = http.DefaultTransport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/messages") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		sse(w,
			`event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[],"usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":4,"cache_creation_input_tokens":2}}}`,

			`event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,

			`event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"pondering"}}`,

			`event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sigABC"}}`,

			`event: content_block_stop
data: {"type":"content_block_stop","index":0}`,

			`event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,

			`event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hello"}}`,

			`event: content_block_stop
data: {"type":"content_block_stop","index":1}`,

			`event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":25}}`,

			`event: message_stop
data: {"type":"message_stop"}`,
		)
	}))
	defer srv.Close()

	tr.statusCode = 0
	cm, err := claude.NewChatModel(context.Background(), &claude.Config{
		APIKey:  "test-key",
		Model:   "claude-test",
		BaseURL: &srv.URL,
		HTTPClient: &http.Client{Transport: &tr},
	})
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}

	// Stream path.
	sr, err := cm.Stream(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var full *schema.Message
	for {
		msg, err := sr.Recv()
		if err != nil {
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
	if full.Content != "Hello" {
		t.Errorf("content = %q, want Hello", full.Content)
	}
	if full.ReasoningContent != "pondering" {
		t.Errorf("ReasoningContent = %q, want pondering", full.ReasoningContent)
	}
	sig, ok := full.Extra["_eino_claude_thinking_signature"]
	if !ok || sig != "sigABC" {
		t.Errorf("signature Extra = %v, want sigABC", sig)
	}
	if full.ResponseMeta == nil || full.ResponseMeta.Usage == nil {
		t.Fatal("no usage in final message")
	}
	u := full.ResponseMeta.Usage
	// PromptTokens = input 10 + cache-read 4 + cache-write 2 (per provider mapping).
	if u.PromptTokens != 16 {
		t.Errorf("PromptTokens = %d, want 16", u.PromptTokens)
	}
	if u.PromptTokenDetails.CachedTokens != 4 || u.PromptTokenDetails.CacheWriteTokens != 2 {
		t.Errorf("cache tokens = read %d write %d, want 4/2", u.PromptTokenDetails.CachedTokens, u.PromptTokenDetails.CacheWriteTokens)
	}
	if u.CompletionTokens != 25 {
		t.Errorf("CompletionTokens = %d, want 25", u.CompletionTokens)
	}
	if !tr.getBodyOK {
		t.Error("claude request body not replayable via GetBody — capture tee needs its own buffering")
	}
}

func TestSpikeOpenAIProviderWireMapping(t *testing.T) {
	var tr captureTransport
	tr.base = http.DefaultTransport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		sse(w,
			`data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}]}`,

			`data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"gpt-test","choices":[{"index":0,"delta":{"reasoning_content":"chain-of-thought"}}]}`,

			`data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"gpt-test","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call1","type":"function","function":{"name":"echo","arguments":"{\"x\":1}"}}]}}]}`,

			`data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"gpt-test","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,

			`data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"gpt-test","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`,

			`data: [DONE]`,
		)
	}))
	defer srv.Close()

	cm, err := openai.NewChatModel(context.Background(), &openai.ChatModelConfig{
		APIKey:     "test-key",
		Model:      "gpt-test",
		BaseURL:    srv.URL + "/v1",
		HTTPClient: &http.Client{Transport: &tr},
	})
	if err != nil {
		t.Fatalf("NewChatModel: %v", err)
	}

	sr, err := cm.Stream(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var chunks []*schema.Message
	for {
		msg, err := sr.Recv()
		if err != nil {
			break
		}
		chunks = append(chunks, msg)
	}
	full, err := schema.ConcatMessageStream(sr)
	_ = full
	_ = err
	concat, err := schema.ConcatMessages(chunks)
	if err != nil {
		t.Fatalf("ConcatMessages: %v", err)
	}
	if concat.Content != "Hi" {
		t.Errorf("content = %q, want Hi", concat.Content)
	}
	if concat.ReasoningContent != "chain-of-thought" {
		t.Errorf("ReasoningContent = %q, want chain-of-thought", concat.ReasoningContent)
	}
	if len(concat.ToolCalls) != 1 || concat.ToolCalls[0].Function.Name != "echo" {
		t.Errorf("tool calls = %+v, want one echo call", concat.ToolCalls)
	}
	if concat.ResponseMeta == nil || concat.ResponseMeta.Usage == nil {
		t.Fatal("no usage in final message (include_usage path)")
	}
	if concat.ResponseMeta.Usage.PromptTokens != 10 || concat.ResponseMeta.Usage.CompletionTokens != 5 {
		t.Errorf("usage = %+v, want 10/5", concat.ResponseMeta.Usage)
	}
	if !tr.getBodyOK {
		t.Error("openai request body not replayable via GetBody")
	}
	_ = model.WithMaxTokens(1)
}
