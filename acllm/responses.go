package acllm

// Self-built chat model for Config.Format == FormatOpenAIResponses, ported from
// norma's wire code (llm/openai_responses.go). The OpenAI Responses API is a
// different wire protocol from Chat Completions: the system prompt is a
// top-level `instructions`, history is a flat `input` array of items (message /
// function_call / function_call_output), tools are flattened, the output cap is
// `max_output_tokens`, reasoning strength is `reasoning.effort`, and streaming
// uses many named SSE events (response.output_text.delta, …) instead of
// choices[].delta.
//
// It is stateless: store is false and the full history is sent every call, so
// it composes with the host's own transcript/compaction (no
// previous_response_id). Retry/rate-limit/per-call-defaults live in the
// decorators the factory wraps around this provider.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type responsesModel struct {
	cfg    Config
	client *http.Client
	tools  []*schema.ToolInfo
}

func newResponsesModel(cfg Config) *responsesModel {
	m := &responsesModel{cfg: cfg}
	if cfg.HTTPClient != nil {
		m.client = cfg.HTTPClient
	} else {
		m.client = http.DefaultClient
	}
	return m
}

// WithTools records the tool set on a derived copy (immutable, concurrency-safe).
func (m *responsesModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	c := *m
	c.tools = tools
	return &c, nil
}

// ---- request ----

type orReq struct {
	Model           string        `json:"model"`
	Instructions    string        `json:"instructions,omitempty"`
	Input           []orInputItem `json:"input"`
	Tools           []orTool      `json:"tools,omitempty"`
	MaxOutputTokens int           `json:"max_output_tokens,omitempty"`
	Reasoning       *orReasoning  `json:"reasoning,omitempty"`
	Temperature     *float64      `json:"temperature,omitempty"`
	Stream          bool          `json:"stream"`
	Store           bool          `json:"store"`
}

type orReasoning struct {
	Effort string `json:"effort"`
}

// orInputItem is a union: a message (Role+Content string, no Type) or a typed
// function_call / function_call_output item. omitempty keeps each shape minimal
// so the API sees exactly one well-formed variant per item.
type orInputItem struct {
	Type      string `json:"type,omitempty"`
	Role      string `json:"role,omitempty"`
	Content   string `json:"content,omitempty"`
	CallID    string `json:"call_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
	Output    string `json:"output,omitempty"`
}

type orTool struct {
	Type        string         `json:"type"` // "function"
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

func (m *responsesModel) buildBody(input []*schema.Message, tools []*schema.ToolInfo, opts []model.Option, stream bool) ([]byte, error) {
	body := orReq{
		Model:  m.cfg.Model,
		Input:  toResponsesInput(input),
		Stream: stream,
		Store:  false, // stateless: full history sent each call
	}
	// Per-call defaults ride as common options (the factory's callDefaults
	// decorator prepends the Config values; the caller's own options win).
	common := model.GetCommonOptions(nil, opts...)
	if common.MaxTokens != nil {
		body.MaxOutputTokens = *common.MaxTokens
	}
	if common.Temperature != nil {
		t := float64(*common.Temperature)
		body.Temperature = &t
	}
	// reasoning.effort is the Responses equivalent of reasoning_effort; send it
	// only when configured (norma suppressed it on per-request "disabled").
	if m.cfg.ReasoningEffort != "" {
		body.Reasoning = &orReasoning{Effort: m.cfg.ReasoningEffort}
	}
	// Tool set: WithTools binding first, then any call-time model.WithTools tools.
	all := tools
	if len(common.Tools) > 0 {
		all = append(append([]*schema.ToolInfo{}, tools...), common.Tools...)
	}
	for _, t := range all {
		params, err := toolInfoParams(t)
		if err != nil {
			return nil, fmt.Errorf("openai-responses: tool %q: %w", t.Name, err)
		}
		body.Tools = append(body.Tools, orTool{Type: "function", Name: t.Name, Description: t.Desc, Parameters: params})
	}
	// System messages become the top-level instructions (norma joinSystem:
	// non-empty segments joined with a blank line).
	var sys []string
	for _, msg := range input {
		if msg.Role == schema.System && strings.TrimSpace(msg.Content) != "" {
			sys = append(sys, strings.TrimSpace(msg.Content))
		}
	}
	body.Instructions = strings.Join(sys, "\n\n")
	return json.Marshal(body)
}

// toolInfoParams renders a ToolInfo's parameter schema as a JSON-Schema map.
// A nil ParamsOneOf means the tool takes no arguments.
func toolInfoParams(info *schema.ToolInfo) (map[string]any, error) {
	if info.ParamsOneOf == nil {
		return nil, nil
	}
	js, err := info.ParamsOneOf.ToJSONSchema()
	if err != nil {
		return nil, err
	}
	if js == nil {
		return nil, nil
	}
	raw, err := json.Marshal(js)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// toResponsesInput flattens eino messages into Responses input items: text
// becomes a role message (string content), assistant tool calls become
// function_call items, tool messages become function_call_output items.
// Thinking (ReasoningContent) is dropped on replay and compact-boundary
// carriers skipped (mirrors norma; the API manages its own reasoning state).
func toResponsesInput(msgs []*schema.Message) []orInputItem {
	var out []orInputItem
	for _, m := range msgs {
		if m == nil || m.Role == schema.System {
			continue
		}
		if _, isBoundary := m.Extra[ExtraBoundary]; isBoundary {
			continue
		}
		if m.Role == schema.Tool {
			// Tool results are function_call_output items, never role messages.
			out = append(out, orInputItem{Type: "function_call_output", CallID: m.ToolCallID, Output: m.Content})
			continue
		}
		role := string(m.Role)
		if content := messageText(m); content != "" {
			out = append(out, orInputItem{Role: role, Content: content})
		}
		if m.Role == schema.Assistant {
			for _, tc := range m.ToolCalls {
				args := tc.Function.Arguments
				if strings.TrimSpace(args) == "" {
					args = "{}"
				}
				out = append(out, orInputItem{Type: "function_call", CallID: tc.ID, Name: tc.Function.Name, Arguments: args})
			}
		}
	}
	return out
}

// messageText renders a message's content as wire text: the string content, or
// the concatenation of text parts when multimodal.
func messageText(m *schema.Message) string {
	if m.Content != "" || len(m.MultiContent) == 0 {
		return m.Content
	}
	var b strings.Builder
	for _, part := range m.MultiContent {
		if part.Type == schema.ChatMessagePartTypeText {
			b.WriteString(part.Text)
		}
	}
	return b.String()
}

func (m *responsesModel) url() string { return m.cfg.BaseURL + "/responses" }

// do performs one HTTP round-trip against /responses, returning a 200 response
// (caller reads + closes the body) or a classified error (StatusError for
// non-200). Retry/rate-limit policy lives in the decorators above.
func (m *responsesModel) do(ctx context.Context, body []byte, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.url(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer "+m.cfg.APIKey)
	req.Header.Set("accept", accept)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, &StatusError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	return resp, nil
}

// ---- streaming ----

func (m *responsesModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	body, err := m.buildBody(input, m.tools, opts, true)
	if err != nil {
		return nil, err
	}
	resp, err := m.do(ctx, body, "text/event-stream")
	if err != nil {
		return nil, err
	}
	sr, sw := schema.Pipe[*schema.Message](8)
	go func() {
		defer sw.Close()
		defer resp.Body.Close()
		scan := newSSEScanner(resp.Body)
		st := &responsesStreamState{}
		for {
			event, data, serr := scan.next()
			if serr == io.EOF {
				return
			}
			if serr != nil {
				sw.Send(nil, serr)
				return
			}
			if data == "" {
				continue
			}
			chunk, ok, perr := st.parseResponsesFrame(event, data)
			if perr != nil {
				sw.Send(nil, perr)
				return
			}
			if !ok {
				continue
			}
			if sw.Send(chunk, nil) {
				return // reader closed / cancelled
			}
		}
	}()
	return sr, nil
}

// responsesStreamState carries the streaming accumulator: which tool call index
// argument deltas belong to, and whether any tool call was emitted (drives the
// finish reason).
type responsesStreamState struct {
	toolCalls int
	current   int // index of the tool call receiving argument deltas
}

// parseResponsesFrame maps one named Responses SSE event to an eino message
// chunk, the way eino-ext providers stream: content deltas as separate
// assistant messages, tool calls merged by Index, usage on the final chunk.
// Unrecognized events (response.created, *.in_progress, item.done,
// content_part.*, …) return ok=false and are skipped.
func (st *responsesStreamState) parseResponsesFrame(event, data string) (*schema.Message, bool, error) {
	var f struct {
		Type string `json:"type"`
		// output_item.added: item carries the function_call id/name.
		Item struct {
			Type      string `json:"type"`
			CallID    string `json:"call_id"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"item"`
		Delta    string `json:"delta"` // *_text.delta / function_call_arguments.delta
		Response struct {
			Status            string `json:"status"`
			IncompleteDetails *struct {
				Reason string `json:"reason"`
			} `json:"incomplete_details"`
			Usage *orUsage `json:"usage"`
		} `json:"response"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(data), &f); err != nil {
		return nil, false, nil // tolerate keepalives / non-JSON
	}
	kind := event
	if kind == "" {
		kind = f.Type // some gateways omit the `event:` line
	}
	switch kind {
	case "response.output_item.added":
		if f.Item.Type == "function_call" {
			idx := st.toolCalls
			st.toolCalls++
			st.current = idx
			return schema.AssistantMessage("", []schema.ToolCall{{
				Index:    &idx,
				ID:       f.Item.CallID,
				Type:     "function",
				Function: schema.FunctionCall{Name: f.Item.Name},
			}}), true, nil
		}
	case "response.output_text.delta":
		if f.Delta != "" {
			return schema.AssistantMessage(f.Delta, nil), true, nil
		}
	case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
		if f.Delta != "" {
			msg := schema.AssistantMessage("", nil)
			msg.ReasoningContent = f.Delta
			return msg, true, nil
		}
	case "response.function_call_arguments.delta":
		if f.Delta != "" {
			idx := st.current
			return schema.AssistantMessage("", []schema.ToolCall{{
				Index:    &idx,
				Type:     "function",
				Function: schema.FunctionCall{Arguments: f.Delta},
			}}), true, nil
		}
	case "response.completed", "response.incomplete":
		stop := "stop"
		if st.toolCalls > 0 {
			stop = "tool_calls"
		}
		if f.Response.IncompleteDetails != nil && f.Response.IncompleteDetails.Reason == "max_output_tokens" {
			stop = "length"
		}
		msg := schema.AssistantMessage("", nil)
		msg.ResponseMeta = &schema.ResponseMeta{FinishReason: stop}
		if f.Response.Usage != nil {
			msg.ResponseMeta.Usage = f.Response.Usage.tokenUsage()
		}
		return msg, true, nil
	case "response.failed", "error":
		msg := "stream error"
		if f.Error != nil {
			msg = f.Error.Message
		}
		return nil, false, fmt.Errorf("openai-responses: %s", msg)
	}
	return nil, false, nil
}

// ---- non-streaming ----

func (m *responsesModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	body, err := m.buildBody(input, m.tools, opts, false)
	if err != nil {
		return nil, err
	}
	resp, err := m.do(ctx, body, "application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseResponsesResponse(raw)
}

type orUsage struct {
	InputTokens        int `json:"input_tokens"`
	OutputTokens       int `json:"output_tokens"`
	InputTokensDetails struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

// tokenUsage maps Responses usage onto eino's TokenUsage via the acllm
// UsageToToken semantics: input_tokens already counts the FULL input including
// cached tokens (OpenAI semantics), so the raw non-cached input is recovered by
// subtraction and PromptTokens is rebuilt as input + cache_read + cache_write —
// exactly what acllm.UsageFromToken unwinds.
func (u orUsage) tokenUsage() *schema.TokenUsage {
	in := u.InputTokens - u.InputTokensDetails.CachedTokens
	if in < 0 {
		in = 0
	}
	return UsageToToken(Usage{
		InputTokens:     in,
		OutputTokens:    u.OutputTokens,
		CacheReadTokens: u.InputTokensDetails.CachedTokens,
	})
}

// parseResponsesResponse decodes a non-streaming /responses body into a full
// assistant message: output message text → Content, reasoning summary →
// ReasoningContent, function_call → ToolCall (ID = call_id, Arguments as the
// JSON string).
func parseResponsesResponse(raw []byte) (*schema.Message, error) {
	var r struct {
		Output []struct {
			Type    string `json:"type"`
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			Summary []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"summary"`
			CallID    string `json:"call_id"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"output"`
		Status            string `json:"status"`
		IncompleteDetails *struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
		Usage *orUsage `json:"usage"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("openai-responses: decode response: %w (body: %s)", err, truncateBody(string(raw), 500))
	}
	if r.Error != nil {
		return nil, fmt.Errorf("openai-responses: %s", r.Error.Message)
	}
	var (
		text, think strings.Builder
		toolCalls   []schema.ToolCall
	)
	for _, item := range r.Output {
		switch item.Type {
		case "message":
			for _, c := range item.Content {
				if c.Type == "output_text" {
					text.WriteString(c.Text)
				}
			}
		case "reasoning":
			// A reasoning item carries its thinking in `summary` (summary_text
			// parts) and/or in `content` (reasoning_text parts) — read both;
			// taking only `summary` drops the whole turn's thinking on models
			// that fill `content`.
			for _, s := range item.Summary {
				think.WriteString(s.Text)
			}
			for _, c := range item.Content {
				if c.Type == "reasoning_text" {
					think.WriteString(c.Text)
				}
			}
		case "function_call":
			args := item.Arguments
			if strings.TrimSpace(args) == "" {
				args = "{}"
			}
			toolCalls = append(toolCalls, schema.ToolCall{
				ID:       item.CallID,
				Type:     "function",
				Function: schema.FunctionCall{Name: item.Name, Arguments: args},
			})
		}
	}
	msg := schema.AssistantMessage(text.String(), toolCalls)
	msg.ReasoningContent = think.String()
	stop := "stop"
	if len(toolCalls) > 0 {
		stop = "tool_calls"
	}
	if r.IncompleteDetails != nil && r.IncompleteDetails.Reason == "max_output_tokens" {
		stop = "length"
	}
	msg.ResponseMeta = &schema.ResponseMeta{FinishReason: stop}
	if r.Usage != nil {
		msg.ResponseMeta.Usage = r.Usage.tokenUsage()
	}
	return msg, nil
}
