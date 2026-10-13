package acllm

import (
	"encoding/json"

	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
)

// schema-side markers. eino's schema.Message carries no error flag on tool
// messages and no compaction-boundary concept, so both ride in Extra under
// these keys. Thinking replay for the eino-ext claude provider deliberately
// uses the provider's own Extra keys (see toSchemaAssistant).
const (
	// ExtraIsError marks a tool message whose result was an error.
	ExtraIsError = "_acllm_is_error"
	// ExtraBoundary marks a compact-boundary carrier message; the value is a
	// JSON-encoded BoundaryMeta.
	ExtraBoundary = "_acllm_compact_boundary"
	// ExtraThinkingSignature carries the Anthropic thinking signature on
	// assistant messages (mirrors the eino-ext claude provider's key so replay
	// round-trips through it).
	ExtraThinkingSignature = "_eino_claude_thinking_signature"
	// ExtraThinking carries the raw thinking text for claude replay.
	ExtraThinking = "_eino_claude_thinking"
)

// ToSchema converts DTO history into eino runtime messages. A DTO user message
// carrying tool_result blocks splits into separate schema tool messages (eino
// models tool results as role=tool messages, one per tool call); text rides in
// a user message. Thinking replays via the claude provider's Extra keys.
//
// Known fidelity limit (accepted drift): a DTO assistant message with several
// interleaved thinking blocks collapses into one ReasoningContent with the last
// block's signature — Anthropic interleaved-thinking replay across a resume of
// such a turn may be rejected by the API. Normal turns (thinking → tool_use →
// text) round-trip exactly.
func ToSchema(msgs []Message) []*schema.Message {
	out := make([]*schema.Message, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case RoleAssistant:
			if s := toSchemaAssistant(m); s != nil {
				out = append(out, s)
			}
		case RoleUser:
			out = append(out, toSchemaUser(m)...)
		}
	}
	return out
}

func toSchemaAssistant(m Message) *schema.Message {
	var (
		thinkBuf, textBuf string
		sig               string
		toolCalls         []schema.ToolCall
	)
	for _, b := range m.Content {
		switch b.Type {
		case BlockThinking:
			if thinkBuf != "" {
				thinkBuf += "\n"
			}
			thinkBuf += b.Thinking
			if b.Signature != "" {
				sig = b.Signature
			}
		case BlockText:
			textBuf += b.Text
		case BlockToolUse:
			args := string(b.Input)
			if args == "" || !json.Valid([]byte(args)) {
				args = "{}"
			}
			toolCalls = append(toolCalls, schema.ToolCall{
				ID:       b.ID,
				Function: schema.FunctionCall{Name: b.Name, Arguments: args},
			})
		}
	}
	sm := schema.AssistantMessage(textBuf, toolCalls)
	if thinkBuf != "" {
		sm.ReasoningContent = thinkBuf
		if sm.Extra == nil {
			sm.Extra = map[string]any{}
		}
		sm.Extra[ExtraThinking] = thinkBuf
		if sig != "" {
			sm.Extra[ExtraThinkingSignature] = sig
		}
	}
	if len(sm.Content) == 0 && len(toolCalls) == 0 && thinkBuf == "" {
		return nil
	}
	return sm
}

func toSchemaUser(m Message) []*schema.Message {
	var out []*schema.Message
	var textBuf string
	flush := func() {
		if textBuf != "" {
			out = append(out, schema.UserMessage(textBuf))
			textBuf = ""
		}
	}
	for _, b := range m.Content {
		switch b.Type {
		case BlockText:
			textBuf += b.Text
		case BlockToolResult:
			flush()
			out = append(out, toolResultSchema(b))
		case BlockCompactBoundary:
			flush()
			payload, _ := json.Marshal(m)
			out = append(out, &schema.Message{
				Role:  schema.User,
				Extra: map[string]any{ExtraBoundary: json.RawMessage(payload)},
			})
		}
	}
	flush()
	return out
}

func toolResultSchema(b ContentBlock) *schema.Message {
	var text string
	for i, cb := range b.Content {
		if i > 0 {
			text += "\n"
		}
		text += cb.Text
	}
	sm := schema.ToolMessage(text, b.ToolUseID)
	if b.IsError {
		if sm.Extra == nil {
			sm.Extra = map[string]any{}
		}
		sm.Extra[ExtraIsError] = true
	}
	return sm
}

// FromSchema converts eino runtime messages back into DTO history (resume
// seeding, transcript writing). System messages are skipped — ARTEX keeps the
// system prompt outside the message array, as before.
func FromSchema(msgs []*schema.Message) []Message {
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case schema.Assistant:
			out = append(out, fromSchemaAssistant(m))
		case schema.User:
			if meta, ok := boundaryExtra(m); ok {
				out = append(out, BoundaryMessage(meta))
				continue
			}
			out = append(out, UserText(m.Content))
		case schema.Tool:
			out = append(out, fromSchemaTool(m))
		}
	}
	return out
}

func fromSchemaAssistant(m *schema.Message) Message {
	var blocks []ContentBlock
	if m.ReasoningContent != "" {
		sig, _ := m.Extra[ExtraThinkingSignature].(string)
		blocks = append(blocks, ContentBlock{Type: BlockThinking, Thinking: m.ReasoningContent, Signature: sig})
	}
	if m.Content != "" {
		blocks = append(blocks, TextBlock(m.Content))
	}
	for _, tc := range m.ToolCalls {
		blocks = append(blocks, ContentBlock{
			Type:  BlockToolUse,
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: json.RawMessage(tc.Function.Arguments),
		})
	}
	if len(blocks) == 0 {
		blocks = []ContentBlock{TextBlock("")}
	}
	return Message{Role: RoleAssistant, Content: blocks}
}

func fromSchemaTool(m *schema.Message) Message {
	isErr, _ := m.Extra[ExtraIsError].(bool)
	return Message{Role: RoleUser, Content: []ContentBlock{
		ToolResultText(m.ToolCallID, m.Content, isErr),
	}}
}

func boundaryExtra(m *schema.Message) (BoundaryMeta, bool) {
	raw, ok := m.Extra[ExtraBoundary]
	if !ok {
		return BoundaryMeta{}, false
	}
	var stored Message
	if err := json.Unmarshal(mustJSON(raw), &stored); err != nil {
		return BoundaryMeta{}, false
	}
	return ParseBoundaryMeta(stored)
}

func mustJSON(v any) []byte {
	switch t := v.(type) {
	case json.RawMessage:
		return t
	case []byte:
		return t
	case string:
		return []byte(t)
	}
	b, _ := json.Marshal(v)
	return b
}

// ToolSchemaToInfo converts a DTO tool definition into eino's ToolInfo for
// model.WithTools: name and description verbatim, the JSON-schema input schema
// carried as ParamsOneOf. A tool without an input schema yields a ToolInfo with
// nil ParamsOneOf (eino's "no parameters" signal).
func ToolSchemaToInfo(ts ToolSchema) (*schema.ToolInfo, error) {
	info := &schema.ToolInfo{Name: ts.Name, Desc: ts.Description}
	if len(ts.InputSchema) > 0 {
		raw, err := json.Marshal(ts.InputSchema)
		if err != nil {
			return nil, err
		}
		var js jsonschema.Schema
		if err := json.Unmarshal(raw, &js); err != nil {
			return nil, err
		}
		info.ParamsOneOf = schema.NewParamsOneOfByJSONSchema(&js)
	}
	return info, nil
}

// UsageFromToken normalizes an eino TokenUsage into the DTO Usage. eino's
// PromptTokens is total prompt tokens INCLUDING cache reads/writes for both
// providers (the claude adapter adds them in; OpenAI's prompt_tokens already
// includes cached tokens), so the raw non-cache input is recovered by
// subtraction — matching what norma recorded in ledgers and UI.
func UsageFromToken(u *schema.TokenUsage) Usage {
	if u == nil {
		return Usage{}
	}
	in := u.PromptTokens - u.PromptTokenDetails.CachedTokens - u.PromptTokenDetails.CacheWriteTokens
	if in < 0 {
		in = u.PromptTokens
	}
	return Usage{
		InputTokens:      in,
		OutputTokens:     u.CompletionTokens,
		CacheReadTokens:  u.PromptTokenDetails.CachedTokens,
		CacheWriteTokens: u.PromptTokenDetails.CacheWriteTokens,
	}
}

// UsageToToken builds an eino TokenUsage from DTO Usage (PromptTokens as the
// total, mirroring provider semantics).
func UsageToToken(u Usage) *schema.TokenUsage {
	return &schema.TokenUsage{
		PromptTokens:     u.InputTokens + u.CacheReadTokens + u.CacheWriteTokens,
		CompletionTokens: u.OutputTokens,
		TotalTokens:      u.InputTokens + u.CacheReadTokens + u.CacheWriteTokens + u.OutputTokens,
		PromptTokenDetails: schema.PromptTokenDetails{
			CachedTokens:     u.CacheReadTokens,
			CacheWriteTokens: u.CacheWriteTokens,
		},
	}
}

// EstimateTokens is the ~4 chars/token footprint estimate over DTO history
// (ported from norma compaction; shared by side-question budgeting and the
// compaction middleware).
func EstimateTokens(msgs []Message) int {
	chars := 0
	for _, m := range msgs {
		for _, b := range m.Content {
			chars += blockChars(b)
		}
	}
	return chars / 4
}

func blockChars(b ContentBlock) int {
	switch b.Type {
	case BlockText:
		return len(b.Text)
	case BlockThinking:
		return len(b.Thinking)
	case BlockToolUse:
		return len(b.Name) + len(b.Input)
	case BlockToolResult:
		n := 0
		for _, cb := range b.Content {
			n += blockChars(cb)
		}
		return n
	default:
		return len(b.Text)
	}
}
