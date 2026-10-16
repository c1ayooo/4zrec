// Package acllm is the session-DTO and conversion layer of the eino migration.
//
// It owns the on-disk conversation vocabulary that 4zrec transcripts have used
// since the norma era (Anthropic content-block shape: Message/ContentBlock with
// text/thinking/tool_use/tool_result blocks, Usage with cache tokens). The JSON
// field names of these types are FROZEN — existing transcript files and resume
// paths decode against them.
//
// eino's schema.Message is the in-memory runtime representation. convert.go
// maps between the two; the mapping is the only sanctioned place where the two
// vocabularies meet.
package acllm

import "encoding/json"

// Role identifies the author of a message.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// BlockType enumerates the kinds of content a message block may carry.
type BlockType string

const (
	BlockText       BlockType = "text"
	BlockThinking   BlockType = "thinking"
	BlockToolUse    BlockType = "tool_use"
	BlockToolResult BlockType = "tool_result"
)

// ContentBlock is one piece of message content. Which fields are populated
// depends on Type. This is the Anthropic content-block union.
type ContentBlock struct {
	Type BlockType `json:"type"`

	// Text block.
	Text string `json:"text,omitempty"`

	// Thinking block (extended thinking). Anthropic requires the field to be
	// named "thinking" (not "text") and requires "signature" when replaying
	// the block in multi-turn history.
	Thinking  string `json:"thinking,omitempty"`
	Signature string `json:"signature,omitempty"`

	// ToolUse: a model request to invoke a tool.
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`

	// ToolResult: the outcome of a tool, fed back to the model.
	ToolUseID string         `json:"tool_use_id,omitempty"`
	Content   []ContentBlock `json:"content,omitempty"`
	IsError   bool           `json:"is_error,omitempty"`
}

// TextBlock builds a text content block.
func TextBlock(s string) ContentBlock { return ContentBlock{Type: BlockText, Text: s} }

// ToolResultText builds a tool_result block carrying a single text block.
func ToolResultText(toolUseID, text string, isError bool) ContentBlock {
	return ContentBlock{
		Type:      BlockToolResult,
		ToolUseID: toolUseID,
		Content:   []ContentBlock{TextBlock(text)},
		IsError:   isError,
	}
}

// Message is a single conversation turn.
type Message struct {
	Role    Role           `json:"role"`
	Content []ContentBlock `json:"content"`
}

// UserText builds a user message with one text block.
func UserText(s string) Message {
	return Message{Role: RoleUser, Content: []ContentBlock{TextBlock(s)}}
}

// ToolUses returns the tool_use blocks of a message.
func (m Message) ToolUses() []ContentBlock {
	var out []ContentBlock
	for _, b := range m.Content {
		if b.Type == BlockToolUse {
			out = append(out, b)
		}
	}
	return out
}

// Text concatenates all text blocks of a message.
func (m Message) Text() string {
	var s string
	for _, b := range m.Content {
		if b.Type == BlockText {
			s += b.Text
		}
	}
	return s
}

// Usage reports token accounting, including prompt-cache tokens (FR-03.8).
type Usage struct {
	InputTokens      int `json:"input_tokens"`
	OutputTokens     int `json:"output_tokens"`
	CacheReadTokens  int `json:"cache_read_tokens"`
	CacheWriteTokens int `json:"cache_write_tokens"`
}

// Add accumulates token counts from another Usage.
func (u *Usage) Add(o Usage) {
	u.InputTokens += o.InputTokens
	u.OutputTokens += o.OutputTokens
	u.CacheReadTokens += o.CacheReadTokens
	u.CacheWriteTokens += o.CacheWriteTokens
}

// ToolSchema is a tool definition exposed to the model.
type ToolSchema struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}
