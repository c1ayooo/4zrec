package noa

import (
	"encoding/json"
	"strings"

	"github.com/Autumn-27/artex/acllm"
)

// origin records where a projected core came from, so reassembly can put it
// back into the right host message and block.
type origin struct {
	msgIdx int
	blkIdx int
}

// Sidecar carries what the flat representation cannot: provider-internal data
// that must survive the round trip untouched.
type Sidecar struct {
	// Signatures holds each thinking block's provider signature, keyed by core
	// id. Anthropic validates it on replay, so it must come back byte-identical.
	Signatures map[string]string
	// Origins maps a core id back to its source position.
	Origins map[string]origin
	// ToolResultIsError preserves the error flag of a tool result.
	ToolResultIsError map[string]bool
}

func newSidecar() *Sidecar {
	return &Sidecar{
		Signatures:        map[string]string{},
		Origins:           map[string]origin{},
		ToolResultIsError: map[string]bool{},
	}
}

// Project flattens the host's history into noa's representation.
//
// Boundary inheritance: a session that previously ran the built-in compaction
// carries a compact_boundary, and everything before it has already been
// summarised into the message that follows. noa's View does not go through
// acllm.MessagesForAPI, so without this slice those pre-boundary originals
// would come back — alongside the summary that replaced them, doubling the
// context.
func Project(msgs []acllm.Message) ([]CoreMessage, *Sidecar) {
	if i := acllm.LastBoundaryIndex(msgs); i >= 0 {
		msgs = msgs[i+1:]
	}

	sc := newSidecar()
	cc := NewClusterCounter()
	var out []CoreMessage

	// Tool results carry no tool name; recover it from the call they answer.
	toolNameByCallID := map[string]string{}
	for _, m := range msgs {
		for _, b := range m.Content {
			if b.Type == acllm.BlockToolUse {
				toolNameByCallID[b.ID] = b.Name
			}
		}
	}

	for mi, m := range msgs {
		for bi, b := range m.Content {
			core, ok := projectBlock(m.Role, b, toolNameByCallID)
			if !ok {
				continue
			}
			core.ID = cc.Next(DeriveMessageID(core.Role, core.ContentType, core.Text, core.ToolCallID, core.ToolName))
			sc.Origins[core.ID] = origin{msgIdx: mi, blkIdx: bi}
			if b.Type == acllm.BlockThinking {
				sc.Signatures[core.ID] = b.Signature
			}
			if b.Type == acllm.BlockToolResult && b.IsError {
				sc.ToolResultIsError[core.ID] = true
			}
			out = append(out, core)
		}
	}
	return out, sc
}

// projectBlock maps one content block; ok=false means the block has no
// representation in the flat model.
func projectBlock(role acllm.Role, b acllm.ContentBlock, toolNames map[string]string) (CoreMessage, bool) {
	switch b.Type {
	case acllm.BlockText:
		r := RoleAssistant
		text := b.Text
		if role == acllm.RoleUser {
			r = RoleUser
			// Only user text carries a tag, and it must not reach the hash.
			text = StripRefTag(text)
		}
		return CoreMessage{Role: r, ContentType: CTText, Text: text}, true

	case acllm.BlockThinking:
		return CoreMessage{Role: RoleAssistant, ContentType: CTReasoning, Text: b.Thinking}, true

	case acllm.BlockToolUse:
		return CoreMessage{
			Role: RoleAssistant, ContentType: CTToolCall,
			ToolName: b.Name, ToolCallID: b.ID, Text: string(b.Input),
		}, true

	case acllm.BlockToolResult:
		return CoreMessage{
			Role: RoleTool, ContentType: CTToolResult,
			ToolCallID: b.ToolUseID, ToolName: toolNames[b.ToolUseID],
			Text: StripRefTag(flattenToolResult(b.Content)),
		}, true

	default:
		// compact_boundary and anything else the host may add: not content.
		return CoreMessage{}, false
	}
}

// flattenToolResult joins a tool result's nested blocks into one body.
func flattenToolResult(blocks []acllm.ContentBlock) string {
	var parts []string
	for _, b := range blocks {
		if b.Type == acllm.BlockText && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// ReassembleOptions controls how cores are rebuilt into host messages.
type ReassembleOptions struct {
	// State supplies the ref map and token snapshot for tagging.
	State *CompressionState
	// Tag enables ref tags. Materialize turns them off: they point at an
	// addressing scheme that is no longer running.
	Tag bool
}

// Reassemble rebuilds host messages from a projected, pruned view.
//
// The output is for one request only. It is never written back to the host's
// history — message identity is a content hash, and writing a tagged or
// truncated body back would change every id derived from it.
func Reassemble(cores []CoreMessage, originals []acllm.Message, sc *Sidecar, opts ReassembleOptions) []acllm.Message {
	// Boundary inheritance must match Project's, or origins would be offset.
	if i := acllm.LastBoundaryIndex(originals); i >= 0 {
		originals = originals[i+1:]
	}

	var out []acllm.Message
	i := 0
	for i < len(cores) {
		c := cores[i]

		// Synthetic messages (summaries, the nudge) have no original to rebuild
		// from — they become standalone user messages.
		if isSynthetic(c) {
			out = append(out, acllm.Message{
				Role:    acllm.RoleUser,
				Content: []acllm.ContentBlock{acllm.TextBlock(c.Text)},
			})
			i++
			continue
		}

		o, known := sc.Origins[c.ID]
		if !known || o.msgIdx >= len(originals) {
			// An unrecognised core still has to reach the model; drop it into a
			// plain message rather than losing it.
			out = append(out, acllm.Message{
				Role:    roleToLLM(c.Role),
				Content: []acllm.ContentBlock{acllm.TextBlock(c.Text)},
			})
			i++
			continue
		}

		// Gather the run of cores that came from this same host message, so its
		// blocks are rebuilt together and in order.
		group := []CoreMessage{c}
		j := i + 1
		for j < len(cores) && !isSynthetic(cores[j]) {
			oj, ok := sc.Origins[cores[j].ID]
			if !ok || oj.msgIdx != o.msgIdx {
				break
			}
			group = append(group, cores[j])
			j++
		}
		i = j

		if rebuilt, ok := rebuildMessage(originals[o.msgIdx], group, sc, opts); ok {
			out = append(out, rebuilt)
		}
	}

	// A range that ended mid-exchange can leave a tool block without its
	// counterpart; strict providers reject that outright.
	out = acllm.PairToolBlocks(out)
	return dropEmpty(out)
}

// rebuildMessage reconstructs one host message from the cores that survived.
func rebuildMessage(orig acllm.Message, group []CoreMessage, sc *Sidecar, opts ReassembleOptions) (acllm.Message, bool) {
	var content []acllm.ContentBlock
	for _, c := range group {
		o, ok := sc.Origins[c.ID]
		if !ok || o.blkIdx >= len(orig.Content) {
			continue
		}
		b := orig.Content[o.blkIdx]
		content = append(content, rebuildBlock(b, c, sc, opts))
	}
	if len(content) == 0 {
		return acllm.Message{}, false
	}
	return acllm.Message{Role: orig.Role, Content: content}, true
}

// rebuildBlock restores one content block, writing back any rewrite the
// pipeline performed and re-attaching the ref tag.
func rebuildBlock(b acllm.ContentBlock, c CoreMessage, sc *Sidecar, opts ReassembleOptions) acllm.ContentBlock {
	switch b.Type {
	case acllm.BlockText:
		body := c.Text
		if opts.Tag && c.Role == RoleUser {
			body = tagged(body, c, opts)
		}
		b.Text = body

	case acllm.BlockThinking:
		b.Thinking = c.Text
		// The signature is restored verbatim. Rewriting thinking text while
		// keeping the old signature makes Anthropic reject the request, so the
		// two must move together or not at all.
		b.Signature = sc.Signatures[c.ID]

	case acllm.BlockToolUse:
		// Only replace the arguments if the rewrite is still valid JSON.
		// Writing a malformed payload back would break the call itself.
		if c.Text != string(b.Input) && json.Valid([]byte(c.Text)) {
			b.Input = json.RawMessage(c.Text)
		}

	case acllm.BlockToolResult:
		body := c.Text
		if opts.Tag {
			body = tagged(body, c, opts)
		}
		b.Content = []acllm.ContentBlock{acllm.TextBlock(body)}
		b.IsError = sc.ToolResultIsError[c.ID]
	}
	return b
}

// tagged appends the ref tag when the message has an addressable ref.
//
// Assistant messages are never tagged: the model copies its own previous output
// far more readily than it copies host chrome, and an echoed tag shows up as
// XML debris in the terminal. It costs nothing — ranges are inclusive spans, so
// anything between two tagged endpoints is included anyway.
func tagged(body string, c CoreMessage, opts ReassembleOptions) string {
	if opts.State == nil {
		return body
	}
	ref, ok := opts.State.MessageRefs.ByRaw[c.ID]
	if !ok || ref == BlockedRef {
		return body
	}
	tokens := tokenForRef(opts.State.TokenSnapshot, ref, body)
	return AppendRefTag(body, RefTag(ref, c, tokens))
}

func isSynthetic(c CoreMessage) bool {
	return strings.HasPrefix(c.ID, SummaryIDPrefix) || c.ID == NudgeMessageID
}

func roleToLLM(r Role) acllm.Role {
	if r == RoleAssistant {
		return acllm.RoleAssistant
	}
	return acllm.RoleUser
}

// dropEmpty removes messages with no content, and assistant messages with
// neither text nor a tool call — OpenAI-compatible providers reject those.
func dropEmpty(msgs []acllm.Message) []acllm.Message {
	out := make([]acllm.Message, 0, len(msgs))
	for _, m := range msgs {
		if len(m.Content) == 0 {
			continue
		}
		if m.Role == acllm.RoleAssistant && m.Text() == "" && len(m.ToolUses()) == 0 {
			hasThinking := false
			for _, b := range m.Content {
				if b.Type == acllm.BlockThinking {
					hasThinking = true
					break
				}
			}
			if !hasThinking {
				continue
			}
		}
		out = append(out, m)
	}
	return out
}
