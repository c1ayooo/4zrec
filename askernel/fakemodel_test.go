package askernel

// Test machinery: a scriptChatModel-style fake (model.ToolCallingChatModel,
// from the proven spike/fakemodel_test.go) plus small CoreTools. The fake
// records every model input and every WithTools binding so tests can assert
// exactly what the model saw.

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/acllm"
	"github.com/Autumn-27/artex/tools"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// fakeTurn is one scripted model turn: a message, or an error.
type fakeTurn struct {
	msg *schema.Message
	err error
}

// fakeModel plays a scripted sequence of model turns: call i returns turns[i]
// (Stream emits the turn's message as one chunk; Generate returns it whole).
// After the script runs out it answers "done". Every model input and the
// effective per-call tool binding (extracted from the model options, the way a
// provider adapter does) are recorded. usage, when set, rides on the response
// chunk (ResponseMeta), the way providers report it.
type fakeModel struct {
	mu    sync.Mutex
	turns []fakeTurn
	usage *schema.TokenUsage

	calls int
	// inputs[i] is the message array the i-th model call received.
	inputs [][]*schema.Message
	// bound[i] is the tool list of the i-th WithTools call.
	bound [][]*schema.ToolInfo
}

func (f *fakeModel) script(msgs ...*schema.Message) {
	for _, m := range msgs {
		f.turns = append(f.turns, fakeTurn{msg: m})
	}
}

func (f *fakeModel) failTurn(err error) { f.turns = append(f.turns, fakeTurn{err: err}) }

func (f *fakeModel) turnFor(call int) fakeTurn {
	if call < len(f.turns) {
		return f.turns[call]
	}
	return fakeTurn{msg: schema.AssistantMessage("done", nil)}
}

func (f *fakeModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	f.mu.Lock()
	call := f.calls
	f.calls++
	f.inputs = append(f.inputs, input)
	f.recordBound(opts)
	f.mu.Unlock()
	turn := f.turnFor(call)
	if turn.err != nil {
		return nil, turn.err
	}
	return turn.msg, nil
}

func (f *fakeModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	f.mu.Lock()
	call := f.calls
	f.calls++
	f.inputs = append(f.inputs, input)
	usage := f.usage
	f.recordBound(opts)
	f.mu.Unlock()
	turn := f.turnFor(call)
	if turn.err != nil {
		return nil, turn.err
	}
	msg := *turn.msg
	if usage != nil {
		msg.ResponseMeta = &schema.ResponseMeta{Usage: usage}
	}
	return schema.StreamReaderFromArray([]*schema.Message{&msg}), nil
}

// recordBound captures the effective tool binding of this call the way a real
// provider adapter does: through the per-call model options.
func (f *fakeModel) recordBound(opts []model.Option) {
	common := model.GetCommonOptions(&model.Options{}, opts...)
	f.bound = append(f.bound, common.Tools)
}

// WithTools satisfies the ToolCallingChatModel interface (the ADK binds tools
// via per-call options, so this only records an extra binding snapshot).
func (f *fakeModel) WithTools(infos []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound = append(f.bound, infos)
	return f, nil
}

// callsMade reports the number of model calls so far.
func (f *fakeModel) callsMade() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// inputOf returns the i-th model call's input messages.
func (f *fakeModel) inputOf(i int) []*schema.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i < len(f.inputs) {
		return f.inputs[i]
	}
	return nil
}

// boundOf returns the WithTools bindings recorded for the first n model calls.
func (f *fakeModel) boundOf(n int) [][]*schema.ToolInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n > len(f.bound) {
		n = len(f.bound)
	}
	return append([][]*schema.ToolInfo(nil), f.bound[:n]...)
}

// --- test tools ---

// simpleTool builds a CoreTool returning out; onRun, when set, observes calls.
func simpleTool(name, out string, onRun func()) tools.CoreTool {
	return tools.Build(tools.Spec{
		Name:        name,
		Description: "test tool " + name,
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, tools.Context) tools.Decision {
			return tools.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *tools.ToolContext) (tools.Result, error) {
			if onRun != nil {
				onRun()
			}
			return tools.Text(out), nil
		},
	})
}

// failingTool always returns a Go error.
func failingTool(name string) tools.CoreTool {
	return tools.Build(tools.Spec{
		Name:        name,
		Description: "always fails",
		Schema:      map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, tools.Context) tools.Decision {
			return tools.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *tools.ToolContext) (tools.Result, error) {
			return tools.Result{}, errBoom
		},
	})
}

// panickingTool always panics.
func panickingTool(name string) tools.CoreTool {
	return tools.Build(tools.Spec{
		Name:        name,
		Description: "always panics",
		Schema:      map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, tools.Context) tools.Decision {
			return tools.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *tools.ToolContext) (tools.Result, error) {
			panic("boom")
		},
	})
}

type errBoomError struct{}

func (errBoomError) Error() string { return "boom failure" }

var errBoom error = errBoomError{}

// toolCallMsg builds an assistant message with one tool call (spike helper).
func toolCallMsg(id, name, args string) *schema.Message {
	return schema.AssistantMessage("", []schema.ToolCall{
		{ID: id, Function: schema.FunctionCall{Name: name, Arguments: args}},
	})
}

// --- event collection helpers ---

// collected is the drained output of one Prompt.
type collected struct {
	events   []RunEvent
	errs     []error
	terminal *Terminal
}

// drainPrompt runs one Prompt to completion, collecting events.
func drainPrompt(s *Session, ctx context.Context, input string) collected {
	var c collected
	for ev, err := range s.Prompt(ctx, input) {
		if err != nil {
			c.errs = append(c.errs, err)
			continue
		}
		c.events = append(c.events, ev)
		if ev.Kind == KindResult && ev.Terminal != nil {
			c.terminal = ev.Terminal
		}
	}
	return c
}

// kinds lists the event kinds in order.
func (c collected) kinds() []EventKind {
	out := make([]EventKind, 0, len(c.events))
	for _, ev := range c.events {
		out = append(out, ev.Kind)
	}
	return out
}

// texts concatenates all KindText payloads.
func (c collected) texts() string {
	var b strings.Builder
	for _, ev := range c.events {
		if ev.Kind == KindText {
			b.WriteString(ev.Text)
		}
	}
	return b.String()
}

// toolResultBlocks returns all KindToolResult blocks.
func (c collected) toolResultBlocks() []acllm.ContentBlock {
	var out []acllm.ContentBlock
	for _, ev := range c.events {
		if ev.Kind == KindToolResult && ev.ToolResult != nil {
			out = append(out, *ev.ToolResult)
		}
	}
	return out
}

// inputContains reports whether a model input contains a message whose content
// contains substr.
func inputContains(input []*schema.Message, substr string) bool {
	for _, m := range input {
		if strings.Contains(m.Content, substr) {
			return true
		}
	}
	return false
}

// bindNames flattens a WithTools binding into a name set.
func bindNames(infos []*schema.ToolInfo) map[string]bool {
	out := map[string]bool{}
	for _, ti := range infos {
		if ti != nil {
			out[ti.Name] = true
		}
	}
	return out
}
