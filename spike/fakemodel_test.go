// Package spike holds P1 verification spikes for the norma → eino migration.
// Each test machine-verifies one design-gate conclusion; the package is deleted
// once the migration lands (see docs/eino-migration.md).
package spike

import (
	"context"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

// scriptChatModel plays a scripted sequence of model turns: turn i returns
// turns[i]'s messages (Stream emits them chunk-by-chunk, Generate returns the
// last). After the script runs out it answers "done".
type scriptChatModel struct {
	turns [][]*schema.Message
	calls int
	bound []*schema.ToolInfo
}

func (f *scriptChatModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	i := f.calls
	f.calls++
	if i >= len(f.turns) {
		return schema.AssistantMessage("done", nil), nil
	}
	msgs := f.turns[i]
	return msgs[len(msgs)-1], nil
}

func (f *scriptChatModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	i := f.calls
	f.calls++
	var msgs []*schema.Message
	if i < len(f.turns) {
		msgs = f.turns[i]
	} else {
		msgs = []*schema.Message{schema.AssistantMessage("done", nil)}
	}
	return schema.StreamReaderFromArray(msgs), nil
}

func (f *scriptChatModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	f.bound = tools
	return f, nil
}

// echoTool is a minimal InvokableTool standing in for the CoreTool adapter.
type echoTool struct {
	name string
	run  func(ctx context.Context, args string) (string, error)
}

func (e *echoTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name: e.name,
		Desc: "echoes its input",
		ParamsOneOf: schema.NewParamsOneOfByParams(map[string]*schema.ParameterInfo{
			"text": {Type: schema.String, Desc: "text to echo", Required: true},
		}),
	}, nil
}

func (e *echoTool) InvokableRun(ctx context.Context, args string, opts ...tool.Option) (string, error) {
	if e.run != nil {
		return e.run(ctx, args)
	}
	return "echo:" + args, nil
}

func toolCall(id, name, args string) *schema.Message {
	return schema.AssistantMessage("", []schema.ToolCall{
		{ID: id, Function: schema.FunctionCall{Name: name, Arguments: args}},
	})
}
