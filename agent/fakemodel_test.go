package agent

// Test machinery: a scripted fake model.ToolCallingChatModel (the askernel
// fakemodel pattern) so the behavioral tests run the FULL kernel — the same
// role the norma-provider fakes played before the eino migration.

import (
	"context"
	"errors"
	"sync"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// scriptTurn is one scripted model turn: a message, an error, or a hang.
type scriptTurn struct {
	msg *schema.Message
	err error
	// hang, when set, blocks the call until ctx is done and then fails with
	// ctx.Err() — the interrupted-mid-stream scenario.
	hang bool
}

// fakeChatModel plays a scripted sequence of model turns: call i returns
// turns[i] (Stream emits the turn's message as one chunk; Generate returns it
// whole). After the script runs out it answers "done". Every model input is
// recorded so tests can assert what the model saw.
type fakeChatModel struct {
	mu    sync.Mutex
	turns []scriptTurn
	usage *schema.TokenUsage

	calls  int
	inputs [][]*schema.Message
}

func (f *fakeChatModel) script(msgs ...*schema.Message) {
	for _, m := range msgs {
		f.turns = append(f.turns, scriptTurn{msg: m})
	}
}

func (f *fakeChatModel) failTurn(err error) { f.turns = append(f.turns, scriptTurn{err: err}) }

func (f *fakeChatModel) hangTurn() { f.turns = append(f.turns, scriptTurn{hang: true}) }

func (f *fakeChatModel) turnFor(call int) scriptTurn {
	if call < len(f.turns) {
		return f.turns[call]
	}
	return scriptTurn{msg: schema.AssistantMessage("done", nil)}
}

func (f *fakeChatModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	turn := f.begin(ctx, input)
	if turn.err != nil {
		return nil, turn.err
	}
	if turn.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	msg := *turn.msg
	if u := f.usageSnapshot(); u != nil {
		msg.ResponseMeta = &schema.ResponseMeta{Usage: u}
	}
	return &msg, nil
}

func (f *fakeChatModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	turn := f.begin(ctx, input)
	if turn.err != nil {
		return nil, turn.err
	}
	if turn.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	msg := *turn.msg
	if f.usageSnapshot() != nil {
		msg.ResponseMeta = &schema.ResponseMeta{Usage: f.usageSnapshot()}
	}
	return schema.StreamReaderFromArray([]*schema.Message{&msg}), nil
}

func (f *fakeChatModel) begin(ctx context.Context, input []*schema.Message) scriptTurn {
	f.mu.Lock()
	call := f.calls
	f.calls++
	f.inputs = append(f.inputs, input)
	f.mu.Unlock()
	_ = ctx
	return f.turnFor(call)
}

func (f *fakeChatModel) usageSnapshot() *schema.TokenUsage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.usage
}

func (f *fakeChatModel) callsMade() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// WithTools satisfies model.ToolCallingChatModel (the ADK binds tools via
// per-call options, so this only returns itself).
func (f *fakeChatModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return f, nil
}

var errFakeProvider = errors.New("provider failed after reporting usage")
