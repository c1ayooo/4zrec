package askernel

// Settlement-focused kernel tests: the wrap-up phase must die with its Prompt
// when the consumer abandons the stream — an abandoned wrap-up left running in
// the background would keep spending model calls nobody reads and interleave
// its DTO writes with a subsequent Prompt on the same session.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/tools"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// settleBlockModel plays one scripted primary turn; every later call (the
// settlement phase) streams one committing chunk and then holds the stream
// open until its call context is done. The done channel closes only when a
// settlement call actually terminates, which pins whether the kernel cancels
// an abandoned settlement run.
type settleBlockModel struct {
	mu    sync.Mutex
	calls int
	first *schema.Message
	done  chan struct{}
}

func newSettleBlockModel(first *schema.Message) *settleBlockModel {
	return &settleBlockModel{first: first, done: make(chan struct{})}
}

func (m *settleBlockModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *settleBlockModel) Generate(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
	return schema.AssistantMessage("not implemented", nil), nil
}

func (m *settleBlockModel) Stream(ctx context.Context, _ []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	m.mu.Lock()
	n := m.calls
	m.calls++
	m.mu.Unlock()
	if n == 0 {
		return schema.StreamReaderFromArray([]*schema.Message{m.first}), nil
	}
	sr, sw := schema.Pipe[*schema.Message](2)
	go func() {
		defer sw.Close()
		sw.Send(schema.AssistantMessage("SETTLE", nil), nil)
		<-ctx.Done() // hold the stream open: only a canceled run ends this
		sw.Send(nil, ctx.Err())
		close(m.done)
	}()
	return sr, nil
}

// TestKernelSettlementStopsWhenConsumerAbandons: the consumer stops draining
// as soon as the wrap-up phase's first text arrives — the settlement runner
// must then be canceled instead of continuing its turn budget in background.
func TestKernelSettlementStopsWhenConsumerAbandons(t *testing.T) {
	echo := simpleTool("echo", "echo ran", nil)
	m := newSettleBlockModel(toolCallMsg("c1", "echo", "{}"))
	s := NewSession(Options{
		Model:      m,
		Tools:      []tools.CoreTool{echo},
		MaxTurns:   1,
		Settlement: &Settlement{Prompt: "wrap up now", MaxTurns: 2},
	})
	defer s.Close()

	for ev, err := range s.Prompt(context.Background(), "go") {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ev.Kind == KindText && strings.Contains(ev.Text, "SETTLE") {
			break // the consumer abandons mid-settlement
		}
	}
	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		t.Fatal("settlement model call still running after the consumer stopped")
	}
}
