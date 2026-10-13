package spike

// V3/V4 spike: ADK ChatModelAgent middleware mechanism — WrapInvokableToolCall
// (approval/steer gate point), BeforeModelRewriteState (per-turn message &
// toolset mutation point), and ToolsNode concurrency policy.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// gateMiddleware mirrors the planned ARTEX kernels: Wrap*ToolCall is the
// guard/intercept/steer blocking point; BeforeModelRewriteState is the
// nudge/skill-guidance injection point.
type gateMiddleware struct {
	adk.TypedBaseChatModelAgentMiddleware[*schema.Message]

	mu            sync.Mutex
	denyNext      map[string]int // tool name -> remaining denials
	modelCalls    int
	sawMessages   int
	wrappedCalls  []string
	toolResults   []string
}

func (g *gateMiddleware) BeforeModelRewriteState(ctx context.Context, state *adk.TypedChatModelAgentState[*schema.Message], mc *adk.TypedModelContext[*schema.Message]) (context.Context, *adk.TypedChatModelAgentState[*schema.Message], error) {
	g.mu.Lock()
	g.modelCalls++
	g.sawMessages = len(state.Messages)
	g.mu.Unlock()
	return ctx, state, nil
}

func (g *gateMiddleware) WrapInvokableToolCall(ctx context.Context, endpoint adk.InvokableToolCallEndpoint, tCtx *adk.ToolContext) (adk.InvokableToolCallEndpoint, error) {
	g.mu.Lock()
	g.wrappedCalls = append(g.wrappedCalls, tCtx.Name)
	deny := g.denyNext[tCtx.Name] > 0
	if deny {
		g.denyNext[tCtx.Name]--
	}
	g.mu.Unlock()
	if deny {
		return func(ctx context.Context, args string, opts ...tool.Option) (string, error) {
			// block + inject, without running the tool (steer/intercept-deny shape)
			return "", fmt.Errorf("blocked by platform governance")
		}, nil
	}
	return func(ctx context.Context, args string, opts ...tool.Option) (string, error) {
		res, err := endpoint(ctx, args, opts...)
		g.mu.Lock()
		g.toolResults = append(g.toolResults, res)
		g.mu.Unlock()
		return res, err
	}, nil
}

func newTestAgent(t *testing.T, m model.ToolCallingChatModel, tools []tool.BaseTool, handlers []adk.ChatModelAgentMiddleware, sequential bool) adk.Agent {
	t.Helper()
	ag, err := adk.NewChatModelAgent(context.Background(), &adk.ChatModelAgentConfig{
		Name:          "spike",
		Instruction:   "test instruction",
		Model:         m,
		MaxIterations: 8,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{Tools: tools, ExecuteSequentially: sequential},
		},
		Handlers: handlers,
	})
	if err != nil {
		t.Fatalf("NewChatModelAgent: %v", err)
	}
	return ag
}

func drainEvents(t *testing.T, runner *adk.Runner, ctx context.Context, query string) (texts []string, toolMsgs []string, lastErr error) {
	t.Helper()
	iter := runner.Query(ctx, query)
	for {
		ev, ok := iter.Next()
		if !ok {
			return
		}
		if ev.Err != nil {
			lastErr = ev.Err
			continue
		}
		if ev.Output == nil || ev.Output.MessageOutput == nil {
			continue
		}
		mv := ev.Output.MessageOutput
		mo, err := mv.GetMessage()
		if err != nil {
			lastErr = err
			continue
		}
		if mv.Role == schema.Tool {
			toolMsgs = append(toolMsgs, mo.Content)
		}
		if len(mo.ToolCalls) > 0 {
			for _, tc := range mo.ToolCalls {
				toolMsgs = append(toolMsgs, "CALL:"+tc.Function.Name)
			}
		}
		if mo.Content != "" && mv.Role == schema.Assistant {
			texts = append(texts, mo.Content)
		}
	}
}

func TestSpikeMiddlewareHooksAndToolGate(t *testing.T) {
	m := &scriptChatModel{turns: [][]*schema.Message{
		{toolCall("call1", "echo", `{"text":"hello"}`)},
		{schema.AssistantMessage("all done", nil)},
	}}
	gate := &gateMiddleware{denyNext: map[string]int{}}
	ag := newTestAgent(t, m, []tool.BaseTool{&echoTool{name: "echo"}}, []adk.ChatModelAgentMiddleware{gate}, false)
	runner := adk.NewRunner(context.Background(), adk.RunnerConfig{Agent: ag, EnableStreaming: true})

	texts, toolMsgs, lastErr := drainEvents(t, runner, context.Background(), "hi")
	if lastErr != nil {
		t.Fatalf("run error: %v", lastErr)
	}
	if len(texts) == 0 || !strings.Contains(strings.Join(texts, "|"), "all done") {
		t.Errorf("final text missing: %v", texts)
	}
	if len(gate.wrappedCalls) != 1 || gate.wrappedCalls[0] != "echo" {
		t.Errorf("wrapped calls = %v, want [echo]", gate.wrappedCalls)
	}
	if len(gate.toolResults) != 1 || !strings.Contains(gate.toolResults[0], "hello") {
		t.Errorf("tool results = %v", gate.toolResults)
	}
	if gate.modelCalls != 2 {
		t.Errorf("BeforeModelRewriteState calls = %d, want 2", gate.modelCalls)
	}
	t.Logf("tool msgs: %v", toolMsgs)
}

func TestSpikeToolGateDeny(t *testing.T) {
	m := &scriptChatModel{turns: [][]*schema.Message{
		{toolCall("call1", "echo", `{"text":"hello"}`)},
		{schema.AssistantMessage("recovered", nil)},
	}}
	gate := &gateMiddleware{denyNext: map[string]int{"echo": 1}}
	ag := newTestAgent(t, m, []tool.BaseTool{&echoTool{name: "echo"}}, []adk.ChatModelAgentMiddleware{gate}, false)
	runner := adk.NewRunner(context.Background(), adk.RunnerConfig{Agent: ag, EnableStreaming: true})

	_, toolMsgs, _ := drainEvents(t, runner, context.Background(), "hi")
	joined := strings.Join(toolMsgs, "|")
	if !strings.Contains(joined, "CALL:echo") {
		t.Errorf("expected echo call in events: %v", toolMsgs)
	}
	if len(gate.toolResults) != 0 {
		t.Errorf("denied tool must not run, but got results %v", gate.toolResults)
	}
}

// blockingTool sleeps to make concurrency measurable.
type blockingTool struct{ name string }

func (b *blockingTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: b.name, Desc: "blocks"}, nil
}
func (b *blockingTool) InvokableRun(ctx context.Context, args string, opts ...tool.Option) (string, error) {
	time.Sleep(400 * time.Millisecond)
	return "slept", nil
}

func parallelTurn() *scriptChatModel {
	return &scriptChatModel{turns: [][]*schema.Message{
		{schema.AssistantMessage("", []schema.ToolCall{
			{ID: "c1", Function: schema.FunctionCall{Name: "slow1", Arguments: "{}"}},
			{ID: "c2", Function: schema.FunctionCall{Name: "slow2", Arguments: "{}"}},
		})},
		{schema.AssistantMessage("both done", nil)},
	}}
}

func runTimed(t *testing.T, sequential bool) time.Duration {
	t.Helper()
	runner := adk.NewRunner(context.Background(), adk.RunnerConfig{
		Agent: newTestAgent(t, parallelTurn(),
			[]tool.BaseTool{&blockingTool{name: "slow1"}, &blockingTool{name: "slow2"}},
			nil, sequential),
		EnableStreaming: true,
	})
	start := time.Now()
	drainEvents(t, runner, context.Background(), "hi")
	return time.Since(start)
}

func TestSpikeToolsNodeConcurrency(t *testing.T) {
	par := runTimed(t, false)
	seq := runTimed(t, true)
	t.Logf("parallel=%v sequential=%v", par, seq)
	if par > 700*time.Millisecond {
		t.Errorf("default ToolsNode looks sequential: %v", par)
	}
	if seq < 700*time.Millisecond {
		t.Errorf("ExecuteSequentially did not serialize: %v", seq)
	}
}
