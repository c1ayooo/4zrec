package agent

import (
	"context"
	"encoding/json"

	"github.com/Autumn-27/artex/acllm"
	"github.com/Autumn-27/artex/askernel"
	"github.com/Autumn-27/artex/guard"
)

// prePostHookRunner is the subset of the guard package's hook registry this
// package consumes. guard/ still speaks the norma hook vocabulary (its re-point
// onto askernel is a separate task); the registry satisfies this interface
// structurally — note the norma signatures use plain []byte where askernel uses
// json.RawMessage (same underlying type, different name — hence the bridge).
// The registry's Stop method takes a norma-typed message slice and is
// structurally unreachable here — and the guard registers no Stop hooks, so a
// "not prevented" Stop is behavior-identical. If guard ever registers Stop
// hooks, this bridge must be revisited (the guard re-point will remove it).
type prePostHookRunner interface {
	PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte)
	PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool)
}

// bridgeHooks adapts a guard hook registry onto askernel.HookRunner.
type bridgeHooks struct{ inner prePostHookRunner }

func (b bridgeHooks) PreToolUse(ctx context.Context, name string, input json.RawMessage) (bool, string, json.RawMessage) {
	block, msg, updated := b.inner.PreToolUse(ctx, name, []byte(input))
	return block, msg, json.RawMessage(updated)
}

func (b bridgeHooks) PostToolUse(ctx context.Context, name string, input json.RawMessage, result string, isErr bool) {
	// The kernel hands PostToolUse the result JSON-encoded (norma parity) — pass
	// those bytes straight through.
	b.inner.PostToolUse(ctx, name, []byte(input), []byte(result), isErr)
}

// Stop: the guard has no Stop hooks (see prePostHookRunner); never prevent.
func (bridgeHooks) Stop(context.Context, []acllm.Message) (bool, []string, string) {
	return false, nil, ""
}

// guardHooks adapts a guard's hook registry to askernel.HookRunner.
func guardHooks(g *guard.Guard) askernel.HookRunner {
	if g == nil {
		return nil
	}
	if pp, ok := any(g.Hooks()).(prePostHookRunner); ok {
		return bridgeHooks{inner: pp}
	}
	return nil
}
