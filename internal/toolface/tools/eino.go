package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/platform/llm/acllm"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

// The CoreTool ↔ eino adapter. The eino ADK runtime (askernel) needs every
// CoreTool as a tool.InvokableTool; this file is the only bridge between the
// two vocabularies. It is deliberately dependency-minimal: the kernel's gate
// (approval hooks, permission pipeline, concurrency scheduling) lives in
// askernel and wraps AROUND the endpoint that ends here, so this adapter only
// covers what must hold for EVERY execution path:
//
//   - ToolContext injection/extraction via the context (WithToolContext /
//     ToolContextFromEino), so a host running tools through eino without the
//     kernel still reaches its tools;
//   - guardPanic semantics: a panicking tool never takes down the run — the
//     panic is recovered and surfaces as an error Result, exactly like the
//     norma harness's execOne guarantee;
//   - the eino error convention: InvokableRun always returns (string, nil).
//     The eino ToolsNode turns a non-nil Go error into a run-fatal failure,
//     whereas norma turned tool failures into error tool_result blocks the
//     model can react to. Returning the error TEXT keeps those semantics.
//     isError rides out-of-band: the caller that knows the Result (the
//     kernel's gate, from tools.Result.IsError) sets acllm.ExtraIsError on
//     the schema tool message itself.

type toolContextKey struct{}

// WithToolContext returns a context carrying tc for tool execution.
func WithToolContext(ctx context.Context, tc *ToolContext) context.Context {
	return context.WithValue(ctx, toolContextKey{}, tc)
}

// ToolContextFromEino returns the ToolContext carried on ctx, or nil.
func ToolContextFromEino(ctx context.Context) *ToolContext {
	tc, _ := ctx.Value(toolContextKey{}).(*ToolContext)
	return tc
}

// ArgsFromEino converts eino tool-call arguments (a JSON string) into the
// json.RawMessage input CoreTool.Call expects. Empty arguments become "{}".
func ArgsFromEino(argsJSON string) json.RawMessage {
	if strings.TrimSpace(argsJSON) == "" {
		return json.RawMessage("{}")
	}
	return json.RawMessage(argsJSON)
}

// ToEino adapts a CoreTool into an eino InvokableTool. The Info is built from
// the tool's InputSchema (extended Prompt merged into the description, matching
// Registry.Schemas). InvokableRun resolves the ToolContext from ctx, recovers
// panics into error results, applies the idempotent output cap, and flattens
// the Result's text blocks into the returned string — always (string, nil).
func ToEino(t CoreTool) tool.InvokableTool {
	return &einoTool{t: t}
}

type einoTool struct {
	t CoreTool
}

// Info renders the tool definition for model binding.
func (e *einoTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	desc := e.t.Description()
	if p := e.t.Prompt(); p != "" {
		desc += "\n\n" + p
	}
	return acllm.ToolSchemaToInfo(acllm.ToolSchema{
		Name:        e.t.Name(),
		Description: desc,
		InputSchema: e.t.InputSchema(),
	})
}

// rawInputTool is the optional opt-out from schema validation, discovered by
// assertion exactly like the norma harness did (see Spec.RawInput).
type rawInputTool interface{ AcceptsRawInput() bool }

// InvokableRun executes the tool. It never returns a non-nil error and never
// panics: failures and panics both become "Error: …" result text.
func (e *einoTool) InvokableRun(ctx context.Context, args string, opts ...tool.Option) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Sprintf("Error: tool %s panicked: %v", e.t.Name(), r)
			err = nil
		}
	}()

	input := ArgsFromEino(args)

	// Schema validation (FR-04.5), skipped for raw-input tools that parse and
	// repair their own arguments.
	if r, ok := e.t.(rawInputTool); !ok || !r.AcceptsRawInput() {
		if verr := ValidateInput(e.t.InputSchema(), input); verr != nil {
			return "Error: invalid tool input: " + verr.Error(), nil
		}
	}

	res, callErr := e.t.Call(ctx, input, ToolContextFromEino(ctx))
	if callErr != nil {
		res = Errorf("Error: " + callErr.Error())
	}
	return FlattenResultEino(ToolContextFromEino(ctx), res), nil
}

// FlattenResultEino applies the idempotent output cap to every text block (so
// no tool can overflow the context window even if it forgot to Capture itself)
// and joins the text blocks with newlines — the eino tool_result is a plain
// string. Empty results become "(no output)".
func FlattenResultEino(tc *ToolContext, res Result) string {
	var b strings.Builder
	for _, block := range res.Content {
		if block.Type != acllm.BlockText {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(CaptureOnce(tc, block.Text))
	}
	if b.Len() == 0 {
		return "(no output)"
	}
	return b.String()
}
