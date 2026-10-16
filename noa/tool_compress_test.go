package noa

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/acllm"
	"github.com/c1ayooo/4zrec/tools"
)

// The kernel's gate (askernel gateMiddleware.execOne) validates a call against
// the tool's InputSchema before dispatching it, so a test that calls runCompress
// directly is testing a path the model may not be able to reach. These tests put
// the arguments through the same gate the kernel uses, so the lenient parsing
// the rest of the suite exercises is known to be reachable in production.
//
// Compress opts out of that gate (tools.Spec.RawInput) because the shapes it
// exists to repair are, by definition, not valid JSON. The opt-out is asserted
// here rather than assumed.

// gate mirrors gateMiddleware.execOne's validation step exactly, including the
// AcceptsRawInput opt-out the kernel consults first.
func gate(t *testing.T, input string) error {
	t.Helper()
	ct := newCompressTool(newTestSession(t, 40000))
	if r, ok := ct.(interface{ AcceptsRawInput() bool }); ok && r.AcceptsRawInput() {
		return nil
	}
	return tools.ValidateInput(ct.InputSchema(), json.RawMessage(input))
}

// The opt-out has to be on, or every lenient-parsing test below is testing a
// path production cannot reach.
func TestCompressOptsOutOfSchemaValidation(t *testing.T) {
	ct := newCompressTool(newTestSession(t, 40000))
	r, ok := ct.(interface{ AcceptsRawInput() bool })
	if !ok || !r.AcceptsRawInput() {
		t.Fatal("Compress does not report AcceptsRawInput, so gateMiddleware validates its " +
			"arguments and ParseCompressArgs never sees a malformed call")
	}
	// The schema must still be advertised: it is what tells the model the shape
	// to aim for, and dropping it would be a much worse trade than the gate.
	if ct.InputSchema() == nil {
		t.Fatal("Compress advertises no schema; the model has nothing to aim for")
	}
	if _, ok := ct.InputSchema()["properties"]; !ok {
		t.Fatalf("the advertised schema has no properties: %v", ct.InputSchema())
	}
}

// The other half: shapes the parser correctly REJECTS must still reach it, so
// the model gets formatParseError's "expected shape" — which names Compress's
// contract — rather than a schema message that does not.
func TestUnparseableArgumentsReachNoasDiagnostics(t *testing.T) {
	corpus := map[string]string{
		"no content field":  `{"topic":"t"}`,
		"content is object": `{"content":{"startId":"m00001"}}`,
		"empty input":       ``,
		"ranges incomplete": `{"content":[{"startId":"m00001"}]}`,
	}
	for name, args := range corpus {
		t.Run(name, func(t *testing.T) {
			if err := gate(t, args); err != nil {
				t.Fatalf("the gate answered before noa did (%v), so formatParseError never runs "+
					"and the model is told nothing about the shape Compress wants", err)
			}
			res, err := runCompress(newTestSession(t, 40000), json.RawMessage(args), nil)
			if err != nil {
				t.Fatalf("runCompress returned a Go error: %v", err)
			}
			if !res.IsError {
				t.Fatalf("unparseable arguments produced a success result: %s", res.Content[0].Text)
			}
			if !strings.Contains(res.Content[0].Text, "Expected shape:") {
				t.Fatalf("the model is not told the expected shape:\n%s", res.Content[0].Text)
			}
		})
	}
}

// A parse failure feeds the failure ladder (recordParseFailure). If the gate
// answers first, the ladder never counts it — so a model stuck emitting a broken
// shape is never detected as stuck by the mechanism built to detect exactly that.
func TestParseFailuresReachTheFailureLadder(t *testing.T) {
	sess := newTestSession(t, 40000)
	broken := `{"content":[{"startId":"m00001","endId":"m00009","summ`

	if err := gate(t, broken); err != nil {
		t.Skipf("the gate rejects this before the tool runs (%v); "+
			"TestCompressOptsOutOfSchemaValidation is the test that covers the consequence", err)
	}
	before := sess.attempts
	if _, err := runCompress(sess, json.RawMessage(broken), nil); err != nil {
		t.Fatalf("runCompress returned a Go error: %v", err)
	}
	if sess.attempts <= before {
		t.Fatalf("the attempt counter stayed at %d after an unparseable call; "+
			"the ladder cannot notice a model that is stuck", before)
	}
}

// A valid question with an empty range list is neither success nor failure: the
// answer is NoRangesMessage, and the failure ladder must not move.
func TestCompressWithNoRangesIsNotCounted(t *testing.T) {
	sess := newTestSession(t, 40000)
	before := sess.attempts
	res, err := runCompress(sess, json.RawMessage(`{"content":[]}`), nil)
	if err != nil {
		t.Fatalf("runCompress returned a Go error: %v", err)
	}
	if res.IsError {
		t.Fatalf("an empty range list is a question, not an error: %s", res.Content[0].Text)
	}
	if res.Content[0].Text != NoRangesMessage {
		t.Fatalf("answer = %q, want NoRangesMessage", res.Content[0].Text)
	}
	if sess.attempts != before {
		t.Fatalf("the failure ladder moved from %d to %d on a well-formed empty call", before, sess.attempts)
	}
}

// The full production path, exercised the way the kernel does it: resolve the
// built tool, validate, check permissions and concurrency, then Call with a
// real ToolContext. Tests that call runCompress skip all of this.
func TestCompressToolThroughTheBuiltToolInterface(t *testing.T) {
	sess := newTestSession(t, 40000)
	var msgs []acllm.Message
	for i := 0; i < 24; i++ {
		msgs = append(msgs, userText(strings.Repeat("field notes and command output. ", 67))) // ~2000 chars
	}
	sess.View(msgs)

	ct := newCompressTool(sess)
	if ct.Name() != CompressToolName {
		t.Fatalf("tool name = %q, want %q", ct.Name(), CompressToolName)
	}

	// A range wide enough to clear the minimum-content rule, ending well before
	// the soft protected zone (the last 5 messages).
	refs := sess.State().MessageRefs
	if len(refs.ByRef) < 16 {
		t.Fatalf("only %d refs assigned; the fixture is too short", len(refs.ByRef))
	}
	args, _ := json.Marshal(map[string]any{"content": []map[string]any{{
		"startId": IndexToRef(2), "endId": IndexToRef(14),
		"summary": strings.Repeat("Summarised the field notes: every command, path and finding kept verbatim. ", 3),
	}}})

	if err := tools.ValidateInput(ct.InputSchema(), args); err != nil {
		t.Fatalf("a well-formed call failed schema validation: %v", err)
	}
	if ct.IsReadOnly(args) {
		t.Fatal("Compress reports read-only; it writes archives and mutates state")
	}
	if ct.IsConcurrencySafe(args) {
		t.Fatal("Compress reports concurrency-safe; two racing compressions would interleave block allocation")
	}

	res, err := ct.Call(t.Context(), args, &tools.ToolContext{ToolUseID: "toolu_gate_1"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.IsError {
		t.Fatalf("a well-formed compression reported an error: %s", res.Content[0].Text)
	}
	if n := PanelBlockCount(res.Content[0].Text); n != 1 {
		t.Fatalf("panel reports %d blocks, want 1:\n%s", n, res.Content[0].Text)
	}

	// The ToolUseID must have been carried into the block, or hide-compress-calls
	// cannot find the call to hide and RebuildStateFromLog cannot replay it.
	blocks := ActiveBlocks(sess.State())
	if len(blocks) != 1 {
		t.Fatalf("%d active blocks, want 1", len(blocks))
	}
	if blocks[0].CompressCallID != "toolu_gate_1" {
		t.Fatalf("block records CompressCallID %q, want the ToolContext's %q — "+
			"without it the call cannot be hidden or replayed",
			blocks[0].CompressCallID, "toolu_gate_1")
	}
	// The compression persists: a fresh store over the same directory reloads
	// the block.
	reloaded, err := NewStateStore(sess.ArchiveRoot()).Load("sess", sess.ArchiveRoot())
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if len(reloaded.Blocks) != 1 {
		t.Fatalf("reloaded state has %d blocks, want the compression to have been persisted", len(reloaded.Blocks))
	}
}

// The permission decision must be Allow without asking. A prompt here would
// interrupt the flow the tool exists to keep smooth, and in a headless run it
// would hang.
func TestCompressNeverPromptsForPermission(t *testing.T) {
	ct := newCompressTool(newTestSession(t, 40000))
	dec := ct.CheckPermissions(t.Context(), json.RawMessage(`{"content":[]}`), tools.Context{})
	if dec.Behavior != tools.Allow {
		t.Fatalf("permission behavior = %s, want allow", dec.Behavior)
	}
}
