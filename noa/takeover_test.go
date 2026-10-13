package noa

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/acllm"
	"github.com/Autumn-27/artex/askernel"
	"github.com/Autumn-27/artex/tools"
)

// Consumer-side seam assertions: the takeover slots into askernel's Noa
// options, and its View replaces acllm.MessagesForAPI as the request
// projection (the role norma's ContextView takeover played).
var (
	_ askernel.NoaTakeover = (*Takeover)(nil)
	_ askernel.NoaView     = (*Takeover)(nil)
)

// newTestSession builds a Session over a throwaway archive directory.
func newTestSession(t *testing.T, window int) *Session {
	t.Helper()
	sess, err := newSession(Options{
		ArchiveBaseDir: t.TempDir(), SessionID: "sess", ModelContextLimit: window,
	})
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	return sess
}

// Enable is the only entry point, and it is all-or-nothing: one call must fill
// Options.Noa with everything the kernel consumes.
func TestEnableWiresNoaIntoKernelOptions(t *testing.T) {
	base := t.TempDir()
	opts := &askernel.Options{}
	if err := Enable(opts, Options{ArchiveBaseDir: base, SessionID: "sess"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if opts.Noa == nil || opts.Noa.Takeover == nil {
		t.Fatal("Enable left Options.Noa.Takeover unset — noa is not enabled")
	}
	tk, ok := opts.Noa.Takeover.(*Takeover)
	if !ok {
		t.Fatalf("Takeover type = %T, want *noa.Takeover", opts.Noa.Takeover)
	}
	if opts.Noa.ArchiveBaseDir != base || opts.Noa.SessionID != "sess" {
		t.Errorf("NoaOptions = %+v, want the archive base and session id carried over", opts.Noa)
	}
	if opts.Noa.ModelContextLimit != defaultContextLimit {
		t.Errorf("ModelContextLimit = %d, want the conservative default %d when the host names no window",
			opts.Noa.ModelContextLimit, defaultContextLimit)
	}
	if tk.Session() == nil || tk.Session().ArchiveRoot() == "" {
		t.Error("the installed takeover carries no usable session")
	}
	// Explicit Config must be carried; ModelContextLimit stays untouched in that
	// case (the config's own limit governs), exactly like norma's Enable.
	opts2 := &askernel.Options{OnWarn: func(string) {}}
	cfg := DefaultConfig(200000)
	if err := Enable(opts2, Options{ArchiveBaseDir: t.TempDir(), SessionID: "s", Config: &cfg}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if opts2.Noa.OnWarn == nil {
		t.Error("an explicit Options.OnWarn was dropped")
	}
	if opts2.Noa.Config == nil {
		t.Error("the explicit Config was dropped from NoaOptions")
	}
	if got := opts2.Noa.Takeover.(*Takeover).Session().Config().ModelContextLimit; got != 200000 {
		t.Errorf("resolved session window = %d, want 200000 from the explicit Config", got)
	}
}

// EnableWithSession is Enable plus the session, so a host can inspect state or
// archives without reaching through the takeover.
func TestEnableWithSessionReturnsTheSession(t *testing.T) {
	base := t.TempDir()
	opts := &askernel.Options{}
	sess, err := EnableWithSession(opts, Options{ArchiveBaseDir: base, SessionID: "sess"})
	if err != nil {
		t.Fatalf("EnableWithSession: %v", err)
	}
	tk, ok := opts.Noa.Takeover.(*Takeover)
	if !ok {
		t.Fatalf("Takeover type = %T, want *noa.Takeover", opts.Noa.Takeover)
	}
	if sess != tk.Session() {
		t.Error("the returned session is not the one the takeover drives")
	}
	if want := base + "/sess"; sess.ArchiveRoot() != want {
		t.Errorf("archive root = %q, want %q (base joined with the session id)", sess.ArchiveRoot(), want)
	}
}

// A host that sets no OnWarn inherits the kernel's, so noa diagnostics are not
// silently swallowed (norma: o.OnWarn = opts.OnWarn).
func TestEnableFallsBackToTheHostsOnWarn(t *testing.T) {
	var got []string
	opts := &askernel.Options{OnWarn: func(m string) { got = append(got, m) }}
	cfg := DefaultConfig(200000)
	cfg.Tiers.MaxTier = 7 // outside the range the tier prompts cover
	if err := Enable(opts, Options{ArchiveBaseDir: t.TempDir(), SessionID: "s", Config: &cfg}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "noa: config: ") {
		t.Fatalf("host OnWarn = %v, want noa's config diagnostics forwarded", got)
	}
}

// An empty archive base must be refused, never defaulted: the archive is the
// only route back to compressed originals.
func TestEnableRefusesAMissingArchiveDir(t *testing.T) {
	opts := &askernel.Options{}
	if err := Enable(opts, Options{SessionID: "sess"}); err != ErrNoArchiveDir {
		t.Fatalf("Enable without ArchiveBaseDir = %v, want ErrNoArchiveDir", err)
	}
	if opts.Noa != nil {
		t.Error("a refused Enable must not leave Options.Noa half-wired")
	}
}

// ExtraTools is the Compress tool and nothing else.
func TestTakeoverExtraToolsIsTheCompressTool(t *testing.T) {
	tk, err := NewTakeover(Options{ArchiveBaseDir: t.TempDir(), SessionID: "s"})
	if err != nil {
		t.Fatalf("NewTakeover: %v", err)
	}
	ts := tk.ExtraTools()
	if len(ts) != 1 {
		t.Fatalf("ExtraTools returned %d tools, want exactly the Compress tool", len(ts))
	}
	ct := ts[0]
	if ct.Name() != CompressToolName {
		t.Fatalf("tool name = %q, want %q", ct.Name(), CompressToolName)
	}
	if ct.Description() != CompressToolDescription {
		t.Errorf("description does not match CompressToolDescription")
	}
	schema := ct.InputSchema()
	if schema == nil {
		t.Fatal("Compress advertises no schema; the model has nothing to aim for")
	}
	if _, ok := schema["properties"]; !ok {
		t.Fatalf("the advertised schema has no properties: %v", schema)
	}
	// The RawInput opt-out must be on, or the kernel's schema gate rejects the
	// malformed shapes ParseCompressArgs exists to repair.
	r, ok := ct.(interface{ AcceptsRawInput() bool })
	if !ok || !r.AcceptsRawInput() {
		t.Fatal("Compress does not report AcceptsRawInput, so the kernel validates its " +
			"arguments and the lenient parser never sees a malformed call")
	}
	// Not read-only: it mutates state and writes archives. Not concurrency-safe:
	// two racing compressions would interleave block allocation.
	if ct.IsReadOnly(nil) {
		t.Error("Compress reports read-only")
	}
	if ct.IsConcurrencySafe(nil) {
		t.Error("Compress reports concurrency-safe")
	}
}

// The resident prompt is one static segment holding the three permanent
// sections — static, because a byte that moves invalidates the prompt-cache
// prefix from that point on.
func TestTakeoverSystemPromptSegmentsAreResident(t *testing.T) {
	tk, err := NewTakeover(Options{ArchiveBaseDir: t.TempDir(), SessionID: "s"})
	if err != nil {
		t.Fatalf("NewTakeover: %v", err)
	}
	segs := tk.SystemPromptSegments()
	if len(segs) != 1 {
		t.Fatalf("SystemPromptSegments returned %d segments, want the one resident prompt", len(segs))
	}
	s := segs[0]
	for _, want := range []string{SystemPromptHeader, "NOA TAGS", "COMPRESSION SUMMARIES IN CONTEXT", "THE ARCHIVE"} {
		if !strings.Contains(s, want) {
			t.Errorf("resident prompt is missing %q", want)
		}
	}
	if again := tk.SystemPromptSegments(); again[0] != s {
		t.Error("the resident prompt is not static across calls; it cannot safely sit in the cacheable prefix")
	}
}

// View must project the history without touching it: the returned array is for
// one request only, and message identity is a content hash over the stored
// text.
func TestTakeoverViewProjectsPurely(t *testing.T) {
	sess := newTestSession(t, 200000)
	tk := &Takeover{sess: sess}
	msgs := []acllm.Message{
		userText(strings.Repeat("turn one body. ", 40)),
		userText(strings.Repeat("turn two body. ", 40)),
	}
	before := msgs[0].Content[0].Text

	view := tk.View(msgs)
	if len(view) == 0 {
		t.Fatal("View produced an empty projection")
	}
	if msgs[0].Content[0].Text != before {
		t.Fatal("View mutated the master history; ids would drift every turn")
	}
	// First sight assigns refs, and the tags ride on the projected copy only.
	if !strings.Contains(view[0].Text(), "<noa-ref id=") {
		t.Fatalf("projected user message carries no ref tag: %q", view[0].Text())
	}
	if strings.Contains(msgs[0].Content[0].Text, "<noa-ref") {
		t.Fatal("the ref tag leaked into the master history")
	}
}

// The Compress tool runs against the same session the View projected, so a
// compression is visible to the very next request (the shared-state contract).
func TestTakeoverToolAndViewShareOneState(t *testing.T) {
	sess := newTestSession(t, 200000)
	tk := &Takeover{sess: sess}

	var msgs []acllm.Message
	for i := 0; i < 24; i++ {
		body := strings.Repeat("working notes for the report. ", 67) // ~2000 chars each
		msgs = append(msgs, userText(body))
	}
	tk.View(msgs)
	if len(sess.State().MessageRefs.ByRef) < 16 {
		t.Fatalf("only %d refs assigned; the fixture is too short", len(sess.State().MessageRefs.ByRef))
	}

	// End the range well before the soft protected zone (the last 5 messages).
	args, err := json.Marshal(map[string]any{"content": []map[string]any{{
		"startId": IndexToRef(2), "endId": IndexToRef(14),
		"summary": strings.Repeat("Decisions and paths from the working notes; kept every file path and error. ", 4),
	}}})
	res, err := tk.ExtraTools()[0].Call(t.Context(), args, &tools.ToolContext{ToolUseID: "toolu_t1"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.IsError {
		t.Fatalf("a well-formed compression reported an error: %s", res.Content[0].Text)
	}
	blocks := ActiveBlocks(sess.State())
	if len(blocks) != 1 {
		t.Fatalf("%d active blocks after compression, want 1", len(blocks))
	}
	// The next View must NOT resurrect the compressed range: the block covers it.
	view := tk.View(msgs)
	for _, m := range view {
		if strings.Contains(m.Text(), "working notes for the report") && MessageRef(m) >= IndexToRef(2) && MessageRef(m) <= IndexToRef(13) {
			t.Fatalf("a message inside the compressed range survived the next view: ref %s", MessageRef(m))
		}
	}
}
