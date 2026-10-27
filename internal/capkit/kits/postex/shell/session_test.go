package shell_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/auditlog"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/exec"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/settings"
	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/flow/session"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell"
	shellsession "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/session"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
)

// fakeExecutor stands in for a host WebShell transport.
type fakeExecutor struct{}

func (fakeExecutor) Exec(_ context.Context, _ shellsession.Session, cmd string) (*shellsession.ExecResult, error) {
	return &shellsession.ExecResult{Output: "OUT:" + cmd, HTTPStatus: 200, TrafficID: "ev_1"}, nil
}
func (fakeExecutor) File(_ context.Context, _ shellsession.Session, op shellsession.FileOp) (*shellsession.ExecResult, error) {
	switch op.Action {
	case "read":
		// base64("file-content"), declared: the adapter decodes on the host's
		// word rather than guessing (a plain "abcdefgh" is also valid base64).
		return &shellsession.ExecResult{Output: "ZmlsZS1jb250ZW50", HTTPStatus: 200, Encoding: "base64"}, nil
	default:
		return &shellsession.ExecResult{Output: "ok", HTTPStatus: 200}, nil
	}
}

func newRuntime(t *testing.T) (*runtime.Runtime, *session.Manager) {
	t.Helper()
	reg := core.NewRegistry()
	if err := all.RegisterSession(reg); err != nil {
		t.Fatal(err)
	}
	scope := gates.StaticScope("127.0.0.1")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()

	mgr := session.NewManager(nil, nil)
	mgr.RegisterOpener("cli", &session.CLIOpener{Runner: exec.NewLocal(nil)})
	mgr.RegisterOpener("webshell", &shell.WebShellOpener{Executor: fakeExecutor{}})

	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		HTTP: httpx.New(scope, lim, audit), Settings: settings.New(nil),
		Sessions: mgr,
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	return rt, mgr
}

func TestSessionOpenExecClose(t *testing.T) {
	rt, _ := newRuntime(t)
	ctx := context.Background()

	open, _ := json.Marshal(map[string]any{"kind": "webshell", "host": "http://127.0.0.1/shell.php"})
	res, err := rt.Call(ctx, "session_open", open, core.CallContext{ProjectID: 1, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("open status = %q summary=%q", res.Status, res.Summary)
	}
	var data map[string]any
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	id, _ := data["session_id"].(string)
	if id == "" {
		t.Fatal("no session_id returned")
	}

	execIn, _ := json.Marshal(map[string]any{"session_id": id, "command": "whoami"})
	execRes, err := rt.Call(ctx, "session_exec", execIn, core.CallContext{ProjectID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if execRes.Status != core.StatusSuccess {
		t.Fatalf("exec status = %q", execRes.Status)
	}
	if !strings.Contains(string(execRes.Data), "OUT:whoami") {
		t.Fatalf("exec data = %s", execRes.Data)
	}
	if len(execRes.Evidence) == 0 {
		t.Fatal("exec should surface an evidence ref")
	}

	// list shows the session
	listRes, _ := rt.Call(ctx, "session_list", json.RawMessage(`{}`), core.CallContext{ProjectID: 1})
	if !strings.Contains(string(listRes.Data), id) {
		t.Fatalf("list data = %s", listRes.Data)
	}

	closeIn, _ := json.Marshal(map[string]any{"session_id": id})
	closeRes, err := rt.Call(ctx, "session_close", closeIn, core.CallContext{ProjectID: 1})
	if err != nil || closeRes.Status != core.StatusSuccess {
		t.Fatalf("close = %v %q", err, closeRes.Status)
	}

	// exec after close → not_found. A distinct TaskID avoids the idempotency
	// cache (identical input+context would legitimately reuse the first result).
	again, err := rt.Call(ctx, "session_exec", execIn, core.CallContext{ProjectID: 1, TaskID: "after-close"})
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != core.StatusFailed || again.Error.Code != core.CodeNotFound {
		t.Fatalf("expected not_found, got %q %+v", again.Status, again.Error)
	}
}

func TestSessionUploadDownload(t *testing.T) {
	rt, _ := newRuntime(t)
	ctx := context.Background()
	open, _ := json.Marshal(map[string]any{"kind": "webshell", "host": "http://127.0.0.1/shell.php"})
	res, _ := rt.Call(ctx, "session_open", open, core.CallContext{ProjectID: 1})
	var data map[string]any
	_ = json.Unmarshal(res.Data, &data)
	id := data["session_id"].(string)

	up, _ := json.Marshal(map[string]any{"session_id": id, "remote": "/tmp/x", "content": "hello"})
	upRes, _ := rt.Call(ctx, "session_upload", up, core.CallContext{ProjectID: 1})
	if upRes.Status != core.StatusSuccess {
		t.Fatalf("upload status = %q", upRes.Status)
	}

	dl, _ := json.Marshal(map[string]any{"session_id": id, "remote": "/tmp/x"})
	dlRes, _ := rt.Call(ctx, "session_download", dl, core.CallContext{ProjectID: 1})
	if dlRes.Status != core.StatusSuccess {
		t.Fatalf("download status = %q", dlRes.Status)
	}
	// The fake returns base64("file-content"); the adapter decodes it. No
	// evidence sink is wired here, so the bytes stay out of Data and the
	// envelope carries a reference instead (§5.5.4).
	if strings.Contains(string(dlRes.Data), "ZmlsZS1jb250ZW50") {
		t.Fatalf("file content must not be inlined in Data: %s", dlRes.Data)
	}
	if len(dlRes.Evidence) != 1 || dlRes.Evidence[0].Kind != "file" || dlRes.Evidence[0].Size == 0 {
		t.Fatalf("download evidence = %+v", dlRes.Evidence)
	}
}

func TestSessionExecMissingSession(t *testing.T) {
	rt, _ := newRuntime(t)
	in, _ := json.Marshal(map[string]any{"session_id": "nope", "command": "id"})
	res, err := rt.Call(context.Background(), "session_exec", in, core.CallContext{ProjectID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("error = %+v", res.Error)
	}
}

func TestSessionOpenScopeDenied(t *testing.T) {
	rt, _ := newRuntime(t)
	in, _ := json.Marshal(map[string]any{"kind": "cli", "host": "example.com"})
	res, err := rt.Call(context.Background(), "session_open", in, core.CallContext{ProjectID: 1})
	if err == nil {
		t.Fatal("expected scope denial")
	}
	if res.Status != core.StatusBlocked {
		t.Fatalf("status = %q", res.Status)
	}
}

func TestSessionMissingManagerFailsClosed(t *testing.T) {
	reg := core.NewRegistry()
	if err := all.RegisterSession(reg); err != nil {
		t.Fatal(err)
	}
	scope := gates.StaticScope("127.0.0.1")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	// The manifest declares it requires the "sessions" port, so a host that
	// omits it cannot construct the runtime at all — fail closed, not open.
	_, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		HTTP: httpx.New(scope, lim, audit), Settings: settings.New(nil),
	}, reg)
	if err == nil || !strings.Contains(err.Error(), "sessions") {
		t.Fatalf("expected missing-sessions error, got %v", err)
	}
}

func TestSessionToolsRegisteredWithSchemas(t *testing.T) {
	m := shell.Manifest()
	// 7 session tools + webshell_deploy (M2-4).
	if len(m.Tools) != 8 {
		t.Fatalf("tools = %d, want 8", len(m.Tools))
	}
	names := map[string]bool{}
	for _, tool := range m.Tools {
		if len(tool.InputSchema) == 0 || len(tool.OutputSchema) == 0 {
			t.Fatalf("%s missing schema", tool.Name)
		}
		if names[tool.Name] {
			t.Fatalf("duplicate tool %q", tool.Name)
		}
		names[tool.Name] = true
	}
	for _, want := range []string{
		"session_open", "session_exec", "session_upload", "session_download",
		"tunnel_open", "session_list", "session_close", "webshell_deploy",
	} {
		if !names[want] {
			t.Fatalf("missing tool %q", want)
		}
	}
	// webshell_deploy writes executable content, so it must be approval-gated.
	for _, tool := range m.Tools {
		if tool.Name == "webshell_deploy" && tool.Risk != core.RiskHigh {
			t.Fatalf("webshell_deploy risk = %q, want high", tool.Risk)
		}
	}
	_ = httptest.NewServer // keep httptest import available for future cases
}

// recordingEvidence captures evidence records for assertions.
type recordingEvidence struct{ records []core.Evidence }

func (e *recordingEvidence) Record(_ context.Context, ev core.Evidence) (string, error) {
	e.records = append(e.records, ev)
	return "ev_shell_1", nil
}

func newRuntimeWithEvidence(t *testing.T, ev core.EvidenceSink) *runtime.Runtime {
	t.Helper()
	reg := core.NewRegistry()
	if err := all.RegisterSession(reg); err != nil {
		t.Fatal(err)
	}
	scope := gates.StaticScope("127.0.0.1", "local")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	mgr := session.NewManager(nil, nil)
	mgr.RegisterOpener("cli", &session.CLIOpener{Runner: exec.NewLocal(audit)})
	mgr.RegisterOpener("webshell", &shell.WebShellOpener{Executor: fakeExecutor{}})
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		HTTP: httpx.New(scope, lim, audit), Settings: settings.New(nil),
		Sessions: mgr, Evidence: ev,
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func openSession(t *testing.T, rt *runtime.Runtime, kind, host string) string {
	t.Helper()
	in, _ := json.Marshal(map[string]any{"kind": kind, "host": host})
	res, err := rt.Call(context.Background(), "session_open", in, core.CallContext{ProjectID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("open %s = %q %s", kind, res.Status, res.Summary)
	}
	var data map[string]any
	_ = json.Unmarshal(res.Data, &data)
	id, _ := data["session_id"].(string)
	if id == "" {
		t.Fatal("no session_id")
	}
	return id
}

// TestSessionDownloadStoresFileAsEvidence is the §5.5.4 gate: with an evidence
// store available, file content goes there and Data carries only a reference.
func TestSessionDownloadStoresFileAsEvidence(t *testing.T) {
	ev := &recordingEvidence{}
	rt := newRuntimeWithEvidence(t, ev)
	id := openSession(t, rt, "webshell", "http://127.0.0.1/shell.php")

	in, _ := json.Marshal(map[string]any{"session_id": id, "remote": "/tmp/x"})
	res, err := rt.Call(context.Background(), "session_download", in, core.CallContext{ProjectID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("download = %q %s", res.Status, res.Summary)
	}
	if strings.Contains(string(res.Data), "file-content") {
		t.Fatalf("file content leaked into Data: %s", res.Data)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Kind != "file" {
		t.Fatalf("evidence = %+v", res.Evidence)
	}
	if res.Evidence[0].Size != len("file-content") {
		t.Fatalf("evidence size = %d", res.Evidence[0].Size)
	}
	if len(res.Evidence[0].SHA256) != 64 {
		t.Fatalf("sha256 = %q", res.Evidence[0].SHA256)
	}
	if len(ev.records) != 1 || string(ev.records[0].Response) != "file-content" {
		t.Fatalf("evidence sink did not get the file: %+v", ev.records)
	}
}

// TestSessionExecRecordsOutputWithoutTransportEvidence covers the local CLI
// transport, which has no traffic id of its own: the tool stores the output.
func TestSessionExecRecordsOutputWithoutTransportEvidence(t *testing.T) {
	ev := &recordingEvidence{}
	rt := newRuntimeWithEvidence(t, ev)
	id := openSession(t, rt, "cli", "local")

	in, _ := json.Marshal(map[string]any{"session_id": id, "command": "echo evidence-path"})
	res, err := rt.Call(context.Background(), "session_exec", in, core.CallContext{ProjectID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("exec = %q %s", res.Status, res.Summary)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Kind != "command_output" {
		t.Fatalf("evidence = %+v", res.Evidence)
	}
	if len(ev.records) != 1 || !strings.Contains(string(ev.records[0].Response), "evidence-path") {
		t.Fatalf("evidence sink did not get the output: %+v", ev.records)
	}
}
