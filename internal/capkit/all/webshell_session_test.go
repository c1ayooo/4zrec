package all_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/flow/session"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell"
	shellsession "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/session"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
)

// These tests exercise the M2 assembly seam end to end: a real WebShell served
// over HTTP, wired through all.RegisterWebShellOpener into a session.Manager,
// then driven by shellkit's session tools through runtime.Call — the same path an
// agent takes. The WebShell adapter is not merely unit-tested: session_exec,
// session_upload and session_download each move real bytes through it, and the
// host-side executor routes them through the gate-aware HTTPDoer, which is how a
// host is documented to wire a WebShell transport.

// ---- the target ----

// webShellServer is a minimal PHP-style shell: it answers pass+op+... and runs the
// command for real, so a passing test means the adapter's protocol handling
// works, not that a mock was called.
type webShellServer struct {
	mu     sync.Mutex
	pass   string
	files  map[string][]byte
	cmdLog []string
	server *httptest.Server
}

func newWebShellServer(t *testing.T) *webShellServer {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("this test runs commands through a POSIX shell: %v", err)
	}
	w := &webShellServer{pass: "s3cret", files: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/w.php", w.handle)
	w.server = httptest.NewServer(mux)
	t.Cleanup(w.server.Close)
	return w
}

func (w *webShellServer) handle(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("pass") != w.pass {
		http.Error(rw, "denied", http.StatusForbidden)
		return
	}
	switch op := r.URL.Query().Get("op"); op {
	case "exec":
		cmd := r.URL.Query().Get("cmd")
		w.mu.Lock()
		w.cmdLog = append(w.cmdLog, cmd)
		w.mu.Unlock()
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput() //nolint:gosec // test-only target
		if err != nil && len(out) == 0 {
			fmt.Fprintf(rw, "err: %v", err)
			return
		}
		_, _ = rw.Write(out)
	case "write":
		w.mu.Lock()
		w.files[r.URL.Query().Get("path")] = []byte(r.URL.Query().Get("data"))
		w.mu.Unlock()
		fmt.Fprint(rw, "written")
	case "read":
		w.mu.Lock()
		body, ok := w.files[r.URL.Query().Get("path")]
		w.mu.Unlock()
		if !ok {
			http.Error(rw, "missing", http.StatusNotFound)
			return
		}
		_, _ = rw.Write(body)
	default:
		http.Error(rw, "unknown op", http.StatusBadRequest)
	}
}

func (w *webShellServer) execs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.cmdLog...)
}

// ---- the host-provided Executor ----

// shellExecutor speaks the shell's op protocol over the host's gate-aware
// HTTPDoer: this is the "host must implement the actual command/file operation"
// boundary from shellkit's README, done the way a real host would.
type shellExecutor struct {
	doer core.HTTPDoer
	base string
	pass string
}

func (e *shellExecutor) call(ctx context.Context, op string, params map[string]string) (*shellsession.ExecResult, error) {
	q := url.Values{"pass": {e.pass}, "op": {op}}
	for k, v := range params {
		q.Set(k, v)
	}
	resp, err := e.doer.Do(ctx, core.Request{
		Method: http.MethodGet, URL: e.base + "/w.php?" + q.Encode(),
	})
	if err != nil {
		return nil, err
	}
	// The test target returns the file body verbatim, so the executor declares no
	// encoding. Declaring it is what keeps the adapter from guessing — and from
	// corrupting text that merely happens to look like base64.
	return &shellsession.ExecResult{Output: string(resp.Body), HTTPStatus: resp.Status}, nil
}

func (e *shellExecutor) Exec(ctx context.Context, _ shellsession.Session, command string) (*shellsession.ExecResult, error) {
	return e.call(ctx, "exec", map[string]string{"cmd": command})
}

func (e *shellExecutor) File(ctx context.Context, _ shellsession.Session, op shellsession.FileOp) (*shellsession.ExecResult, error) {
	switch op.Action {
	case "write":
		return e.call(ctx, "write", map[string]string{"path": op.Path, "data": string(op.Content)})
	case "read":
		return e.call(ctx, "read", map[string]string{"path": op.Path})
	default:
		return nil, fmt.Errorf("unsupported file action %q", op.Action)
	}
}

// ---- the assembly under test ----

// webshellRuntime builds the chain a host would: a Manager, the WebShell opener
// registered through all.RegisterWebShellOpener, shellkit's tools in a runtime
// behind a real gate-aware transport, and a scope that admits the test host.
func webshellRuntime(t *testing.T, shellURL string) *runtime.Runtime {
	t.Helper()
	manager := session.NewManager(nil, nil)
	exec := &shellExecutor{doer: newTransport(), base: shellURL, pass: "s3cret"}
	if err := all.RegisterWebShellOpener(manager, exec); err != nil {
		t.Fatalf("RegisterWebShellOpener: %v", err)
	}
	reg := core.NewRegistry()
	if err := reg.Add(core.Spec{Manifest: shell.Manifest(), New: shell.NewCapability}); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(runtime.Config{
		Scope: gates.StaticScope(hostOf(shellURL)), Approval: gates.AutoApprove(),
		Limiter: gates.NewLimiter(), Audit: noAudit{}, Sessions: manager,
		HTTP: newTransport(),
	}, reg)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	return rt
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

func newTransport() *httpx.Client {
	return httpx.New(gates.AllowAllScope(), gates.NewLimiter(), noAudit{})
}

type noAudit struct{}

func (noAudit) Record(context.Context, core.AuditEvent) {}

func callTool(t *testing.T, rt *runtime.Runtime, tool string, input map[string]any) core.Result {
	t.Helper()
	var raw json.RawMessage
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		raw = b
	}
	res, err := rt.Call(context.Background(), tool, raw, core.CallContext{ProjectID: 1, Actor: "test"})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return res
}

func TestWebShellSessionRoundTrip(t *testing.T) {
	shell := newWebShellServer(t)
	rt := webshellRuntime(t, shell.server.URL)

	// 1. Open: the opener the helper registered must answer kind=webshell, with
	// the transport parameters riding in options as documented.
	opened := callTool(t, rt, "session_open", map[string]any{
		"kind": "webshell", "host": shell.server.URL + "/w.php",
		"secret": shell.pass,
		"options": map[string]string{
			"shell_type": "php", "cmd_param": "cmd", "protocol": "plain",
		},
	})
	if opened.Status != core.StatusSuccess {
		t.Fatalf("session_open failed: %s / %s", opened.Summary, errText(opened))
	}
	var openData struct {
		SessionID string `json:"session_id"`
		Kind      string `json:"kind"`
	}
	if err := json.Unmarshal(opened.Data, &openData); err != nil {
		t.Fatal(err)
	}
	if openData.Kind != "webshell" || openData.SessionID == "" {
		t.Fatalf("open data = %+v", openData)
	}

	// 2. Exec: a real command must return its real output, through the adapter.
	ran := callTool(t, rt, "session_exec", map[string]any{
		"session_id": openData.SessionID, "command": "echo hello-from-webshell",
	})
	if ran.Status != core.StatusSuccess {
		t.Fatalf("session_exec failed: %s / %s", ran.Summary, errText(ran))
	}
	var execData struct {
		Stdout string `json:"stdout"`
	}
	if err := json.Unmarshal(ran.Data, &execData); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(execData.Stdout, "hello-from-webshell") {
		t.Fatalf("stdout = %q (expected the command's real output)", execData.Stdout)
	}

	// 3. Upload: the WebShell must satisfy core.Uploader (docs §5.1 optional
	// capability) and the bytes must land on the target.
	uploaded := callTool(t, rt, "session_upload", map[string]any{
		"session_id": openData.SessionID, "remote": "/tmp/capkit-webshell-test",
		"content": "payloadbytes", // 12 base64-shaped chars: a sniffer would decode these to garbage
	})
	if uploaded.Status != core.StatusSuccess {
		t.Fatalf("session_upload failed: %s / %s", uploaded.Summary, errText(uploaded))
	}
	shell.mu.Lock()
	stored := string(shell.files["/tmp/capkit-webshell-test"])
	shell.mu.Unlock()
	if stored != "payloadbytes" {
		t.Fatalf("uploaded bytes did not reach the target: %q", stored)
	}

	// 4. Download: the same file must come back.
	downloaded := callTool(t, rt, "session_download", map[string]any{
		"session_id": openData.SessionID, "remote": "/tmp/capkit-webshell-test",
	})
	if downloaded.Status != core.StatusSuccess {
		t.Fatalf("session_download failed: %s / %s", downloaded.Summary, errText(downloaded))
	}
	var dlData struct {
		Bytes int `json:"bytes"`
	}
	if err := json.Unmarshal(downloaded.Data, &dlData); err != nil {
		t.Fatal(err)
	}
	if dlData.Bytes != len("payloadbytes") {
		t.Fatalf("downloaded %d bytes, want %d", dlData.Bytes, len("payloadbytes"))
	}

	// 5. Close, and the idempotent close the contract promises.
	closed := callTool(t, rt, "session_close", map[string]any{"session_id": openData.SessionID})
	if closed.Status != core.StatusSuccess {
		t.Fatalf("session_close failed: %s", closed.Summary)
	}
	again := callTool(t, rt, "session_close", map[string]any{"session_id": openData.SessionID})
	if again.Status != core.StatusSuccess {
		t.Fatalf("closing twice must stay successful: %s", again.Summary)
	}

	if execs := shell.execs(); len(execs) != 1 || execs[0] != "echo hello-from-webshell" {
		t.Fatalf("the target saw %v, want exactly the one command sent", execs)
	}
}

func TestWebShellSessionListSeesTheOpenedSession(t *testing.T) {
	shell := newWebShellServer(t)
	rt := webshellRuntime(t, shell.server.URL)
	opened := callTool(t, rt, "session_open", map[string]any{
		"kind": "webshell", "host": shell.server.URL + "/w.php", "secret": shell.pass,
	})
	if opened.Status != core.StatusSuccess {
		t.Fatalf("open: %s", opened.Summary)
	}
	listed := callTool(t, rt, "session_list", nil)
	var listData struct {
		Count    int `json:"count"`
		Sessions []struct {
			Kind string `json:"kind"`
			Host string `json:"host"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(listed.Data, &listData); err != nil {
		t.Fatal(err)
	}
	if listData.Count != 1 || len(listData.Sessions) != 1 {
		t.Fatalf("list data = %+v", listData)
	}
	if listData.Sessions[0].Kind != "webshell" {
		t.Fatalf("kind = %q", listData.Sessions[0].Kind)
	}
}

func TestWebShellOpenerRejectsMissingCollaborators(t *testing.T) {
	manager := session.NewManager(nil, nil)
	if err := all.RegisterWebShellOpener(manager, nil); err == nil {
		t.Fatal("a nil Executor must be refused at assembly, not at open time")
	}
	if err := all.RegisterWebShellOpener(nil, &shellExecutor{}); err == nil {
		t.Fatal("a nil Manager must be refused")
	}
}

func TestWebShellOpenUnregisteredKind(t *testing.T) {
	shell := newWebShellServer(t)
	rt := webshellRuntime(t, shell.server.URL)
	res := callTool(t, rt, "session_open", map[string]any{"kind": "ssh", "host": "127.0.0.1"})
	if res.Error == nil || res.Error.Code != core.CodeTargetUnreachable {
		t.Fatalf("an unregistered kind must surface as unreachable: %+v", res.Error)
	}
	if !strings.Contains(res.Error.Message, "没有注册 ssh") {
		t.Fatalf("message should name the missing kind: %q", res.Error.Message)
	}
}

func errText(res core.Result) string {
	if res.Error == nil {
		return ""
	}
	return res.Error.Code + ": " + res.Error.Message
}
