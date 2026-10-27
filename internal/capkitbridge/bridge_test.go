package capkitbridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	capkit "github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	shellsession "github.com/c1ayooo/4zrec/internal/capkit/kits/shellkit/session"

	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// fakeExecutor stands in for the host's WebShell transport: it records the
// command it was handed and returns a fixed body.
type fakeExecutor struct {
	last string
	file bool
}

func (f *fakeExecutor) Exec(_ context.Context, _ shellsession.Session, command string) (*shellsession.ExecResult, error) {
	f.last = command
	return &shellsession.ExecResult{Output: "uid=33(www-data)\n", HTTPStatus: 200}, nil
}

func (f *fakeExecutor) File(_ context.Context, _ shellsession.Session, _ shellsession.FileOp) (*shellsession.ExecResult, error) {
	f.file = true
	return &shellsession.ExecResult{Output: "nope"}, nil
}

func newTestBridge(t *testing.T, exec shellsession.Executor) *Bridge {
	t.Helper()
	scope := gates.StaticScope("127.0.0.1")
	limiter := gates.NewLimiter()
	b, err := New(Options{
		Scope:    scope,
		HTTP:     httpx.New(scope, limiter, nopAudit{}),
		Limiter:  limiter,
		Executor: exec,
		Context: func(context.Context) capkit.CallContext {
			return capkit.CallContext{ProjectID: 1, Actor: "bridge-test"}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func toolByName(t *testing.T, tools []actool.CoreTool, name string) actool.CoreTool {
	t.Helper()
	for _, tl := range tools {
		if tl.Name() == name {
			return tl
		}
	}
	names := make([]string, 0, len(tools))
	for _, tl := range tools {
		names = append(names, tl.Name())
	}
	t.Fatalf("工具 %s 不在桥接结果里: %v", name, names)
	return nil
}

func TestNewRequiresScopeAndHTTP(t *testing.T) {
	if _, err := New(Options{}); err == nil || !strings.Contains(err.Error(), "Scope") {
		t.Fatalf("缺 Scope 应报错, got %v", err)
	}
	if _, err := New(Options{Scope: gates.StaticScope("h")}); err == nil || !strings.Contains(err.Error(), "HTTP") {
		t.Fatalf("缺 HTTP 应报错, got %v", err)
	}
}

func TestBridgeExposesSessionAndIdentityTools(t *testing.T) {
	b := newTestBridge(t, &fakeExecutor{})
	want := []string{
		"session_open", "session_exec", "session_upload", "session_download",
		"session_close", "session_list", "tunnel_open", "webshell_deploy",
		"identity_login", "identity_csrf", "identity_token_check",
	}
	tools := b.Tools()
	for _, name := range want {
		toolByName(t, tools, name)
	}
}

func TestAvailableKindsMatchRegisteredTransports(t *testing.T) {
	b := newTestBridge(t, &fakeExecutor{})
	got := strings.Join(b.AvailableKinds(), ",")
	// HTTP and Executor are supplied by the helper, Process is not: smb must
	// not be advertised as openable. cli is never advertised — the platform
	// host is not a project target, so a local session cannot be scoped.
	if got != "webshell,ssh,winrm" {
		t.Fatalf("AvailableKinds = %q, want webshell,ssh,winrm", got)
	}
	// A bridge without a WebShell executor must not advertise webshell.
	bare, err := New(Options{
		Scope: gates.StaticScope("127.0.0.1"),
		HTTP:  httpx.New(gates.StaticScope("127.0.0.1"), gates.NewLimiter(), nopAudit{}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, kind := range bare.AvailableKinds() {
		if kind == "webshell" {
			t.Fatalf("未注入 Executor 却声明 webshell 可用")
		}
	}
}

func TestSessionRoundTripReachesExecutor(t *testing.T) {
	exec := &fakeExecutor{}
	b := newTestBridge(t, exec)
	tools := b.Tools()
	ctx := context.Background()

	open := toolByName(t, tools, "session_open")
	res, err := open.Call(ctx, json.RawMessage(`{
		"kind":"webshell","host":"http://127.0.0.1/shell.php","secret":"pw",
		"options":{"shell_type":"php","cmd_param":"cmd"}}`), nil)
	if err != nil {
		t.Fatalf("session_open: %v", err)
	}
	if res.IsError {
		t.Fatalf("session_open 失败: %s", res.Flatten())
	}
	if !strings.Contains(res.Flatten(), "[success]") {
		t.Fatalf("信封未渲染成功状态: %s", res.Flatten())
	}

	// The session id is what session_exec needs; take it from the envelope data.
	var opened struct {
		SessionID string `json:"session_id"`
	}
	text := res.Flatten()
	idx := strings.Index(text, "数据: ")
	if idx < 0 {
		t.Fatalf("信封里没有 data 段: %s", text)
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(text[idx+len("数据: "):])), &opened); err != nil {
		t.Fatalf("解析 data: %v (%s)", err, text)
	}
	if opened.SessionID == "" {
		t.Fatalf("session_open 没返回 session_id: %s", text)
	}

	execTool := toolByName(t, tools, "session_exec")
	input, _ := json.Marshal(map[string]string{"session_id": opened.SessionID, "command": "id"})
	res, err = execTool.Call(ctx, input, nil)
	if err != nil {
		t.Fatalf("session_exec: %v", err)
	}
	if res.IsError {
		t.Fatalf("session_exec 失败: %s", res.Flatten())
	}
	if exec.last != "id" {
		t.Fatalf("命令没有到达 Executor: %q", exec.last)
	}
	if !strings.Contains(res.Flatten(), "uid=33(www-data)") {
		t.Fatalf("执行结果没进信封: %s", res.Flatten())
	}
}

func TestScopeDeniedIsErrorResult(t *testing.T) {
	b := newTestBridge(t, &fakeExecutor{})
	open := toolByName(t, b.Tools(), "session_open")
	res, err := open.Call(context.Background(),
		json.RawMessage(`{"kind":"webshell","host":"http://evil.test/shell.php","secret":"pw"}`), nil)
	if err != nil {
		t.Fatalf("门禁拦截不应返回 Go error: %v", err)
	}
	if !res.IsError {
		t.Fatal("越权目标必须作为错误结果返回")
	}
	text := res.Flatten()
	if !strings.Contains(text, "scope_denied") {
		t.Fatalf("越权原因未透出: %s", text)
	}
}

func TestHighRiskAsksForApproval(t *testing.T) {
	decision := riskDecision("webshell_deploy", capkit.RiskHigh)
	if decision.Behavior != actool.Ask {
		t.Fatalf("高风险工具应触发人工确认, got %v", decision.Behavior)
	}
	decision = riskDecision("session_list", capkit.RiskLow)
	if decision.Behavior != actool.Allow {
		t.Fatalf("只读工具不应弹确认, got %v", decision.Behavior)
	}
}

func TestWebshellDeployWithoutDeployerReportsToolMissing(t *testing.T) {
	b := newTestBridge(t, &fakeExecutor{})
	deploy := toolByName(t, b.Tools(), "webshell_deploy")
	res, err := deploy.Call(context.Background(), json.RawMessage(`{
		"target":"http://127.0.0.1/exec.php","shell_type":"php"}`), nil)
	if err != nil {
		t.Fatalf("缺少 deployer 不应返回 Go error: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "tool_missing") {
		t.Fatalf("未注入 deployer 应报 tool_missing: %s", res.Flatten())
	}
}

func TestSessionListIsReadOnly(t *testing.T) {
	b := newTestBridge(t, &fakeExecutor{})
	list := toolByName(t, b.Tools(), "session_list")
	if !list.IsReadOnly(nil) {
		t.Fatal("session_list 应声明为只读")
	}
	exec := toolByName(t, b.Tools(), "session_exec")
	if exec.IsReadOnly(nil) {
		t.Fatal("session_exec 不得声明为只读")
	}
}

func TestReadOnlyToolNames(t *testing.T) {
	for _, name := range []string{"session_list", "identity_token_check"} {
		if !readOnlyTool(name) {
			t.Fatalf("%s 应为只读", name)
		}
	}
	if readOnlyTool("session_open") {
		t.Fatal("session_open 不得为只读")
	}
}

func TestRenderEnvelopeCarriesNextAndEvidence(t *testing.T) {
	res := capkit.Result{
		OK:      true,
		Status:  capkit.StatusSuccess,
		Summary: "已落地 php shell",
		Evidence: []capkit.EvidenceRef{
			{ID: "ev-1", Kind: "http_exchange", SHA256: "abc", Preview: "line1\nline2"},
		},
		Next: []capkit.NextStep{{Tool: "session_open", Reason: "接管会话"}},
	}
	text := renderEnvelope(res)
	for _, want := range []string{"[success]", "ev-1", "http_exchange", "sha256=abc", "next", "session_open"} {
		if want == "next" {
			want = "下一步"
		}
		if !strings.Contains(text, want) {
			t.Fatalf("信封缺少 %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "  line1\n  line2") {
		t.Fatalf("证据 preview 未缩进: %q", text)
	}
}
