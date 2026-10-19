package server

// Opt-in transport labs: open a real session of each kind against a real
// target and run one command through it. Gated on CAPKIT_LABS=1 plus the
// per-kind address, because CI has no containers.
//
//   CAPKIT_LABS=1
//   CAPKIT_SSH_LAB=127.0.0.1:12222   CAPKIT_SSH_USER=root  CAPKIT_SSH_PASS=capkit
//   CAPKIT_SMB_LAB=127.0.0.1:445     CAPKIT_SMB_USER=capkit CAPKIT_SMB_PASS=capkit
//                                    CAPKIT_SMB_SHARE=public
//
// The WebShell kind is covered by capkit_e2e_test.go (probe → deploy → take
// over); WinRM has no lab on Linux and is covered by the transport wiring tests
// in capkitbridge. scripts/capkit-labs.sh brings the containers up.

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit/adapters/exec"
	"github.com/c1ayooo/capkit/adapters/httpx"
	capkit "github.com/c1ayooo/capkit/core"
	"github.com/c1ayooo/capkit/gates"

	"github.com/c1ayooo/4zrec/internal/capkitbridge"
)

// labBridge builds a bridge with the same transports as the server (SSH, CLI,
// SMB through the gate-aware runner, WinRM through httpx) but a permissive
// static scope, so the test exercises transport code rather than authorization.
func labBridge(t *testing.T) *capkitbridge.Bridge {
	t.Helper()
	scope := gates.StaticScope("127.0.0.1")
	limiter := gates.NewLimiter()
	audit := &capkitAudit{}
	b, err := capkitbridge.New(capkitbridge.Options{
		Scope:    scope,
		HTTP:     httpx.New(scope, limiter, audit),
		Process:  exec.New(scope, limiter, audit),
		Limiter:  limiter,
		Audit:    audit,
		Executor: &webshellExecutor{http: httpx.New(scope, limiter, audit)},
	})
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	return b
}

func labEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("CAPKIT_LABS") == "" {
		t.Skip("需要 CAPKIT_LABS=1 与对应靶机环境变量（见 scripts/capkit-labs.sh）")
	}
}

func labEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// openAndExec opens one session and runs a command, returning stdout.
func openAndExec(t *testing.T, b *capkitbridge.Bridge, open, command string) (string, capkit.Result) {
	t.Helper()
	ctx := context.Background()
	cc := capkit.CallContext{ProjectID: 1, Actor: "lab"}
	res, err := b.Call(ctx, "session_open", json.RawMessage(open), cc)
	if err != nil {
		t.Fatalf("session_open: %v", err)
	}
	if !res.OK {
		t.Fatalf("session_open 失败: %s", res.Summary)
	}
	var out struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil || out.SessionID == "" {
		t.Fatalf("session_id 解析失败: %s (%v)", string(res.Data), err)
	}
	execRaw, _ := json.Marshal(map[string]any{"session_id": out.SessionID, "command": command})
	execRes, err := b.Call(ctx, "session_exec", execRaw, cc)
	if err != nil {
		t.Fatalf("session_exec: %v", err)
	}
	if !execRes.OK {
		t.Fatalf("session_exec 失败: %s", execRes.Summary)
	}
	closeRaw, _ := json.Marshal(map[string]string{"session_id": out.SessionID})
	if closeRes, err := b.Call(ctx, "session_close", closeRaw, cc); err != nil || !closeRes.OK {
		t.Fatalf("session_close 失败: %v", execRes.Summary)
	}
	var execOut struct {
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
	}
	_ = json.Unmarshal(execRes.Data, &execOut)
	if execOut.ExitCode != 0 {
		t.Fatalf("命令退出码 %d: %s", execOut.ExitCode, execOut.Stdout)
	}
	return execOut.Stdout, execRes
}

func TestLabSSHSession(t *testing.T) {
	labEnabled(t)
	addr := os.Getenv("CAPKIT_SSH_LAB")
	if addr == "" {
		t.Skip("未设置 CAPKIT_SSH_LAB")
	}
	host, port := splitLabAddr(t, addr, 22)
	open := `{"kind":"ssh","host":"` + host + `","port":` + strconv.Itoa(port) +
		`,"user":"` + labEnv("CAPKIT_SSH_USER", "root") +
		`","secret":"` + labEnv("CAPKIT_SSH_PASS", "capkit") + `"}`
	out, _ := openAndExec(t, labBridge(t), open, "id")
	if !strings.Contains(out, "uid=") {
		t.Fatalf("ssh 会话未返回 id 输出: %q", out)
	}
}

func TestLabSMBSession(t *testing.T) {
	labEnabled(t)
	addr := os.Getenv("CAPKIT_SMB_LAB")
	if addr == "" {
		t.Skip("未设置 CAPKIT_SMB_LAB")
	}
	host, port := splitLabAddr(t, addr, 445)
	open := `{"kind":"smb","host":"` + host + `","port":` + strconv.Itoa(port) +
		`","user":"` + labEnv("CAPKIT_SMB_USER", "capkit") +
		`","secret":"` + labEnv("CAPKIT_SMB_PASS", "capkit") +
		`","options":{"share":"` + labEnv("CAPKIT_SMB_SHARE", "public") + `"}}`
	out, res := openAndExec(t, labBridge(t), open, "ls")
	// smbclient prints the share banner on stdout; an auth or share failure
	// would have surfaced as a non-zero exit above.
	if !strings.Contains(strings.ToLower(out), "blocks") && !strings.Contains(out, ".") {
		t.Fatalf("smb 会话 ls 输出异常: %q", out)
	}
	if !strings.Contains(res.Summary, "smb") && res.Summary == "" {
		t.Fatalf("会话摘要为空")
	}
}

func splitLabAddr(t *testing.T, addr string, defaultPort int) (string, int) {
	t.Helper()
	host, portText, found := strings.Cut(addr, ":")
	if !found {
		return addr, defaultPort
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("非法地址 %q: %v", addr, err)
	}
	return host, port
}
