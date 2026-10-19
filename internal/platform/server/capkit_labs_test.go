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

// openLab opens one session and returns its id.
func openLab(t *testing.T, b *capkitbridge.Bridge, open string) string {
	t.Helper()
	res, err := b.Call(context.Background(), "session_open", json.RawMessage(open), labCallContext())
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
	return out.SessionID
}

// execLab runs one command on an already-open session and returns stdout.
func execLab(t *testing.T, b *capkitbridge.Bridge, id, command string) (string, capkit.Result) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"session_id": id, "command": command})
	res, err := b.Call(context.Background(), "session_exec", raw, labCallContext())
	if err != nil {
		t.Fatalf("session_exec: %v", err)
	}
	if !res.OK {
		t.Fatalf("session_exec 失败: %s", res.Summary)
	}
	var out struct {
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
	}
	_ = json.Unmarshal(res.Data, &out)
	if out.ExitCode != 0 {
		t.Fatalf("命令退出码 %d: %s", out.ExitCode, out.Stdout)
	}
	return out.Stdout, res
}

func closeLab(t *testing.T, b *capkitbridge.Bridge, id string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"session_id": id})
	res, err := b.Call(context.Background(), "session_close", raw, labCallContext())
	if err != nil || !res.OK {
		t.Fatalf("session_close 失败: %v (%s)", err, res.Summary)
	}
}

func labCallContext() capkit.CallContext {
	return capkit.CallContext{ProjectID: 1, Actor: "lab"}
}

// openAndExec opens a session, runs one command, and closes it.
func openAndExec(t *testing.T, b *capkitbridge.Bridge, open, command string) (string, capkit.Result) {
	t.Helper()
	id := openLab(t, b, open)
	out, res := execLab(t, b, id, command)
	closeLab(t, b, id)
	return out, res
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

// labBridgeDB is labBridge plus the database transports, which the host wires
// through ExtraOpeners.
func labBridgeDB(t *testing.T) *capkitbridge.Bridge {
	t.Helper()
	scope := gates.StaticScope("127.0.0.1")
	limiter := gates.NewLimiter()
	audit := &capkitAudit{}
	b, err := capkitbridge.New(capkitbridge.Options{
		Scope:        scope,
		HTTP:         httpx.New(scope, limiter, audit),
		Process:      exec.New(scope, limiter, audit),
		Limiter:      limiter,
		Audit:        audit,
		Executor:     &webshellExecutor{http: httpx.New(scope, limiter, audit)},
		ExtraOpeners: dbOpeners(),
	})
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	return b
}

// TestLabMySQLSession runs a real statement round trip against a MySQL lab.
func TestLabMySQLSession(t *testing.T) {
	labEnabled(t)
	addr := os.Getenv("CAPKIT_MYSQL_LAB")
	if addr == "" {
		t.Skip("未设置 CAPKIT_MYSQL_LAB")
	}
	host, port := splitLabAddr(t, addr, 3306)
	open := `{"kind":"mysql","host":"` + host + `","port":` + strconv.Itoa(port) +
		`,"user":"` + labEnv("CAPKIT_MYSQL_USER", "root") +
		`","secret":"` + labEnv("CAPKIT_MYSQL_PASS", "capkit") +
		`","options":{"database":"` + labEnv("CAPKIT_MYSQL_DB", "app") + `"}}`
	out, _ := openAndExec(t, labBridgeDB(t), open, "SELECT 1+1 AS n")
	if !strings.Contains(out, "n") || !strings.Contains(out, "2") {
		t.Fatalf("mysql 查询结果异常: %q", out)
	}
}

// TestLabPostgresSession is the same for PostgreSQL.
func TestLabPostgresSession(t *testing.T) {
	labEnabled(t)
	addr := os.Getenv("CAPKIT_PG_LAB")
	if addr == "" {
		t.Skip("未设置 CAPKIT_PG_LAB")
	}
	host, port := splitLabAddr(t, addr, 5432)
	open := `{"kind":"postgres","host":"` + host + `","port":` + strconv.Itoa(port) +
		`,"user":"` + labEnv("CAPKIT_PG_USER", "capkit") +
		`","secret":"` + labEnv("CAPKIT_PG_PASS", "capkit") +
		`","options":{"database":"` + labEnv("CAPKIT_PG_DB", "app") + `"}}`
	out, _ := openAndExec(t, labBridgeDB(t), open, "SELECT current_database()")
	if !strings.Contains(out, "app") {
		t.Fatalf("postgres 查询结果异常: %q", out)
	}
}

// TestLabDBWriteIsLabelled checks the write marker the console shows: a write
// statement must come back with the 写操作 prefix, a read must not.
func TestLabDBWriteIsLabelled(t *testing.T) {
	labEnabled(t)
	addr := os.Getenv("CAPKIT_MYSQL_LAB")
	if addr == "" {
		t.Skip("未设置 CAPKIT_MYSQL_LAB")
	}
	host, port := splitLabAddr(t, addr, 3306)
	b := labBridgeDB(t)
	open := `{"kind":"mysql","host":"` + host + `","port":` + strconv.Itoa(port) +
		`,"user":"` + labEnv("CAPKIT_MYSQL_USER", "root") +
		`","secret":"` + labEnv("CAPKIT_MYSQL_PASS", "capkit") +
		`","options":{"database":"` + labEnv("CAPKIT_MYSQL_DB", "app") + `"}}`
	id := openLab(t, b, open)
	defer closeLab(t, b, id)
	wrote, _ := execLab(t, b, id, "CREATE TABLE IF NOT EXISTS zrec_probe (id int)")
	if !strings.Contains(wrote, "写操作") {
		t.Fatalf("写语句未标注: %q", wrote)
	}
	read, _ := execLab(t, b, id, "SELECT 1 AS n")
	if strings.Contains(read, "写操作") {
		t.Fatalf("读语句被误标为写: %q", read)
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
