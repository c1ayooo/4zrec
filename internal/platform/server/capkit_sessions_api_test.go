package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	capkit "github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	shellsession "github.com/c1ayooo/4zrec/internal/capkit/kits/shellkit/session"

	"github.com/c1ayooo/4zrec/internal/capkitbridge"
)

// apiFakeExec is the WebShell transport for the API tests: exec succeeds and
// echoes a fixed body; no network is involved.
type apiFakeExec struct{}

func (apiFakeExec) Exec(context.Context, shellsession.Session, string) (*shellsession.ExecResult, error) {
	return &shellsession.ExecResult{Output: "uid=33(www-data)\n", HTTPStatus: 200}, nil
}

func (apiFakeExec) File(context.Context, shellsession.Session, shellsession.FileOp) (*shellsession.ExecResult, error) {
	return &shellsession.ExecResult{Output: "unsupported"}, nil
}

func newSessionAPIServer(t *testing.T, openers ...map[string]capkit.SessionOpener) *Server {
	t.Helper()
	s := &Server{capkitBridge: apitestBridge(t, openers...)}
	return s
}

// apitestBridge 是测试用的桥接:假 WebShell 执行器,scope 放行 127.0.0.1。
// DB 相关的测试再按需追加 ExtraOpeners。
func apitestBridge(t *testing.T, openers ...map[string]capkit.SessionOpener) *capkitbridge.Bridge {
	t.Helper()
	scope := &capkitScope{pg: stubScopePG{allowed: "127.0.0.1"}}
	limiter := gates.NewLimiter()
	audit := &capkitAudit{}
	opts := capkitbridge.Options{
		Scope: scope, HTTP: httpx.New(scope, limiter, audit), Limiter: limiter,
		Audit: audit, Executor: apiFakeExec{},
	}
	if len(openers) > 0 {
		opts.ExtraOpeners = openers[0]
	}
	b, err := capkitbridge.New(opts)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	return b
}

func withProject(r *http.Request, projectID int64) *http.Request {
	sc := APIScope{ProjectID: projectID}
	if projectID <= 0 {
		sc = APIScope{Global: true}
	}
	return r.WithContext(withAPIScope(r.Context(), sc))
}

func openSession(t *testing.T, s *Server, projectID int64) string {
	t.Helper()
	body := `{"kind":"webshell","host":"http://127.0.0.1/shell.php","secret":"pw"}`
	r := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/open", strings.NewReader(body)), projectID)
	w := httptest.NewRecorder()
	s.capkitSessionOpen(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("open: %d %s", w.Code, w.Body.String())
	}
	var out capkitSessionDTO
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.ID == "" {
		t.Fatalf("open 返回不完整: %v (%s)", err, w.Body.String())
	}
	return out.ID
}

func TestSessionAPIOpenAndList(t *testing.T) {
	s := newSessionAPIServer(t)
	id := openSession(t, s, 7)

	r := withProject(httptest.NewRequest(http.MethodGet, "/api/capkit/sessions", nil), 7)
	w := httptest.NewRecorder()
	s.capkitSessionList(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Sessions []capkitSessionDTO `json:"sessions"`
		Enabled  bool               `json:"enabled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析列表: %v", err)
	}
	if !out.Enabled || len(out.Sessions) != 1 || out.Sessions[0].ID != id || out.Sessions[0].ProjectID != 7 {
		t.Fatalf("列表不对: %s", w.Body.String())
	}
}

func TestSessionAPIProjectIsolation(t *testing.T) {
	s := newSessionAPIServer(t)
	id := openSession(t, s, 7)

	// Another project must not see it.
	r := withProject(httptest.NewRequest(http.MethodGet, "/api/capkit/sessions", nil), 8)
	w := httptest.NewRecorder()
	s.capkitSessionList(w, r)
	var out struct {
		Sessions []capkitSessionDTO `json:"sessions"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out.Sessions) != 0 {
		t.Fatalf("项目 8 不该看到项目 7 的会话: %s", w.Body.String())
	}

	// Nor drive it.
	exec := func(projectID int64) int {
		req := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/x/exec",
			strings.NewReader(`{"command":"id"}`)), projectID)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.capkitSessionExec(rec, req)
		return rec.Code
	}
	if code := exec(8); code != http.StatusNotFound {
		t.Fatalf("跨项目执行应 404, got %d", code)
	}
	if code := exec(7); code != http.StatusOK {
		t.Fatalf("本项目执行应 200, got %d", code)
	}
}

func TestSessionAPIExecAndClose(t *testing.T) {
	s := newSessionAPIServer(t)
	id := openSession(t, s, 7)

	req := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/x/exec",
		strings.NewReader(`{"command":"id"}`)), 7)
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	s.capkitSessionExec(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("exec: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析 exec: %v", err)
	}
	if !strings.Contains(out.Stdout, "uid=33(www-data)") {
		t.Fatalf("stdout 不对: %s", w.Body.String())
	}

	creq := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/x/close", nil), 7)
	creq.SetPathValue("id", id)
	cw := httptest.NewRecorder()
	s.capkitSessionClose(cw, creq)
	if cw.Code != http.StatusOK {
		t.Fatalf("close: %d %s", cw.Code, cw.Body.String())
	}

	// After close the owner record is gone and the session is absent.
	if _, ok := s.capkitBridge.SessionProject(id); ok {
		t.Fatal("关闭后不应再记录归属")
	}
}

func TestSessionAPIExecRequiresCommand(t *testing.T) {
	s := newSessionAPIServer(t)
	id := openSession(t, s, 7)
	req := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/x/exec",
		strings.NewReader(`{}`)), 7)
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	s.capkitSessionExec(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺 command 应 400, got %d", w.Code)
	}
}

func TestSessionAPIOpenValidatesRequiredFields(t *testing.T) {
	s := newSessionAPIServer(t)
	r := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/open",
		strings.NewReader(`{"kind":"webshell"}`)), 7)
	w := httptest.NewRecorder()
	s.capkitSessionOpen(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺 host 应 400, got %d %s", w.Code, w.Body.String())
	}
}

func TestSessionAPIKindCatalogMatchesTransports(t *testing.T) {
	s := newSessionAPIServer(t)
	r := withProject(httptest.NewRequest(http.MethodGet, "/api/capkit/sessions", nil), 7)
	w := httptest.NewRecorder()
	s.capkitSessionList(w, r)
	var out struct {
		Kinds []capkitKindDTO `json:"kinds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]capkitKindDTO{}
	for _, k := range out.Kinds {
		byID[k.ID] = k
	}
	if !byID["webshell"].Available {
		t.Fatalf("注入 Executor 后 webshell 应可用: %+v", byID["webshell"])
	}
	if !byID["ssh"].Available {
		t.Fatalf("ssh opener 总是注册,应可用: %+v", byID["ssh"])
	}
	if byID["cli"].Available || byID["smb"].Available {
		t.Fatalf("未注入 ProcessRunner 时 cli/smb 不应可用")
	}
	if byID["db"].Available {
		t.Fatalf("数据库类型由 opener 决定可用性,未注册时不应标记可用")
	}
	if byID["mysql"].Available || byID["postgres"].Available {
		t.Fatalf("未注入数据库 opener 时 mysql/postgres 不应可用")
	}
	if byID["webshell"].Category == "" || len(byID["webshell"].Fields) == 0 {
		t.Fatalf("目录项需要分类与字段: %+v", byID["webshell"])
	}
}

func TestSessionAPIKindCatalogWithDatabaseOpener(t *testing.T) {
	s := newSessionAPIServer(t, map[string]capkit.SessionOpener{"mysql": stubOpener{}})
	r := withProject(httptest.NewRequest(http.MethodGet, "/api/capkit/sessions", nil), 7)
	w := httptest.NewRecorder()
	s.capkitSessionList(w, r)
	var out struct {
		Kinds []capkitKindDTO `json:"kinds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]capkitKindDTO{}
	for _, k := range out.Kinds {
		byID[k.ID] = k
	}
	if !byID["mysql"].Available {
		t.Fatalf("注册了 mysql opener 后应可用: %+v", byID["mysql"])
	}
	if byID["mysql"].Category != "database" {
		t.Fatalf("mysql 应归入 database 分类, got %q", byID["mysql"].Category)
	}
	if !strings.Contains(strings.Join(byID["mysql"].Fields, ","), "database") {
		t.Fatalf("mysql 表单需要库名字段: %v", byID["mysql"].Fields)
	}
	if byID["postgres"].Available {
		t.Fatalf("postgres 未注册 opener,不应可用")
	}
}

// stubOpener is a no-op transport: enough for catalogue and validation tests,
// which never reach Exec.
type stubOpener struct{}

func (stubOpener) Open(context.Context, capkit.SessionSpec) (capkit.Session, error) {
	return stubSession{}, nil
}

type stubSession struct{}

func (stubSession) Exec(context.Context, string, capkit.ExecOpts) (capkit.Output, error) {
	return capkit.Output{}, nil
}

func (stubSession) Info() capkit.SessionInfo { return capkit.SessionInfo{Kind: "mysql"} }

func (stubSession) Close() error { return nil }

func TestSessionAPIOpenRejectsUnavailableKind(t *testing.T) {
	s := newSessionAPIServer(t)
	r := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/open",
		strings.NewReader(`{"kind":"mysql","host":"127.0.0.1"}`)), 7)
	w := httptest.NewRecorder()
	s.capkitSessionOpen(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未注册 opener 的类型应 400, got %d %s", w.Code, w.Body.String())
	}
}

// TestSessionAPISSHLab drives the whole HTTP path — API handler, bridge, real
// opener — against a real sshd. Opt-in: CAPKIT_SSH_LAB=127.0.0.1:12222.
func TestSessionAPISSHLab(t *testing.T) {
	addr := os.Getenv("CAPKIT_SSH_LAB")
	if addr == "" {
		t.Skip("未设置 CAPKIT_SSH_LAB")
	}
	host, portText, found := strings.Cut(addr, ":")
	if !found {
		t.Fatalf("地址需为 host:port: %q", addr)
	}
	s := newSessionAPIServer(t)

	body := `{"kind":"ssh","host":"` + host + `","port":` + portText +
		`,"user":"` + labEnvOr("CAPKIT_SSH_USER", "root") +
		`","secret":"` + labEnvOr("CAPKIT_SSH_PASS", "capkit") + `"}`
	req := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/open", strings.NewReader(body)), 7)
	w := httptest.NewRecorder()
	s.capkitSessionOpen(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("open: %d %s", w.Code, w.Body.String())
	}
	var opened capkitSessionDTO
	if err := json.Unmarshal(w.Body.Bytes(), &opened); err != nil || opened.ID == "" {
		t.Fatalf("open 响应异常: %s (%v)", w.Body.String(), err)
	}

	execReq := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/x/exec",
		strings.NewReader(`{"command":"id"}`)), 7)
	execReq.SetPathValue("id", opened.ID)
	execW := httptest.NewRecorder()
	s.capkitSessionExec(execW, execReq)
	if execW.Code != http.StatusOK {
		t.Fatalf("exec: %d %s", execW.Code, execW.Body.String())
	}
	var out struct {
		Stdout string `json:"stdout"`
	}
	_ = json.Unmarshal(execW.Body.Bytes(), &out)
	if !strings.Contains(out.Stdout, "uid=") {
		t.Fatalf("ssh exec 输出异常: %q", out.Stdout)
	}

	closeReq := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/x/close",
		strings.NewReader(`{}`)), 7)
	closeReq.SetPathValue("id", opened.ID)
	closeW := httptest.NewRecorder()
	s.capkitSessionClose(closeW, closeReq)
	if closeW.Code != http.StatusOK {
		t.Fatalf("close: %d %s", closeW.Code, closeW.Body.String())
	}
}

// TestSessionAPIDBLab drives a database session through the HTTP surface:
// open with a real MySQL, run SELECT, close. Opt-in: CAPKIT_MYSQL_LAB=host:port.
func TestSessionAPIDBLab(t *testing.T) {
	addr := os.Getenv("CAPKIT_MYSQL_LAB")
	if addr == "" {
		t.Skip("未设置 CAPKIT_MYSQL_LAB")
	}
	host, portText, found := strings.Cut(addr, ":")
	if !found {
		t.Fatalf("地址需为 host:port: %q", addr)
	}
	s := newSessionAPIServer(t, dbOpeners())

	body := `{"kind":"mysql","host":"` + host + `","port":` + portText +
		`,"user":"` + labEnvOr("CAPKIT_MYSQL_USER", "root") +
		`","secret":"` + labEnvOr("CAPKIT_MYSQL_PASS", "capkit") +
		`","options":{"database":"` + labEnvOr("CAPKIT_MYSQL_DB", "app") + `"}}`
	req := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/open", strings.NewReader(body)), 7)
	w := httptest.NewRecorder()
	s.capkitSessionOpen(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("open: %d %s", w.Code, w.Body.String())
	}
	var opened capkitSessionDTO
	if err := json.Unmarshal(w.Body.Bytes(), &opened); err != nil || opened.ID == "" {
		t.Fatalf("open 响应异常: %s (%v)", w.Body.String(), err)
	}

	execReq := withProject(httptest.NewRequest(http.MethodPost, "/api/capkit/sessions/x/exec",
		strings.NewReader(`{"command":"SELECT 1+1 AS n"}`)), 7)
	execReq.SetPathValue("id", opened.ID)
	execW := httptest.NewRecorder()
	s.capkitSessionExec(execW, execReq)
	if execW.Code != http.StatusOK {
		t.Fatalf("exec: %d %s", execW.Code, execW.Body.String())
	}
	var out struct {
		Stdout string `json:"stdout"`
	}
	_ = json.Unmarshal(execW.Body.Bytes(), &out)
	if !strings.Contains(out.Stdout, "n") || !strings.Contains(out.Stdout, "2") {
		t.Fatalf("SQL 输出异常: %q", out.Stdout)
	}
}

func labEnvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func TestSessionAPIWithoutBridgeIsDisabled(t *testing.T) {
	s := &Server{capkitErr: errCapkitBridgeDisabledForTest}
	r := withProject(httptest.NewRequest(http.MethodGet, "/api/capkit/sessions", nil), 7)
	w := httptest.NewRecorder()
	s.capkitSessionList(w, r)
	var out struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Enabled {
		t.Fatalf("未启用时应返回 enabled=false: %s", w.Body.String())
	}
}

var errCapkitBridgeDisabledForTest = errTest("bridge disabled")

type errTest string

func (e errTest) Error() string { return string(e) }

var _ = capkit.StatusSuccess
