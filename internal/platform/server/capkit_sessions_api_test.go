package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit/adapters/httpx"
	capkit "github.com/c1ayooo/capkit/core"
	"github.com/c1ayooo/capkit/gates"
	shellsession "github.com/c1ayooo/capkit/kits/shellkit/session"

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

func newSessionAPIServer(t *testing.T) *Server {
	t.Helper()
	scope := &capkitScope{pg: stubScopePG{allowed: "127.0.0.1"}}
	limiter := gates.NewLimiter()
	audit := &capkitAudit{}
	b, err := capkitbridge.New(capkitbridge.Options{
		Scope: scope, HTTP: httpx.New(scope, limiter, audit), Limiter: limiter,
		Audit: audit, Executor: apiFakeExec{},
	})
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	return &Server{capkitBridge: b}
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
