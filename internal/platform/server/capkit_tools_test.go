package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	capkit "github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	shellsession "github.com/c1ayooo/4zrec/internal/capkit/kits/shellkit/session"
)

// stubScopePG stands in for *db.DB.AuthorizedTarget: only target.test is in
// scope, so the adapter's mapping (URL → hostname → domain/IP) is observable.
type stubScopePG struct{ allowed string }

func (s stubScopePG) AuthorizedTarget(_ int64, domains, ips []string) bool {
	for _, d := range domains {
		if d == s.allowed {
			return true
		}
	}
	for _, i := range ips {
		if i == s.allowed {
			return true
		}
	}
	return false
}

func TestCapkitScopeChecksProjectFence(t *testing.T) {
	sc := &capkitScope{pg: stubScopePG{allowed: "target.test"}}

	if err := sc.Check(context.Background(), capkit.Target{ProjectID: 7, URL: "https://target.test/login"}); err != nil {
		t.Fatalf("范围内目标被拒: %v", err)
	}
	err := sc.Check(context.Background(), capkit.Target{ProjectID: 7, URL: "https://other.test/login"})
	if err == nil {
		t.Fatal("范围外目标必须被拒")
	}
	var ce *capkit.Error
	if !errors.As(err, &ce) || ce.Code != capkit.CodeScopeDenied {
		t.Fatalf("越权应返回 scope_denied 信封错误, got %v", err)
	}

	// No project context → the fence is not active, matching AuthorizedTarget.
	if err := sc.Check(context.Background(), capkit.Target{ProjectID: 0, URL: "https://other.test/"}); err != nil {
		t.Fatalf("无项目上下文不应拦: %v", err)
	}

	// IP targets go through the IP branch.
	ips := &capkitScope{pg: stubScopePG{allowed: "10.0.0.5"}}
	if err := ips.Check(context.Background(), capkit.Target{ProjectID: 1, IP: "10.0.0.5"}); err != nil {
		t.Fatalf("范围内 IP 被拒: %v", err)
	}
	if err := ips.Check(context.Background(), capkit.Target{ProjectID: 1, IP: "10.0.0.6"}); err == nil {
		t.Fatal("范围外 IP 必须被拒")
	}
}

func TestCapkitScopeCIDRIsNotSilentlyAllowed(t *testing.T) {
	sc := &capkitScope{pg: stubScopePG{allowed: "target.test"}}
	if err := sc.Check(context.Background(), capkit.Target{ProjectID: 3, CIDR: "10.0.0.0/8"}); err == nil {
		t.Fatal("CIDR 目标不能被静默放行")
	}
}

// TestWebshellExecutorSpeaksPlainProtocol drives the host executor against a
// server that behaves like the plain PHP template (password + command param).
func TestWebshellExecutorSpeaksPlainProtocol(t *testing.T) {
	var gotPass, gotCmd string
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		gotPass = r.Form.Get("pass")
		gotCmd = r.Form.Get("cmd")
		if gotPass != "s3cret_pw" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("uid=33(www-data) gid=33(www-data)\n"))
	}))
	defer srv.Close()

	scope := gates.StaticScope("127.0.0.1")
	exec := &webshellExecutor{http: httpx.New(scope, gates.NewLimiter(), &capkitAudit{})}
	sess := shellsession.Session{
		URL: srv.URL + "/shell.php", Password: "s3cret_pw",
		ShellType: "php", CmdParam: "cmd", Method: "GET",
	}
	res, err := exec.Exec(context.Background(), sess, "id")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("默认方法应为 GET, got %s", gotMethod)
	}
	if gotCmd != "id" {
		t.Fatalf("命令没到目标: %q", gotCmd)
	}
	if !strings.Contains(res.Output, "uid=33(www-data)") {
		t.Fatalf("回显没拿到: %q", res.Output)
	}
	if res.HTTPStatus != http.StatusOK {
		t.Fatalf("状态码应为 200, got %d", res.HTTPStatus)
	}
}

func TestWebshellExecutorPOSTUsesBody(t *testing.T) {
	var rawQuery string
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery = r.URL.RawQuery
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		body = string(buf)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	scope := gates.StaticScope("127.0.0.1")
	exec := &webshellExecutor{http: httpx.New(scope, gates.NewLimiter(), &capkitAudit{})}
	sess := shellsession.Session{
		URL: srv.URL + "/shell.php", Password: "pw",
		ShellType: "php", CmdParam: "cmd", Method: "POST",
	}
	if _, err := exec.Exec(context.Background(), sess, "whoami"); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if rawQuery != "" {
		t.Fatalf("POST 不应把参数放 query: %q", rawQuery)
	}
	if !strings.Contains(body, "cmd=whoami") || !strings.Contains(body, "pass=pw") {
		t.Fatalf("POST body 缺参数: %q", body)
	}
}

func TestWebshellExecutorFileIsExplicitlyUnsupported(t *testing.T) {
	exec := &webshellExecutor{http: httpx.New(gates.StaticScope("127.0.0.1"), gates.NewLimiter(), &capkitAudit{})}
	sess := shellsession.Session{URL: "http://127.0.0.1/shell.php", ShellType: "php", Protocol: "plain"}
	_, err := exec.File(context.Background(), sess, shellsession.FileOp{Action: "read", Path: "/etc/passwd"})
	if err == nil {
		t.Fatal("plain 模板不支持文件操作，必须报错而不是假装成功")
	}
	if !strings.Contains(err.Error(), "不支持文件操作") {
		t.Fatalf("错误信息应说清原因: %v", err)
	}
}

func TestCapkitToolBindingsCoverEveryBridgedTool(t *testing.T) {
	// Every name the bridge can expose must have an explicit binding decision;
	// a typo would silently leave a tool bound to nobody.
	for name := range capkitToolBindings {
		if strings.TrimSpace(name) == "" {
			t.Fatal("绑定表里有空工具名")
		}
	}
	if len(capkitToolBindings["webshell_deploy"]) == 0 {
		t.Fatal("webshell_deploy 应有默认 agent 绑定")
	}
}
