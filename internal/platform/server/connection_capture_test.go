package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	capkit "github.com/c1ayooo/capkit/core"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/toolface/intercept"
)

// captureTestServer 建一个挂好项目的任务上下文,供自动落库路径使用。
// 返回 server 与带任务上下文的 ctx;清理随 t 结束。
func captureTestServer(t *testing.T) (*Server, context.Context, int64) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	proj, err := m.pg.Projects().CreateProject(fmt.Sprintf("自动落库测试%d", time.Now().UnixNano()), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	task, err := m.pg.CreateTask("连接台账自动落库", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Exec(`UPDATE tasks SET project_id=$1 WHERE id=$2`, proj.ID, task.ID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM connections WHERE project_id=$1`, proj.ID)
		_, _ = m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		_ = m.pg.Projects().DeleteProject(proj.ID)
	})
	ctx := intercept.WithTaskContext(t.Context(), strconv.FormatInt(task.ID, 10), "test-agent", nil)
	return &Server{m: m}, ctx, proj.ID
}

func listConns(t *testing.T, s *Server, projectID int64, kind string) []*db.Connection {
	t.Helper()
	rows, err := s.m.pg.ListConnections(context.Background(), projectID, kind, 200)
	if err != nil {
		t.Fatalf("list connections: %v", err)
	}
	return rows
}

// TestDetectWebshellInvocation http_probe 的启发式识别:命令参数 + 口令参数 +
// 命令输出三条同时成立才算命中。
func TestDetectWebshellInvocation(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		url     string
		body    string
		status  int
		resp    string
		hit     bool
		wantURL string
		cmdP    string
		passP   string
	}{
		{
			name: "linux_id", method: "GET",
			url:    "http://103.145.163.60:8080/zzsg.jsp?k=k7Qm2xVp9Ld4&c=id",
			status: 200, resp: "uid=1001 gid=0(root) groups=0(root)",
			hit: true, wantURL: "http://103.145.163.60:8080/zzsg.jsp", cmdP: "c", passP: "k",
		},
		{
			name: "windows_whoami_slash", method: "GET",
			url:    "http://h/1.jsp?pass=p@ss&cmd=whoami",
			status: 200, resp: "nt authority\\system",
			hit: true, wantURL: "http://h/1.jsp", cmdP: "cmd", passP: "pass",
		},
		{
			name: "post_form", method: "POST",
			url:    "http://h/shell.php",
			body:   "cmd=uname+-a&pass=abc123",
			status: 200, resp: "Linux h 5.15.0 x86_64 GNU/Linux",
			hit: true, wantURL: "http://h/shell.php", cmdP: "cmd", passP: "pass",
		},
		{
			name: "keeps_routing_param", method: "GET",
			url:    "http://h/x.php?a=shell&pass=zzz123&cmd=pwd",
			status: 200, resp: "/var/www/html",
			hit: true, wantURL: "http://h/x.php?a=shell", cmdP: "cmd", passP: "pass",
		},
		{
			name: "html_page_not_a_shell", method: "GET",
			url:    "http://h/index.php?cat=id&k=abc123",
			status: 200, resp: "<!DOCTYPE html><html><body>category id listing</body></html>",
			hit: false,
		},
		{
			name: "cmd_param_but_login_page", method: "GET",
			url:    "http://h/gate.jsp?k=secret1&c=id",
			status: 200, resp: "<html><head><title>Login</title></head></html>",
			hit: false,
		},
		{
			name: "no_password_param", method: "GET",
			url:    "http://h/diag?cmd=id",
			status: 200, resp: "uid=0(root)",
			hit: false,
		},
		{
			name: "404", method: "GET",
			url:    "http://h/gone.jsp?k=k7Qm2xVp9Ld4&c=id",
			status: 404, resp: "uid=0(root)",
			hit: false,
		},
		{
			name: "output_does_not_match", method: "GET",
			url:    "http://h/x.jsp?k=k7Qm2xVp9Ld4&c=id",
			status: 200, resp: "welcome to the dashboard",
			hit: false,
		},
		{
			name: "plain_page_no_params", method: "GET",
			url:    "http://h/index.html",
			status: 200, resp: "hello",
			hit: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, params, ok := detectWebshellInvocation(tc.method, tc.url, tc.body, tc.status, tc.resp)
			if ok != tc.hit {
				t.Fatalf("hit=%v want %v (target=%q params=%+v)", ok, tc.hit, target, params)
			}
			if !tc.hit {
				return
			}
			if target != tc.wantURL {
				t.Fatalf("target=%q want %q", target, tc.wantURL)
			}
			if params.CmdParam != tc.cmdP || params.PassParam != tc.passP {
				t.Fatalf("params=%+v", params)
			}
			if params.Password == "" {
				t.Fatalf("password missing: %+v", params)
			}
		})
	}
}

// TestNewWebshellConnectionShape 台账 extra 的键必须与消费方(webshellConfigOf /
// sessionOpenInputFor)读取的键一致。
func TestNewWebshellConnectionShape(t *testing.T) {
	c, err := newWebshellConnection("HTTP://Target.LOCAL:8081/BE/zzktb.JSP", webshellParams{
		Password: "pw", CmdParam: "c", PassParam: "k", Method: "post", Protocol: "plain",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != "webshell" || c.Host != "target.local" || c.Port != 8081 || c.Secret != "pw" {
		t.Fatalf("row wrong: %+v", c)
	}
	if c.Extra == nil {
		t.Fatal("extra missing")
	}
	var extra map[string]any
	if err := json.Unmarshal(c.Extra, &extra); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"url": "http://target.local:8081/BE/zzktb.JSP", "cmd_param": "c",
		"pass_param": "k", "method": "POST", "protocol": "plain", "shell_type": "jsp",
	}
	for k, v := range want {
		if got, _ := extra[k].(string); got != v {
			t.Errorf("extra[%s] = %q, want %q", k, got, v)
		}
	}
	// 消费方:控制台配置要能读出同样的落点与参数名。
	conf := webshellConfigOf(&db.Connection{Kind: "webshell", Secret: "pw", Extra: c.Extra})
	if conf.URL != "http://target.local:8081/BE/zzktb.JSP" || conf.CmdParam != "c" ||
		conf.PassParam != "k" || conf.ShellType != "jsp" || conf.Protocol != "plain" {
		t.Fatalf("config mismatch: %+v", conf)
	}
	if opts := conf.webshellOptions(); opts["protocol"] != "plain" || opts["shell_type"] != "jsp" {
		t.Fatalf("options mismatch: %v", opts)
	}
}

// TestCaptureWebshellDeploy 投递成功后自动落库(source=discovered, status=alive)。
func TestCaptureWebshellDeploy(t *testing.T) {
	s, ctx, projectID := captureTestServer(t)
	data, _ := json.Marshal(map[string]any{
		"file_url": "http://203.0.113.9:8080/up/a.jsp",
		"webshell": map[string]any{
			"kind": "webshell", "host": "http://203.0.113.9:8080/up/a.jsp", "secret": "genPass1",
			"options": map[string]string{"shell_type": "jsp", "cmd_param": "cmd", "pass_param": "pass", "method": "POST"},
		},
	})
	s.observeCapkitResult(ctx, "webshell_deploy", json.RawMessage(`{"target":"http://203.0.113.9:8080/x"}`),
		capkit.Result{OK: true, Data: data})

	rows := listConns(t, s, projectID, "webshell")
	if len(rows) != 1 {
		t.Fatalf("want 1 webshell row, got %d", len(rows))
	}
	got := rows[0]
	if got.Source != "discovered" || got.Status != "alive" || got.Secret != "genPass1" {
		t.Fatalf("row wrong: %+v", got)
	}
	if got.Host != "203.0.113.9" || got.Port != 8080 {
		t.Fatalf("host/port not derived from url: %+v", got)
	}
	if db.WebshellURLOf(got) != "http://203.0.113.9:8080/up/a.jsp" {
		t.Fatalf("url wrong: %s", got.Extra)
	}

	// 同一落点再次投递 → 合并,不产生第二行。
	s.observeCapkitResult(ctx, "webshell_deploy", json.RawMessage(`{"target":"http://203.0.113.9:8080/x"}`),
		capkit.Result{OK: true, Data: data})
	if rows := listConns(t, s, projectID, "webshell"); len(rows) != 1 {
		t.Fatalf("re-deploy must merge: got %d rows", len(rows))
	}
}

// TestCaptureSessionOpen session_open 建连成功 → 落库;cli 本机会话不落。
func TestCaptureSessionOpen(t *testing.T) {
	s, ctx, projectID := captureTestServer(t)

	// webshell:host 就是落点 URL,参数在 options 里。
	s.observeCapkitResult(ctx, "session_open", json.RawMessage(`{
		"kind":"webshell","host":"http://198.51.100.7:8080/zzsg.jsp","secret":"k7Qm2xVp9Ld4",
		"options":{"cmd_param":"c","pass_param":"k","shell_type":"jsp","method":"GET"}}`),
		capkit.Result{OK: true})
	// ssh:普通主机 + 用户名。
	s.observeCapkitResult(ctx, "session_open", json.RawMessage(`{
		"kind":"ssh","host":"198.51.100.8","port":22,"user":"ubuntu","secret":"s3cr3t"}`),
		capkit.Result{OK: true})
	// 数据库:附加信息进 extra。
	s.observeCapkitResult(ctx, "session_open", json.RawMessage(`{
		"kind":"postgres","host":"198.51.100.9","port":5432,"user":"jasperuser","secret":"jasperuser",
		"options":{"database":"jasper_prod","sslmode":"disable"}}`),
		capkit.Result{OK: true})
	// cli 是本机会话,目标不是项目资产 → 不登记。
	s.observeCapkitResult(ctx, "session_open", json.RawMessage(`{"kind":"cli","host":"127.0.0.1","secret":"x"}`),
		capkit.Result{OK: true})
	// 失败结果不登记。
	s.observeCapkitResult(ctx, "session_open", json.RawMessage(`{"kind":"ssh","host":"198.51.100.10","secret":"bad"}`),
		capkit.Result{OK: false})

	shells := listConns(t, s, projectID, "webshell")
	if len(shells) != 1 || shells[0].Secret != "k7Qm2xVp9Ld4" || shells[0].Host != "198.51.100.7" {
		t.Fatalf("webshell row wrong: %+v", shells)
	}
	if conf := webshellConfigOf(shells[0]); conf.CmdParam != "c" || conf.PassParam != "k" || conf.ShellType != "jsp" {
		t.Fatalf("webshell params lost: %+v", conf)
	}

	sshs := listConns(t, s, projectID, "ssh")
	if len(sshs) != 1 || sshs[0].Username != "ubuntu" || sshs[0].Port != 22 || sshs[0].Source != "discovered" {
		t.Fatalf("ssh row wrong: %+v", sshs)
	}

	pgs := listConns(t, s, projectID, "postgres")
	if len(pgs) != 1 {
		t.Fatalf("postgres row missing: %+v", pgs)
	}
	var extra map[string]any
	_ = json.Unmarshal(pgs[0].Extra, &extra)
	if extra["database"] != "jasper_prod" || extra["sslmode"] != "disable" {
		t.Fatalf("db extra wrong: %s", pgs[0].Extra)
	}

	if rows := listConns(t, s, projectID, "cli"); len(rows) != 0 {
		t.Fatalf("cli must not be registered: %+v", rows)
	}
}

// TestCredentialRegisterWebshell 手工登记 webshell:url 推导 host/port,
// 参数名进 extra(旧实现没有 extra,登记出来是条打不开的残废行)。
func TestCredentialRegisterWebshell(t *testing.T) {
	s, ctx, projectID := captureTestServer(t)
	in := fmt.Sprintf(`{"kind":"webshell","url":"http://203.0.113.50:8080/z.jsp?x=1",
		"secret":"pw9","cmd_param":"c","pass_param":"k","shell_type":"jsp","note":"已存在的前台 shell","project_id":%d}`, projectID)
	res, err := s.toolCredentialRegister().Call(ctx, json.RawMessage(in), nil)
	if err != nil || res.IsError {
		t.Fatalf("register: %v %s", err, res.Flatten())
	}
	rows := listConns(t, s, projectID, "webshell")
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	got := rows[0]
	if got.Source != "manual" || got.Status != "unknown" {
		t.Fatalf("manual registration semantics wrong: %+v", got)
	}
	if got.Host != "203.0.113.50" || got.Port != 8080 {
		t.Fatalf("host/port not derived: %+v", got)
	}
	conf := webshellConfigOf(got)
	if conf.URL != "http://203.0.113.50:8080/z.jsp?x=1" || conf.CmdParam != "c" || conf.PassParam != "k" || conf.ShellType != "jsp" {
		t.Fatalf("config not usable: %+v", conf)
	}

	// 缺 url 必须报错,而不是落一条没有落点的行。
	res2, _ := s.toolCredentialRegister().Call(ctx, json.RawMessage(
		fmt.Sprintf(`{"kind":"webshell","host":"203.0.113.51","project_id":%d}`, projectID)), nil)
	if !res2.IsError || !strings.Contains(res2.Flatten(), "url") {
		t.Fatalf("webshell without url must fail: %s", res2.Flatten())
	}
	if rows := listConns(t, s, projectID, "webshell"); len(rows) != 1 {
		t.Fatalf("failed registration must not write: %d rows", len(rows))
	}
}

// TestCredentialRegisterExtraForDBKind 普通类型的 extra(database 等)能落库。
func TestCredentialRegisterExtraForDBKind(t *testing.T) {
	s, ctx, projectID := captureTestServer(t)
	in := fmt.Sprintf(`{"kind":"postgres","host":"203.0.113.60","username":"jasperuser","secret":"jasperuser",
		"extra":{"database":"jasper_prod"},"project_id":%d}`, projectID)
	res, err := s.toolCredentialRegister().Call(ctx, json.RawMessage(in), nil)
	if err != nil || res.IsError {
		t.Fatalf("register: %v %s", err, res.Flatten())
	}
	rows := listConns(t, s, projectID, "postgres")
	if len(rows) != 1 || rows[0].Port != 5432 {
		t.Fatalf("row wrong: %+v", rows)
	}
	var extra map[string]any
	_ = json.Unmarshal(rows[0].Extra, &extra)
	if extra["database"] != "jasper_prod" {
		t.Fatalf("extra not stored: %s", rows[0].Extra)
	}
}

// TestCaptureProbeWebshell 端到端:http_probe 的识别结果写进台账。
func TestCaptureProbeWebshell(t *testing.T) {
	s, ctx, projectID := captureTestServer(t)
	note := s.captureProbeWebshell(ctx, "GET",
		"http://103.145.163.60:8080/zzsg.jsp?k=k7Qm2xVp9Ld4&c=id", "", 200,
		"uid=1001 gid=0(root) groups=0(root)")
	if note == "" {
		t.Fatal("没有识别出 shell 调用")
	}
	rows := listConns(t, s, projectID, "webshell")
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	got := rows[0]
	if db.WebshellURLOf(got) != "http://103.145.163.60:8080/zzsg.jsp" {
		t.Fatalf("落点应去掉命令/口令参数: %s", got.Extra)
	}
	if got.Secret != "k7Qm2xVp9Ld4" || got.Source != "discovered" {
		t.Fatalf("row wrong: %+v", got)
	}
	conf := webshellConfigOf(got)
	if conf.CmdParam != "c" || conf.PassParam != "k" || conf.ShellType != "jsp" {
		t.Fatalf("params wrong: %+v", conf)
	}
}
