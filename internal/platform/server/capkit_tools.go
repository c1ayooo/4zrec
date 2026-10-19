package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/capkit/adapters/httpx"
	capkit "github.com/c1ayooo/capkit/core"
	"github.com/c1ayooo/capkit/gates"
	"github.com/c1ayooo/capkit/kits/identitykit"
	shellsession "github.com/c1ayooo/capkit/kits/shellkit/session"

	"github.com/c1ayooo/4zrec/internal/capkitbridge"
	"github.com/c1ayooo/4zrec/internal/toolface/intercept"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// capkitTools returns the capkit capabilities exposed to agents. A build failure
// is logged and yields no tools: a misconfigured bridge must not take the whole
// agent runtime down, and the reason is visible in the server log.
//
// The runtime lives on the Server, not in a package-level Once: two servers in
// one process (tests) must not share one session map.
func (s *Server) capkitTools() []actool.CoreTool {
	s.capkitMu.Lock()
	defer s.capkitMu.Unlock()
	if s.capkitBridge == nil && s.capkitErr == nil {
		s.capkitBridge, s.capkitErr = s.buildCapkitBridge()
		if s.capkitErr != nil {
			log.Printf("[capkit] 桥接未启用: %v", s.capkitErr)
		}
	}
	if s.capkitBridge == nil {
		return nil
	}
	return s.capkitBridge.Tools()
}

func (s *Server) buildCapkitBridge() (*capkitbridge.Bridge, error) {
	scope := &capkitScope{pg: s.m.pg}
	limiter := gates.NewLimiter()
	audit := &capkitAudit{}
	// capkit's own httpx adapter is the gate-aware transport: it re-checks scope
	// on every redirect hop and applies per-host rate limiting, which is exactly
	// the boundary a bridged tool must not bypass.
	httpDoer := httpx.New(scope, limiter, audit)

	points := newConfirmedPoints()
	deployer := &capkitDeployer{points: points}

	bridge, err := capkitbridge.New(capkitbridge.Options{
		Scope:    scope,
		HTTP:     httpDoer,
		Limiter:  limiter,
		Audit:    audit,
		Executor: &webshellExecutor{http: httpDoer},
		Flows:    identitykit.NewAuthFlowRegistry(),
		Deployer: deployer,
		Context: func(ctx context.Context) capkit.CallContext {
			return s.capkitCallContext(ctx)
		},
		// The deployer needs the runtime to reach the confirmed injection point,
		// and the runtime is built with the deployer already inside it.
		OnResult: func(ctx context.Context, tool string, input json.RawMessage, res capkit.Result) {
			s.observeCapkitResult(ctx, tool, input, res)
		},
	})
	if err != nil {
		return nil, err
	}
	deployer.bridge = bridge
	s.capkitPoints = points
	return bridge, nil
}

// capkitCallContext maps the host's per-call attribution onto capkit's caller
// identity. Project comes from the task/conversation the agent is running
// under, exactly as the RoE checks do; it is never taken from tool input.
func (s *Server) capkitCallContext(ctx context.Context) capkit.CallContext {
	cc := capkit.CallContext{}
	if id := s.roeProjectID(ctx, 0); id > 0 {
		cc.ProjectID = id
	}
	if taskID, agentName := intercept.TaskInfoFromContext(ctx); taskID != "" {
		cc.TaskID = taskID
		cc.Actor = agentName
	}
	return cc
}

// capkitToolBindings is the default agent binding per bridged tool. Session
// tools are for the agents that actually operate footholds; identity tools also
// serve recon (login-state checks before enumeration). job_status ships with the
// runtime and is bound wherever the other capkit tools are.
var capkitToolBindings = map[string][]string{
	"session_open":         {"worker", "pentest", "auto"},
	"session_exec":         {"worker", "pentest", "auto"},
	"session_upload":       {"worker", "pentest", "auto"},
	"session_download":     {"worker", "pentest", "auto"},
	"session_close":        {"worker", "pentest", "auto"},
	"session_list":         {"worker", "pentest", "auto", "planner"},
	"tunnel_open":          {"worker", "pentest", "auto"},
	"webshell_deploy":      {"worker", "pentest", "auto"},
	"identity_login":       {"worker", "pentest", "recon", "auto"},
	"identity_csrf":        {"worker", "pentest", "recon", "auto"},
	"identity_token_check": {"worker", "pentest", "recon", "auto"},
	"job_status":           {"worker", "pentest", "auto"},
	// exploitkit supplies the primitives the deployer and the agent both need:
	// cmdi_probe confirms a point, cmdi_execute proves command output (and is
	// what records the point for delivery). Bound to the same agents as the
	// deploy tool so a confirm → deploy chain is one agent's work.
	"cmdi_probe":     {"worker", "pentest", "auto"},
	"cmdi_execute":   {"worker", "pentest", "auto"},
	"ssti_probe":     {"worker", "pentest", "auto"},
	"lfi_probe":      {"worker", "pentest", "auto"},
	"lfi_read":       {"worker", "pentest", "auto"},
	"sqli_probe":     {"worker", "pentest", "auto"},
	"ssrf_probe":     {"worker", "pentest", "auto"},
	"redis_gopher":   {"worker", "pentest", "auto"},
	"deser_generate": {"worker", "pentest", "auto"},
}

// seedCapkitTools inserts the bridged tools into the tools table once, so they
// can be enabled/disabled and bound per agent from /system/tools like every
// other host tool. SeedTool is first-insert-only: UI edits survive restarts.
func (s *Server) seedCapkitTools() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	tools := s.capkitTools()
	if len(tools) == 0 {
		return
	}
	for _, t := range tools {
		bind, ok := capkitToolBindings[t.Name()]
		if !ok {
			// A newly registered capkit tool starts bound to nobody rather than
			// silently reaching every agent.
			bind = nil
		}
		schema, _ := json.Marshal(t.InputSchema())
		agents, _ := json.Marshal(bind)
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[capkit] seed tool %s: %v", t.Name(), err)
		}
	}
}

// capkitScope enforces the project's authorization scope through the same
// check the host's own tools use (project scope rules ∪ approved assets). A
// target outside it is a scope_denied envelope, not an error the agent can
// retry around.
type capkitScope struct {
	pg interface {
		AuthorizedTarget(int64, []string, []string) bool
	}
}

func (c *capkitScope) Check(_ context.Context, t capkit.Target) error {
	// No project context → the fence is not active (matches AuthorizedTarget's
	// own semantics for projectID <= 0).
	if t.ProjectID <= 0 || c.pg == nil {
		return nil
	}
	host := strings.TrimSpace(t.Host)
	if host == "" {
		host = strings.TrimSpace(t.IP)
	}
	if host == "" && t.URL != "" {
		if u, err := url.Parse(t.URL); err == nil {
			host = u.Hostname()
		}
	}
	if host == "" {
		if t.CIDR != "" {
			return capkit.ScopeDenied("CIDR 目标 " + t.CIDR + " 需展开为具体主机后再校验授权范围")
		}
		return nil
	}
	var domains, ips []string
	if net.ParseIP(host) != nil {
		ips = []string{host}
	} else {
		domains = []string{host}
	}
	if !c.pg.AuthorizedTarget(t.ProjectID, domains, ips) {
		return capkit.ScopeDenied(fmt.Sprintf("目标 %s 不在项目 %d 授权范围内", host, t.ProjectID))
	}
	return nil
}

// capkitAudit writes capkit's gate trace to the server log. It carries tool,
// risk, status and duration — never request bodies or credentials.
type capkitAudit struct{}

func (a *capkitAudit) Record(_ context.Context, ev capkit.AuditEvent) {
	if ev.Phase != "finish" {
		return
	}
	status := ev.Status
	if ev.Error != "" {
		status += "/" + ev.Error
	}
	log.Printf("[capkit] tool=%s risk=%s status=%s dur=%dms actor=%s project=%d",
		ev.Tool, ev.Risk, status, ev.DurationMS, ev.Actor, ev.ProjectID)
}

// webshellExecutor is the host boundary shellkit requires: it speaks the
// dropped payload's protocol over the gate-aware HTTP transport.
//
// The plain PHP/ASP/JSP templates take a password plus one command parameter,
// so Exec maps onto them directly. File operations are not supported by those
// templates; File reports that instead of returning an empty success, and the
// session tools surface it as an unavailable capability.
type webshellExecutor struct{ http capkit.HTTPDoer }

func (e *webshellExecutor) Exec(ctx context.Context, s shellsession.Session, command string) (*shellsession.ExecResult, error) {
	cmdParam := capkit.FirstNonEmpty(s.CmdParam, "cmd")
	passParam := capkit.FirstNonEmpty(s.PassParam, "pass")
	query := url.Values{}
	query.Set(passParam, s.Password)
	query.Set(cmdParam, command)

	res, err := e.call(ctx, s, query, nil)
	if err != nil {
		return nil, err
	}
	return &shellsession.ExecResult{Output: string(res.Body), HTTPStatus: res.Status}, nil
}

func (e *webshellExecutor) File(_ context.Context, s shellsession.Session, op shellsession.FileOp) (*shellsession.ExecResult, error) {
	return nil, fmt.Errorf("该 WebShell 协议(%s/%s)不支持文件操作: %s", s.ShellType, s.Protocol, op.Action)
}

func (e *webshellExecutor) call(ctx context.Context, s shellsession.Session, query url.Values, body []byte) (*capkit.Response, error) {
	method := strings.ToUpper(capkit.FirstNonEmpty(s.Method, http.MethodGet))
	req := capkit.Request{Method: method, URL: s.URL, Timeout: 60 * time.Second, Proxy: s.ProxyURL}
	if method == http.MethodGet || method == http.MethodHead {
		u, err := url.Parse(s.URL)
		if err != nil {
			return nil, fmt.Errorf("WebShell URL 无效: %w", err)
		}
		u.RawQuery = query.Encode()
		req.URL = u.String()
	} else {
		req.Headers = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		req.Body = []byte(query.Encode())
	}
	return e.http.Do(ctx, req)
}

// ensure the compiler checks the collaborator contracts the bridge depends on.
var _ shellsession.Executor = (*webshellExecutor)(nil)
var _ capkit.ScopeChecker = (*capkitScope)(nil)
var _ capkit.AuditSink = (*capkitAudit)(nil)
