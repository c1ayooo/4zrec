// Package capkitbridge exposes capkit capabilities as native host tools.
//
// It deliberately registers the two capabilities the host uses today instead of
// importing capkit's all/ package: all.RegisterFull pulls every kit (and every
// cloud SDK) into the host binary, while this bridge keeps the imported surface
// to identitykit, shellkit and the runtime. Adding a capability later is one
// reg.Add call, mirroring all.Register*.
//
// The host owns the ports. Every tool call still runs through capkit's gate
// chain (scope → approval → ratelimit → audit); the bridge only translates the
// result envelope into the host's actool.Result and maps capkit's Risk onto the
// host's own permission pipeline so high-risk tools ask for approval twice (the
// host prompt is the one the user sees).
package capkitbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	capkit "github.com/c1ayooo/capkit/core"
	"github.com/c1ayooo/capkit/gates"
	"github.com/c1ayooo/capkit/kits/exploitkit"
	"github.com/c1ayooo/capkit/kits/identitykit"
	"github.com/c1ayooo/capkit/kits/sessionkit"
	"github.com/c1ayooo/capkit/kits/shellkit"
	shellsession "github.com/c1ayooo/capkit/kits/shellkit/session"
	capruntime "github.com/c1ayooo/capkit/runtime"

	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// Options are the host-supplied pieces of the bridge.
type Options struct {
	// Scope is required: capkit refuses target tools without an authorization
	// boundary, and the host is the only party that knows a project's scope.
	Scope capkit.ScopeChecker
	// HTTP is required by identity_csrf (it fetches the login page).
	HTTP capkit.HTTPDoer
	// Evidence receives every evidence ref capkit records. Optional: tools still
	// run, but their bodies are only summarised in the result.
	Evidence capkit.EvidenceSink
	// Audit is the host audit sink. Defaults to a no-op logger.
	Audit capkit.AuditSink
	// Limiter defaults to capkit's in-process limiter.
	Limiter capkit.Limiter
	// Approval gates capkit's high-risk tools. Defaults to AutoApprove because
	// the host's own permission pipeline already asks (see riskDecision).
	Approval capkit.Approver
	// Deployer is the host delivery channel for webshell_deploy. Nil leaves the
	// tool in place but reporting tool_missing when called.
	Deployer shellkit.WebShellDeployer
	// Executor drives WebShell sessions. Nil means session_open(kind=webshell)
	// will report the kind as unregistered.
	Executor shellsession.Executor
	// Flows lets the host assemble site logins once and share them with every
	// identity_login call. Nil starts with an empty registry (login reports the
	// kind as unregistered rather than pretending).
	Flows *identitykit.AuthFlowRegistry
	// Context maps the host's per-call context onto capkit's caller identity.
	// The host supplies project/task/actor here; the bridge never invents them.
	Context func(context.Context) capkit.CallContext
	// OnResult, when set, observes every finished tool call. The host uses it to
	// remember state that only a result reveals — a confirmed injection point
	// being the case it exists for.
	OnResult func(ctx context.Context, tool string, input json.RawMessage, res capkit.Result)
}

// Bridge holds a capkit runtime with the host ports bound.
type Bridge struct {
	rt       *capruntime.Runtime
	mgr      *sessionkit.Manager
	flows    *identitykit.AuthFlowRegistry
	ctxFn    func(context.Context) capkit.CallContext
	onResult func(context.Context, string, json.RawMessage, capkit.Result)
	// owners maps session id → the project that opened it. capkit's session
	// manager is process-wide and knows nothing about projects, so without this
	// a multi-project host would show one project's footholds to another.
	ownerMu sync.RWMutex
	owners  map[string]int64
}

// New builds the runtime. It fails closed: a missing required port is an error
// here, not a half-working tool later.
func New(opts Options) (*Bridge, error) {
	if opts.Scope == nil {
		return nil, errors.New("capkitbridge: Scope 必须提供")
	}
	if opts.HTTP == nil {
		return nil, errors.New("capkitbridge: HTTP 必须提供（identity_csrf 需要）")
	}
	limiter := opts.Limiter
	if limiter == nil {
		limiter = gates.NewLimiter()
	}
	audit := opts.Audit
	if audit == nil {
		audit = nopAudit{}
	}
	approval := opts.Approval
	if approval == nil {
		approval = gates.AutoApprove()
	}
	flows := opts.Flows
	if flows == nil {
		flows = identitykit.NewAuthFlowRegistry()
	}

	mgr := sessionkit.NewManager(nil, nil)
	if opts.Executor != nil {
		mgr.RegisterOpener("webshell", &shellkit.WebShellOpener{Executor: opts.Executor})
	}

	reg := capkit.NewRegistry()
	// Same declarations as all.RegisterSessionWithDeployer / RegisterIdentity /
	// RegisterExploit — written out here so this package does not pull all/
	// (and every kit) in.
	if err := reg.Add(capkit.Spec{
		Manifest: shellkit.Manifest(),
		New: func(deps capkit.Deps) (capkit.Capability, error) {
			if opts.Deployer != nil {
				return shellkit.NewCapabilityWithDeployer(deps, opts.Deployer)
			}
			return shellkit.NewCapability(deps)
		},
	}); err != nil {
		return nil, err
	}
	if err := reg.Add(capkit.Spec{
		Manifest: identitykit.Manifest(),
		New: func(deps capkit.Deps) (capkit.Capability, error) {
			return identitykit.NewCapabilityWithFlows(deps, flows)
		},
	}); err != nil {
		return nil, err
	}
	// exploitkit supplies the delivery primitive webshell_deploy needs: a
	// confirmed command-injection point is what lets the host write the payload.
	if err := reg.Add(capkit.Spec{
		Manifest: exploitkit.Manifest(),
		New:      exploitkit.NewCapability,
	}); err != nil {
		return nil, err
	}

	rt, err := capruntime.New(capruntime.Config{
		Scope: opts.Scope, Approval: approval, Limiter: limiter, Audit: audit,
		HTTP: opts.HTTP, Evidence: opts.Evidence, Sessions: mgr,
	}, reg)
	if err != nil {
		return nil, err
	}
	return &Bridge{
		rt: rt, mgr: mgr, flows: flows, ctxFn: opts.Context, onResult: opts.OnResult,
		owners: map[string]int64{},
	}, nil
}

// Flows exposes the registry so the host can assemble site logins at startup.
func (b *Bridge) Flows() *identitykit.AuthFlowRegistry { return b.flows }

// Sessions exposes the manager (session_list/session_close already operate on
// it; the host may also use it to close footholds on shutdown).
func (b *Bridge) Sessions() *sessionkit.Manager { return b.mgr }

// Call invokes a capkit tool directly, for host code that needs a capability as
// a building block (the deployer reuses cmdi_execute instead of opening its own
// HTTP path, so the same gates and evidence apply). It goes through the same
// runtime as an agent call.
func (b *Bridge) Call(ctx context.Context, tool string, input json.RawMessage, cc capkit.CallContext) (capkit.Result, error) {
	res, err := b.rt.Call(ctx, tool, input, cc)
	if b.onResult != nil {
		b.onResult(ctx, tool, input, res)
	}
	if res.OK && cc.ProjectID > 0 {
		b.noteSession(tool, input, res.Data, cc.ProjectID)
	}
	return res, err
}

// noteSession keeps the session→project map in step with opens and closes. The
// session id is read from the envelope data (open) or the input (close), so it
// stays correct even if a tool's data shape gains fields.
func (b *Bridge) noteSession(tool string, input, data json.RawMessage, projectID int64) {
	switch tool {
	case "session_open":
		var out struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal(data, &out) == nil && out.SessionID != "" {
			b.ownerMu.Lock()
			b.owners[out.SessionID] = projectID
			b.ownerMu.Unlock()
		}
	case "session_close":
		var in struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal(input, &in) == nil && in.SessionID != "" {
			b.ownerMu.Lock()
			delete(b.owners, in.SessionID)
			b.ownerMu.Unlock()
		}
	}
}

// SessionInfo is one entry of SessionList: the capkit info plus the owning
// project. Hosts filter on Project to isolate multi-project views.
type SessionInfo struct {
	capkit.SessionInfo
	ProjectID int64 `json:"project_id"`
}

// LiveSessions returns live sessions. When projectID > 0 only that project's
// footholds come back; 0 returns all of them.
func (b *Bridge) LiveSessions(projectID int64) []SessionInfo {
	list := b.mgr.List()
	b.ownerMu.RLock()
	defer b.ownerMu.RUnlock()
	out := make([]SessionInfo, 0, len(list))
	for _, info := range list {
		owner := b.owners[info.ID]
		if projectID > 0 && owner != projectID {
			continue
		}
		out = append(out, SessionInfo{SessionInfo: info, ProjectID: owner})
	}
	return out
}

// CloseSession closes one session.
func (b *Bridge) CloseSession(id string) error {
	err := b.mgr.Close(id)
	if err == nil {
		b.ownerMu.Lock()
		delete(b.owners, id)
		b.ownerMu.Unlock()
	}
	return err
}

// SessionProject returns the project that opened the session. ok is false for
// sessions opened without a project context (global / unscoped).
func (b *Bridge) SessionProject(id string) (int64, bool) {
	b.ownerMu.RLock()
	defer b.ownerMu.RUnlock()
	p, ok := b.owners[id]
	return p, ok
}

// Tools adapts every registered capkit tool to the host's CoreTool contract.
func (b *Bridge) Tools() []actool.CoreTool {
	specs := b.rt.Tools()
	out := make([]actool.CoreTool, 0, len(specs))
	for _, spec := range specs {
		out = append(out, b.wrap(spec))
	}
	return out
}

// capkitPrompt tells the model how to read capkit's envelope. It is appended to
// every bridged tool description.
const capkitPrompt = "结果统一为 capkit 信封：[status] summary，随后是 data/findings/evidence/next。" +
	"status 为 blocked/scope_denied 时不要重试同一输入；" +
	"next 给出建议的下一工具与参数，可直接照做。"

func (b *Bridge) wrap(spec capkit.ToolSpec) actool.CoreTool {
	schema := map[string]any{"type": "object"}
	if len(spec.InputSchema) > 0 {
		var parsed map[string]any
		if err := json.Unmarshal(spec.InputSchema, &parsed); err == nil && parsed != nil {
			schema = parsed
		}
	}
	readOnly := readOnlyTool(spec.Name)
	name := spec.Name
	return actool.Build(actool.Spec{
		Name:        name,
		Description: spec.Description,
		Prompt:      capkitPrompt,
		Schema:      schema,
		ReadOnly:    func(json.RawMessage) bool { return readOnly },
		Concurrent:  func(json.RawMessage) bool { return readOnly },
		// capkit validates its own input and answers every shape with an
		// envelope, so the host must not reject the call before capkit sees it.
		RawInput: true,
		Permissions: func(_ context.Context, _ json.RawMessage, _ actool.Context) actool.Decision {
			return riskDecision(name, spec.Risk)
		},
		Run: func(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			return b.invoke(ctx, name, input, tc)
		},
	})
}

// riskDecision maps capkit Risk onto the host permission pipeline. High risk
// asks the user (the host's approval UI); everything else is allowed here and
// still passes capkit's own approval/rate-limit gates.
func riskDecision(name string, risk capkit.Risk) actool.Decision {
	if risk.AtLeast(capkit.RiskHigh) {
		return actool.AskUser("高风险操作: " + name + "（目标侧写入/接管，需人工确认）")
	}
	return actool.Allowed()
}

// readOnlyTool marks the tools that only read runtime state. Everything else
// defaults to non-read-only, which is fail-closed for the scheduler.
func readOnlyTool(name string) bool {
	switch name {
	case "session_list", "identity_token_check":
		return true
	}
	return false
}

func (b *Bridge) invoke(ctx context.Context, tool string, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	cc := capkit.CallContext{}
	if b.ctxFn != nil {
		cc = b.ctxFn(ctx)
	}
	if tc != nil {
		if cc.Actor == "" {
			cc.Actor = tc.AgentID
		}
		if cc.TaskID == "" && tc.ToolUseID != "" {
			// ToolUseID is the closest stable per-call identity the host exposes;
			// it is not the task id, so keep it in Meta-free form only when empty.
			_ = tc.ToolUseID
		}
	}
	res, err := b.rt.Call(ctx, tool, input, cc)
	if b.onResult != nil {
		b.onResult(ctx, tool, input, res)
	}
	if res.OK && cc.ProjectID > 0 {
		b.noteSession(tool, input, res.Data, cc.ProjectID)
	}
	text := renderEnvelope(res)
	if !res.OK {
		// Gate blocks and tool failures both come back as a full envelope. The
		// host wants them as an error result so the model sees it failed, while
		// keeping the envelope text (including error.hint) in the content.
		return actool.Errorf(text), nil
	}
	if err != nil {
		// A successful envelope with a non-nil error should not happen, but do
		// not lose the error if a host port misbehaves.
		return actool.Text(text + "\n警告: " + err.Error()), nil
	}
	return actool.Text(text), nil
}

// renderEnvelope turns capkit's Result into the text the host shows the model.
func renderEnvelope(res capkit.Result) string {
	var b strings.Builder
	status := string(res.Status)
	if status == "" {
		status = "unknown"
	}
	fmt.Fprintf(&b, "[%s] %s", status, res.Summary)
	if res.Error != nil {
		if res.Error.Code != "" {
			fmt.Fprintf(&b, "\n错误码: %s", res.Error.Code)
		}
		if res.Error.Message != "" && res.Error.Message != res.Summary {
			fmt.Fprintf(&b, "\n错误: %s", res.Error.Message)
		}
		if res.Error.Hint != "" {
			fmt.Fprintf(&b, "\n提示: %s", res.Error.Hint)
		}
		if res.Error.Retryable {
			b.WriteString("\n可重试: 是")
		}
	}
	if len(res.Data) > 0 {
		fmt.Fprintf(&b, "\n数据: %s", string(res.Data))
	}
	for _, f := range res.Findings {
		fmt.Fprintf(&b, "\n发现: %s confirmed=%t payload=%s", f.Kind, f.Confirmed, f.Payload)
	}
	for _, e := range res.Evidence {
		line := "\n证据: " + e.ID + " (" + e.Kind + ")"
		if e.SHA256 != "" {
			line += " sha256=" + e.SHA256
		}
		if e.Preview != "" {
			line += "\n  " + strings.ReplaceAll(e.Preview, "\n", "\n  ")
		}
		b.WriteString(line)
	}
	for _, n := range res.Next {
		fmt.Fprintf(&b, "\n下一步: %s — %s", n.Tool, n.Reason)
		if len(n.Params) > 0 {
			fmt.Fprintf(&b, "\n  参数: %s", string(n.Params))
		}
	}
	if res.Truncated {
		b.WriteString("\n(输出已截断)")
	}
	return b.String()
}

// nopAudit is the default sink: capkit requires one, but a host that has not
// wired auditing yet should still get working tools.
type nopAudit struct{}

func (nopAudit) Record(context.Context, capkit.AuditEvent) {}
