package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/guard"
)

// Config holds host-provided ports. Scope, Limiter and Audit are mandatory.
type Config struct {
	// Guard 是执行侧围栏的宿主裁决面（可选）。非 nil 时在门禁链最前面
	// 调用——它要看原始输入，而 scope 只看结构化目标字段。nil = 不启用，
	// 行为与未引入 Guard 前完全一致。语义见 core/guard.go。
	Guard     core.Guard
	Scope     core.ScopeChecker
	Approval  core.Approver
	Evidence  core.EvidenceSink
	HTTP      core.HTTPDoer
	Fetcher   core.Fetcher
	Limiter   core.Limiter
	Audit     core.AuditSink
	Settings  core.Settings
	Sealer    core.Sealer
	Logger    core.Logger
	Clock     core.Clock
	IDs       core.IDGenerator
	Processes core.ProcessRunner
	Artifacts core.ArtifactStore
	Binaries  core.BinaryManager

	Fingerprints    core.FingerprintProvider
	Templates       core.TemplateCatalog
	TemplateEngines map[string]core.TemplateEngine
	Sessions        core.SessionManager

	// Intel is the host-owned vulnerability-intel store; Completer is the
	// host-provided model port. Both are optional and only required by the
	// kits that declare them.
	Intel     core.IntelStore
	Completer core.Completer
	// ExtraIntel are host-implemented advisory sources polled alongside the
	// intel kit's own. Optional; see core.IntelSource.
	ExtraIntel []core.IntelSource

	// RequireApprovalAt defaults to high.
	RequireApprovalAt core.Risk
	// IdempotencyWindow bounds how long a result keyed by idempotency_key is
	// reused. Defaults to 5 minutes; <=0 disables caching.
	IdempotencyWindow time.Duration
	// JobWindow bounds how long a finished async job stays pollable through
	// job_status. Defaults to 15 minutes.
	JobWindow time.Duration
	// JobTimeout bounds one async job's total runtime. Defaults to 0 (no extra
	// bound beyond whatever the tool applies).
	JobTimeout time.Duration
}

type registeredTool struct {
	capability string
	spec       core.ToolSpec
	version    string
}

// Runtime is the instance container. It never exposes a Register method: all
// declarations live in core.Registry, and New builds instances from it.
type Runtime struct {
	guard      core.Guard
	cfg        Config
	chain      *gates.Chain
	caps       map[string]core.Capability
	manifests  map[string]core.Manifest
	tools      map[string]registeredTool
	idem       *idemCache
	jobs       *jobRegistry
	jobTimeout time.Duration
	now        func() time.Time
}

// New validates the registry against the provided ports and instantiates every
// capability exactly once.
func New(cfg Config, reg *core.Registry) (*Runtime, error) {
	if reg == nil {
		return nil, fmt.Errorf("registry is required")
	}
	if cfg.Scope == nil {
		return nil, fmt.Errorf("scope checker is required")
	}
	if cfg.Limiter == nil {
		return nil, fmt.Errorf("limiter is required")
	}
	if cfg.Audit == nil {
		return nil, fmt.Errorf("audit sink is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = nopLogger{}
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.IDs == nil {
		cfg.IDs = randomIDs{}
	}
	// Count outbound requests at the port boundary so every tool reports its
	// spend in Meta.Requests without kit cooperation (docs §5.5.7).
	if cfg.HTTP != nil {
		cfg.HTTP = countingHTTP{inner: cfg.HTTP}
	}
	if cfg.Fetcher != nil {
		cfg.Fetcher = countingFetcher{inner: cfg.Fetcher}
	}

	deps := core.Deps{
		Scope: cfg.Scope, Approval: cfg.Approval, Evidence: cfg.Evidence,
		HTTP: cfg.HTTP, Fetcher: cfg.Fetcher, Limiter: cfg.Limiter, Audit: cfg.Audit,
		Settings: cfg.Settings, Sealer: cfg.Sealer, Logger: cfg.Logger,
		Clock: cfg.Clock, IDs: cfg.IDs, Processes: cfg.Processes,
		Artifacts: cfg.Artifacts, Binaries: cfg.Binaries,
		Fingerprints: cfg.Fingerprints, Templates: cfg.Templates, TemplateEngines: cfg.TemplateEngines,
		Sessions: cfg.Sessions,
		Intel:    cfg.Intel, Completer: cfg.Completer,
		ExtraIntel: cfg.ExtraIntel,
	}
	if err := reg.Validate(deps); err != nil {
		return nil, err
	}

	rt := &Runtime{
		guard:      cfg.Guard,
		cfg:        cfg,
		caps:       map[string]core.Capability{},
		manifests:  map[string]core.Manifest{},
		tools:      map[string]registeredTool{},
		jobTimeout: cfg.JobTimeout,
		now:        cfg.Clock.Now,
	}
	window := cfg.IdempotencyWindow
	if window == 0 {
		window = 5 * time.Minute
	}
	rt.idem = newIdemCache(window, rt.now)
	rt.jobs = newJobRegistry(cfg.JobWindow, rt.now)
	threshold := cfg.RequireApprovalAt
	if threshold == "" {
		threshold = core.RiskHigh
	}
	rt.chain = &gates.Chain{
		Scope: cfg.Scope, Approval: cfg.Approval, Limiter: cfg.Limiter,
		Audit: cfg.Audit, RequireApprovalAt: threshold,
		Clock: cfg.Clock, IDs: cfg.IDs,
	}

	for _, spec := range reg.Specs() {
		cap, err := spec.New(deps)
		if err != nil {
			return nil, fmt.Errorf("%s: construct: %w", spec.Manifest.Name, err)
		}
		man := cap.Manifest()
		if err := man.Validate(); err != nil {
			return nil, fmt.Errorf("%s: manifest: %w", spec.Manifest.Name, err)
		}
		if man.Name != spec.Manifest.Name {
			return nil, fmt.Errorf("%s: manifest name mismatch %q", spec.Manifest.Name, man.Name)
		}
		if _, ok := rt.caps[man.Name]; ok {
			return nil, fmt.Errorf("capability %q already instantiated", man.Name)
		}
		rt.caps[man.Name] = cap
		rt.manifests[man.Name] = man
		for _, tool := range man.Tools {
			if _, ok := rt.tools[tool.Name]; ok {
				return nil, fmt.Errorf("tool %q already registered", tool.Name)
			}
			rt.tools[tool.Name] = registeredTool{capability: man.Name, spec: tool, version: man.Version}
		}
	}

	// Fail fast if a high-risk tool has no approval gate.
	for _, tool := range rt.tools {
		if tool.spec.Risk.AtLeast(threshold) && cfg.Approval == nil {
			return nil, fmt.Errorf("tool %q is %s risk but approval gate is not configured", tool.spec.Name, tool.spec.Risk)
		}
	}
	// The runtime owns job_status: it polls the async jobs this runtime started
	// (docs §5.5.5), so no kit declares it.
	spec := jobStatusSpec()
	rt.tools[jobStatusTool] = registeredTool{capability: "", spec: spec, version: "v1"}
	return rt, nil
}

// Tools returns all registered tool specs.
func (r *Runtime) Tools() []core.ToolSpec {
	out := make([]core.ToolSpec, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t.spec)
	}
	return out
}

// Manifests returns all capability manifests.
func (r *Runtime) Manifests() []core.Manifest {
	out := make([]core.Manifest, 0, len(r.manifests))
	for _, m := range r.manifests {
		out = append(out, m)
	}
	return out
}

// Call routes a tool invocation through the mandatory gate chain and completes
// the result envelope (Status, Summary, Meta, Data clamp) before returning.
func (r *Runtime) Call(ctx context.Context, tool string, input json.RawMessage, cc core.CallContext) (res core.Result, err error) {
	rt, ok := r.tools[tool]
	if !ok {
		e := core.NotFound("unknown tool: " + tool)
		return r.finalize(ctx, core.FailResult(e), tool, "", cc, r.now()), e
	}
	if tool == jobStatusTool {
		// Polling is a read of runtime state: no capability, no gate chain.
		return r.finalize(ctx, r.jobStatus(input), tool, rt.version, cc, r.now()), nil
	}
	cap, ok := r.caps[rt.capability]
	if !ok {
		e := core.NewError(core.CodeInternal, "capability not instantiated: "+rt.capability)
		return r.finalize(ctx, core.FailResult(e), tool, rt.version, cc, r.now()), e
	}
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	ctx = withRequestCounter(ctx)
	key := idempotencyKey(tool, cc, input)
	ctx = core.WithCallContext(ctx, cc)
	started := r.now()
	// 围栏（可选）：门禁链最前面，看原始输入。deny 直接拒；ask 由宿主的
	// Check 阻塞等完人工裁决再返回（语义见 core/guard.go）。
	if r.guard != nil {
		targets := guard.Inspect(tool, input, "").CoreTargets()
		v, gerr := r.guard.Check(ctx, tool, input, targets)
		if gerr != nil {
			e := core.NewError(core.CodeScopeDenied, "围栏不可用（fail closed）: "+gerr.Error())
			return r.finalize(ctx, core.FailResult(e), tool, rt.version, cc, started), e
		}
		switch v.Decision {
		case core.GuardAllow:
			// 放行，继续走后续门禁。
		case core.GuardDeny:
			e := core.NewError(core.CodeScopeDenied, "围栏拒绝: "+v.Reason)
			return r.finalize(ctx, core.FailResult(e), tool, rt.version, cc, started), e
		case core.GuardAsk:
			e := core.NewError(core.CodeApprovalRequired, "围栏待裁决: "+v.Reason)
			return r.finalize(ctx, core.FailResult(e), tool, rt.version, cc, started), e
		default:
			e := core.NewError(core.CodeInternal, "围栏返回未知处置: "+string(v.Decision))
			return r.finalize(ctx, core.FailResult(e), tool, rt.version, cc, started), e
		}
	}
	ctx, finish, gateErr := r.chain.Before(ctx, rt.capability, rt.spec, core.Call{
		Tool: tool, Input: input, Context: cc,
	})
	if gateErr != nil {
		return r.finalize(ctx, core.FailResult(gateErr), tool, rt.version, cc, started), gateErr
	}
	if key != "" {
		if cached, ok := r.idem.get(key); ok {
			cached.Meta.Cached = true
			finish(cached, nil)
			return cached, nil
		}
	}
	// Async mode (docs §5.5.5): the gates above ran synchronously, so a scope
	// denial was already reported; the tool itself runs in the background and
	// the caller polls it through job_status.
	if asyncRequested(input) {
		rec := r.jobs.start(r.cfg.IDs.New("job"), tool)
		r.runAsync(ctx, rec, cap, tool, rt.version, input, cc, finish)
		return r.finalize(ctx, jobRefResult(tool, rec.id, 2000), tool, rt.version, cc, started), nil
	}
	defer func() {
		if rec := recover(); rec != nil {
			err = core.NewError(core.CodeInternal, fmt.Sprintf("capability panic: %v", rec))
			res = core.FailResult(err)
		}
		res = r.finalize(ctx, res, tool, rt.version, cc, started)
		if key != "" && cacheable(res) {
			r.idem.put(key, res)
		}
		finish(res, err)
	}()
	res, err = cap.Call(ctx, core.Call{Tool: tool, Input: input, Context: cc})
	if err != nil {
		res = core.FailResult(err)
	}
	return res, err
}

// finalize completes the envelope invariants the runtime owns: a valid Status,
// a non-empty clamped Summary, Meta (tool/version/duration/gate trace/target),
// and the 8KB Data ceiling.
func (r *Runtime) finalize(ctx context.Context, res core.Result, tool, version string, cc core.CallContext, started time.Time) core.Result {
	if !res.Status.Valid() {
		if res.Error != nil {
			res.Status = core.StatusForError(res.Error)
		} else if res.OK {
			res.Status = core.StatusSuccess
		} else {
			res.Status = core.StatusFailed
		}
	}
	res.OK = res.Status == core.StatusSuccess || res.Status == core.StatusPartial
	if res.Summary == "" {
		res.Summary = summarize(res)
	}
	res.Summary = core.ClampSummary(res.Summary)
	if res.Meta.Tool == "" {
		res.Meta.Tool = tool
	}
	if res.Meta.Version == "" {
		res.Meta.Version = version
	}
	if res.Meta.DurationMS <= 0 {
		res.Meta.DurationMS = r.now().Sub(started).Milliseconds()
		if res.Meta.DurationMS <= 0 {
			res.Meta.DurationMS = 1
		}
	}
	if res.Meta.Requests == 0 {
		res.Meta.Requests = requestCount(ctx)
	}
	if res.Meta.GateTrace == nil {
		res.Meta.GateTrace = gates.GateTraceFrom(ctx)
	}
	if res.Meta.Target == "" {
		if ts := res.Findings; len(ts) > 0 {
			res.Meta.Target = ts[0].Target.Key()
		}
	}
	res.ClampData()
	return res
}

// summarize derives a short Summary from a result that did not set one, so
// every real return carries a readable line for the agent.
func summarize(res core.Result) string {
	if res.Error != nil && res.Error.Message != "" {
		return res.Error.Message
	}
	if res.Text != "" {
		return res.Text
	}
	switch res.Status {
	case core.StatusSuccess:
		return "完成"
	case core.StatusPartial:
		return "部分完成"
	case core.StatusBlocked:
		return "被门禁拦截"
	case core.StatusNeedHuman:
		return "需人工确认"
	case core.StatusUnavailable:
		return "依赖不可用"
	default:
		return "失败"
	}
}

// cacheable reports whether a finished result may be reused for a repeated
// idempotency key. Gate-blocked and human-gated results are not cached so the
// agent's changed authorization or confirmation is honored.
func cacheable(res core.Result) bool {
	switch res.Status {
	case core.StatusBlocked, core.StatusNeedHuman, core.StatusUnavailable:
		return false
	}
	return true
}

type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type randomIDs struct{}

func (randomIDs) New(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	if prefix == "" {
		prefix = "id"
	}
	return prefix + "-" + hex.EncodeToString(b)
}
