// Package cleanupkit removes operational traces (docs §4.8, phase P3).
//
// It is intentionally two-phase and cannot be collapsed into one call:
//
//	cleanup_preview  read-only: enumerates what WOULD be removed and returns a
//	                 plan_id (a content hash of the exact target set) plus the
//	                 exact commands that would run. It changes nothing.
//	cleanup_apply    requires confirm=true AND the plan_id from a preview; it
//	                 recomputes the plan from the same inputs and refuses to run
//	                 if the hash does not match, so an agent cannot skip the
//	                 review step or widen the scope after previewing.
//
// A blanket wipe is refused by construction: every plan is an explicit, bounded
// list of named files/logs (never "*"), and an empty scope is an error rather
// than "everything" ("禁止一键清空", docs §4.8).
//
// Everything runs THROUGH a core.Session resolved from core.Deps.Sessions.
package cleanup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

const (
	kitName    = "cleanupkit"
	kitVersion = "0.1.0"
	apiVersion = "v1"

	defaultTimeout = 20 * time.Second
	maxTimeout     = 3 * time.Minute
	perCmdTimeout  = 15 * time.Second
)

// Capability exposes the cleanup tools. It depends only on core.Deps.
type Capability struct {
	deps core.Deps
}

// NewCapability builds the cleanup capability.
func NewCapability(deps core.Deps) (core.Capability, error) {
	return &Capability{deps: deps}, nil
}

// Manifest declares the cleanup tool surface.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: kitName, Version: kitVersion, APIVersion: apiVersion,
		Requires: []string{"scope", "limiter", "audit", "sessions"},
		Tools:    []core.ToolSpec{previewSpec(), applySpec()},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches the cleanup tools.
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "cleanup_preview":
		return c.preview(ctx, call)
	case "cleanup_apply":
		return c.apply(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (c *Capability) session(id string) (core.Session, *core.Error) {
	if c.deps.Sessions == nil {
		return nil, core.ToolMissing("SessionManager 未注入（宿主需提供 core.Deps.Sessions）")
	}
	if strings.TrimSpace(id) == "" {
		return nil, core.InvalidInput("session_id 必填")
	}
	s, ok := c.deps.Sessions.Get(id)
	if !ok {
		return nil, core.NotFound("会话不存在: " + id)
	}
	return s, nil
}

func (c *Capability) run(ctx context.Context, s core.Session, cmd string, timeout time.Duration) (core.Output, bool) {
	out, err := s.Exec(ctx, cmd, core.ExecOpts{Timeout: timeout, MaxOutput: 128 << 10})
	if err != nil {
		return core.Output{Command: cmd}, false
	}
	return out, true
}

func detectPlatform(ctx context.Context, c *Capability, s core.Session, to time.Duration) string {
	if os := strings.ToLower(strings.TrimSpace(s.Info().OS)); os != "" {
		if strings.Contains(os, "win") {
			return "windows"
		}
		return "linux"
	}
	if out, ok := c.run(ctx, s, "uname -s", to); ok && strings.TrimSpace(out.Stdout) != "" {
		return "linux"
	}
	return "windows"
}

// ---- inputs ----

// scopeInput names one trace source. Path is a file path (Linux) or an event
// log name (Windows). Pattern, when set, selects the lines to remove (Linux) or
// is recorded for context (Windows).
type scopeInput struct {
	Kind    string `json:"kind"` // log | history | utmp | eventlog | file
	Path    string `json:"path"`
	Pattern string `json:"pattern,omitempty"`
}

type previewInput struct {
	SessionID string       `json:"session_id"`
	Platform  string       `json:"platform"`
	Scope     []scopeInput `json:"scope"`
	Paths     []string     `json:"paths,omitempty"` // shorthand: file scope entries
	Pattern   string       `json:"pattern,omitempty"`
	TimeoutMS int          `json:"timeout_ms"`
}

type applyInput struct {
	previewInput
	PlanID  string `json:"plan_id"`
	Confirm bool   `json:"confirm"`
	Backup  *bool  `json:"backup,omitempty"`
}

func (in *previewInput) normalize() *core.Error {
	// A paths list is sugar for file-scope entries.
	for _, p := range in.Paths {
		if strings.TrimSpace(p) != "" {
			in.Scope = append(in.Scope, scopeInput{Kind: "file", Path: strings.TrimSpace(p)})
		}
	}
	for i := range in.Scope {
		in.Scope[i].Kind = strings.ToLower(strings.TrimSpace(in.Scope[i].Kind))
		in.Scope[i].Path = strings.TrimSpace(in.Scope[i].Path)
		if in.Scope[i].Kind == "" {
			in.Scope[i].Kind = "file"
		}
		if in.Scope[i].Path == "" {
			return core.InvalidInput(fmt.Sprintf("scope[%d].path 必填", i))
		}
		if in.Scope[i].Pattern == "" {
			in.Scope[i].Pattern = strings.TrimSpace(in.Pattern)
		}
		// Reject wildcard/whole-tree selectors: cleanup must be bounded.
		if isBlanket(in.Scope[i].Path) {
			return core.InvalidInput("拒绝通配/根目录路径: " + in.Scope[i].Path + "（清理必须限定具体文件/日志）")
		}
	}
	if len(in.Scope) == 0 {
		return core.InvalidInput("scope 不能为空；清理必须显式指定具体文件/日志，禁止一键清空")
	}
	return nil
}

// isBlanket flags selectors that would remove an unbounded set.
func isBlanket(path string) bool {
	p := strings.TrimSpace(path)
	switch p {
	case "", ".", "..", "/", "*", "/*", "~", "~/*", `C:\`, "C:/":
		return true
	}
	if strings.HasSuffix(p, "/*") || strings.HasSuffix(p, `\*`) || strings.ContainsAny(p, "*?") && strings.HasSuffix(p, "*") {
		return true
	}
	return false
}

// ---- tool specs ----

func previewSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "cleanup_preview",
		Description: "只读预览：枚举将会被清理的痕迹（日志、命令历史、wtmp/btmp/lastlog、Windows 事件日志、指定文件），返回可复核的差异（命中行数/样例）、将执行的精确命令，以及 plan_id。不修改任何东西。清理必须先预览，禁止一键清空。",
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 3, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "platform":{"type":"string","enum":["auto","linux","windows"]},
    "scope":{"type":"array","description":"显式的痕迹来源清单","items":{"type":"object","properties":{"kind":{"type":"string","enum":["log","history","utmp","eventlog","file"]},"path":{"type":"string"},"pattern":{"type":"string"}},"required":["path"]}},
    "paths":{"type":"array","items":{"type":"string"},"description":"scope 的简化形式：等价于 kind=file 的条目"},
    "pattern":{"type":"string","description":"全局过滤正则/子串（如攻击者 IP）"},
    "timeout_ms":{"type":"integer"}
  },
  "required":["session_id"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "plan_id":{"type":"string"},
    "platform":{"type":"string"},
    "targets":{"type":"array","items":{"type":"object"}},
    "commands":{"type":"array","items":{"type":"object"}},
    "total_matched":{"type":"integer"}
  }
}`),
	}
}

func applySpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "cleanup_apply",
		Description: "执行 cleanup_preview 生成的清理计划。高风险：runtime 会强制审批与范围校验；必须携带 preview 返回的 plan_id 且 confirm=true，且重算的计划哈希必须与 plan_id 一致——否则拒绝执行（防止跳过预览或事后扩大范围）。默认先备份再删除。",
		Risk:        core.RiskHigh,
		RateLimit:   core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "platform":{"type":"string","enum":["auto","linux","windows"]},
    "scope":{"type":"array","items":{"type":"object","properties":{"kind":{"type":"string"},"path":{"type":"string"},"pattern":{"type":"string"}},"required":["path"]}},
    "paths":{"type":"array","items":{"type":"string"}},
    "pattern":{"type":"string"},
    "plan_id":{"type":"string","description":"cleanup_preview 返回的哈希；必须一致"},
    "confirm":{"type":"boolean","description":"必须为 true"},
    "backup":{"type":"boolean","description":"默认 true：删除前备份到 *.capkit-bak"},
    "timeout_ms":{"type":"integer"}
  },
  "required":["session_id","plan_id","confirm"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "plan_id":{"type":"string"},
    "applied":{"type":"boolean"},
    "targets":{"type":"array","items":{"type":"object"}}
  }
}`),
	}
}

// ---- handlers ----

func (c *Capability) preview(ctx context.Context, call core.Call) (core.Result, error) {
	var in previewInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return core.FailResult(e), nil
	}
	platform := strings.ToLower(strings.TrimSpace(in.Platform))
	if platform == "" || platform == "auto" {
		platform = detectPlatform(ctx, c, s, core.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout))
	}
	in.Platform = platform
	if e := in.normalize(); e != nil {
		return core.FailResult(e), nil
	}
	plan, e := buildCleanupPlan(in)
	if e != nil {
		return core.FailResult(e), nil
	}
	// Read-only probing: gather match counts/samples so a human can review.
	targets := make([]targetPreview, 0, len(plan.Targets))
	var raws []core.Output
	total := 0
	for _, t := range plan.Targets {
		tp := targetPreview{Kind: t.Kind, Path: t.Path, Pattern: t.Pattern}
		if t.PreviewCmd != "" {
			if o, ok := c.run(ctx, s, t.PreviewCmd, perCmdTimeout); ok && o.ExitCode == 0 {
				tp.Matched = parseInt(o.Stdout)
				tp.Sample = core.Truncate(strings.TrimSpace(o.Stdout), 512)
				raws = append(raws, o)
			}
		}
		total += tp.Matched
		targets = append(targets, tp)
	}
	data, _ := core.DataResult(map[string]any{
		"plan_id": plan.ID, "platform": platform, "targets": targets,
		"commands": plan.commandsView(), "total_matched": total,
	})
	data.Summary = core.ClampSummary(fmt.Sprintf("预览：%d 个痕迹来源，预计命中 %d 项（未做任何修改）；确认后携带 plan_id=%s 执行 cleanup_apply", len(targets), total, plan.ID))
	data.Evidence = core.EvidenceRefs(raws...)
	data.Next = []core.NextStep{{
		Tool:          "cleanup_apply",
		Reason:        "复核预览后，携带 plan_id 与 confirm=true 执行清理",
		Risk:          core.RiskHigh,
		Preconditions: []string{"cleanup.previewed", "human.confirmed"},
		Params:        mustJSON(map[string]string{"plan_id": plan.ID}),
	}}
	return data, nil
}

func (c *Capability) apply(ctx context.Context, call core.Call) (core.Result, error) {
	var in applyInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return core.FailResult(e), nil
	}
	if !in.Confirm {
		return core.FailResult(core.NeedHuman("cleanup_apply 需要 confirm=true（清理不可逆，须人工确认）")), nil
	}
	platform := strings.ToLower(strings.TrimSpace(in.Platform))
	if platform == "" || platform == "auto" {
		platform = detectPlatform(ctx, c, s, core.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout))
	}
	in.Platform = platform
	if e := in.normalize(); e != nil {
		return core.FailResult(e), nil
	}
	plan, e := buildCleanupPlan(in.previewInput)
	if e != nil {
		return core.FailResult(e), nil
	}
	if strings.TrimSpace(in.PlanID) == "" || in.PlanID != plan.ID {
		return core.FailResult(core.Conflict(
			fmt.Sprintf("plan_id 不匹配：期望 %s，收到 %q。必须先 cleanup_preview 并原样回传 plan_id，防止跳过预览或事后扩大范围", plan.ID, in.PlanID),
		)), nil
	}
	backup := true
	if in.Backup != nil {
		backup = *in.Backup
	}
	to := core.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout)
	type targetResult struct {
		Path     string `json:"path"`
		Kind     string `json:"kind"`
		Backup   string `json:"backup,omitempty"`
		OK       bool   `json:"ok"`
		ExitCode int    `json:"exit_code"`
		Output   string `json:"output,omitempty"`
	}
	results := make([]targetResult, 0, len(plan.Targets))
	var raws []core.Output
	failed := 0
	for _, t := range plan.Targets {
		tr := targetResult{Path: t.Path, Kind: t.Kind}
		for _, step := range t.applySteps(backup) {
			o, ok := c.run(ctx, s, step, to)
			if !ok || o.ExitCode != 0 {
				failed++
				tr.ExitCode = o.ExitCode
				tr.Output = core.Truncate(strings.TrimSpace(o.Stderr+o.Stdout), 512)
				raws = append(raws, o)
				break
			}
			tr.OK = true
			raws = append(raws, o)
		}
		if backup && t.Kind != "eventlog" {
			tr.Backup = t.Path + ".capkit-bak"
		}
		results = append(results, tr)
	}
	status := core.StatusSuccess
	summary := fmt.Sprintf("已清理 %d 个痕迹来源（plan %s）", len(results), plan.ID)
	if failed > 0 {
		status = core.StatusPartial
		summary = fmt.Sprintf("清理完成：%d/%d 失败（plan %s）", failed, len(results), plan.ID)
	}
	data, _ := core.DataResult(map[string]any{
		"plan_id": plan.ID, "applied": failed == 0, "targets": results,
	})
	data.Status = status
	data.OK = status == core.StatusSuccess
	data.Summary = core.ClampSummary(summary)
	data.Evidence = core.EvidenceRefs(raws...)
	return data, nil
}

// ---- plan model ----

type cleanupTarget struct {
	Kind       string
	Path       string
	Pattern    string
	PreviewCmd string
	DeleteStep []string // 可能有备份步 + 删除步
}

type cleanupPlan struct {
	ID      string
	Targets []cleanupTarget
}

func (p cleanupPlan) commandsView() []string {
	var cmds []string
	for _, t := range p.Targets {
		cmds = append(cmds, t.DeleteStep...)
	}
	return cmds
}

// (targetPreview is the review row returned by preview.)
type targetPreview struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Pattern string `json:"pattern,omitempty"`
	Matched int    `json:"matched"`
	Sample  string `json:"sample,omitempty"`
}

// applySteps returns the commands to run for one target, optionally prefixing a
// backup step.
func (t cleanupTarget) applySteps(backup bool) []string {
	if !backup || t.Kind == "eventlog" {
		return t.DeleteStep
	}
	steps := make([]string, 0, len(t.DeleteStep)+1)
	steps = append(steps, t.BackupCmd())
	steps = append(steps, t.DeleteStep...)
	return steps
}

func (t cleanupTarget) BackupCmd() string {
	return fmt.Sprintf("cp -p %s %s 2>/dev/null || true", core.ShellQuote(t.Path), core.ShellQuote(t.Path+".capkit-bak"))
}

// buildCleanupPlan turns a normalized input into a deterministic plan. The ID
// is a hash over the exact target/command set, so any change to scope after a
// preview produces a different ID and cleanup_apply refuses the stale one.
func buildCleanupPlan(in previewInput) (cleanupPlan, *core.Error) {
	platform := strings.ToLower(strings.TrimSpace(in.Platform))
	plan := cleanupPlan{}
	for _, sc := range in.Scope {
		t := cleanupTarget{Kind: sc.Kind, Path: sc.Path, Pattern: sc.Pattern}
		if err := fillCommands(&t, platform); err != nil {
			return cleanupPlan{}, err
		}
		plan.Targets = append(plan.Targets, t)
	}
	plan.ID = hashPlan(plan)
	return plan, nil
}

func hashPlan(p cleanupPlan) string {
	parts := make([]string, 0, len(p.Targets))
	for _, t := range p.Targets {
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%s", t.Kind, t.Path, t.Pattern, strings.Join(t.DeleteStep, ";")))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:8])
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func parseInt(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// Preview commands emit a plain integer; if anything else slips in, take the
	// first whitespace field and parse it, else 0 (fail-closed).
	field := strings.Fields(s)
	if len(field) == 0 {
		return 0
	}
	n := 0
	for _, r := range field[0] {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
