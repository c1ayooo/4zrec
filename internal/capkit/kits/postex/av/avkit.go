// Package avkit is the AV/EDR identification fingerprint database (docs §4.12,
// phase P3 — "杀软识别指纹库").
//
// It is identification only. The kit runs read-only enumeration over a
// core.Session (processes, services, drivers, registry keys) and matches what
// it finds against a static fingerprint database of well-known AV/EDR products.
// It returns the identified products, their defensive categories, and the
// signatures that matched — decision support for the operator. It builds or
// downloads no bypass, no AMSI/ETW patch, no BYOVD artifact; those stay out of
// the library ("识别与决策在库内，成品载荷在库外").
//
// A second tool, av_list, returns the fingerprint database's known products so
// an operator can review coverage without touching a target.
//
// Everything runs THROUGH a core.Session resolved from core.Deps.Sessions.
package av

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

const (
	kitName    = "avkit"
	kitVersion = "0.1.0"
	apiVersion = "v1"

	defaultTimeout = 30 * time.Second
	maxTimeout     = 3 * time.Minute
	perCmdTimeout  = 12 * time.Second
)

// Category groups the defensive role a product plays, so an operator can reason
// about what coverage exists rather than the brand name.
type Category string

const (
	CatEDR     Category = "edr"      // behavioral EDR / endpoint detection
	CatAV      Category = "av"       // traditional antivirus
	CatNGAV    Category = "ngav"     // next-gen AV (cloud + ML)
	CatEPP     Category = "epp"      // endpoint protection platform
	CatLogging Category = "logging"  // audit/log forwarding (sysmon, etc.)
	CatFW      Category = "firewall" // host firewall
)

// Product is one known AV/EDR product and the signatures that identify it on a
// host. Only one signature needs to match for detection.
type Product struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Vendor    string   `json:"vendor"`
	Category  Category `json:"category"`
	Platform  string   `json:"platform"`            // linux | windows
	Processes []string `json:"processes,omitempty"` // process image names
	Services  []string `json:"services,omitempty"`  // service names
	Drivers   []string `json:"drivers,omitempty"`   // loaded kernel driver names
	Registry  []string `json:"registry,omitempty"`  // registry key/prefix (windows)
	Files     []string `json:"files,omitempty"`     // on-disk file paths
	// Notes are operator-facing decision support (what the product watches for),
	// NOT bypass instructions.
	Notes string `json:"notes,omitempty"`
}

// Match is one signature that fired for a detected product.
type Match struct {
	Kind   string `json:"kind"` // process | service | driver | registry | file
	Value  string `json:"value"`
	Sample string `json:"sample,omitempty"` // trimmed evidence line
}

// Detection is one identified product and the signatures that matched.
type Detection struct {
	ProductID string   `json:"product_id"`
	Name      string   `json:"name"`
	Category  Category `json:"category"`
	Platform  string   `json:"platform"`
	Matches   []Match  `json:"matches"`
}

// Database is the static fingerprint set.
type Database struct {
	Products []Product `json:"products"`
}

// DefaultDatabase is the built-in AV/EDR fingerprint set.
func DefaultDatabase() Database {
	return Database{Products: defaultProducts}
}

// Capability exposes the AV/EDR identification tools.
type Capability struct {
	deps core.Deps
	db   Database
}

// NewCapability builds the capability. An empty database falls back to the
// built-in default so the tool always has something to match against.
func NewCapability(deps core.Deps) (core.Capability, error) {
	db := DefaultDatabase()
	return &Capability{deps: deps, db: db}, nil
}

// Manifest declares the AV/EDR tool surface.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: kitName, Version: kitVersion, APIVersion: apiVersion,
		Requires: []string{"scope", "limiter", "audit", "sessions"},
		Tools:    []core.ToolSpec{detectSpec(), listSpec()},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches the tools.
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "av_detect":
		return c.detect(ctx, call)
	case "av_list":
		return c.list(call)
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
	out, err := s.Exec(ctx, cmd, core.ExecOpts{Timeout: timeout, MaxOutput: 256 << 10})
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

// ---- tool specs ----

func detectSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "av_detect",
		Description: "只读识别会话目标（Linux/Windows）上已安装的杀软/EDR：进程、服务、内核驱动、注册表键、关键文件指纹。返回识别到的产品、防御类别与命中签名。只做识别与决策支持，不生成/落地任何绕过载荷。",
		Risk:        core.RiskLow,
		RateLimit:   core.RateLimitSpec{PerSecond: 2, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "platform":{"type":"string","enum":["auto","linux","windows"]},
    "category":{"type":"string","enum":["edr","av","ngav","epp","logging","firewall"],"description":"只返回该类别（可选）"},
    "timeout_ms":{"type":"integer"}
  },
  "required":["session_id"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "platform":{"type":"string"},
    "count":{"type":"integer"},
    "detections":{"type":"array","items":{"type":"object"}},
    "commands":{"type":"array","items":{"type":"object"}}
  }
}`),
	}
}

func listSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "av_list",
		Description: "返回库内已知杀软/EDR 指纹库的产品清单（含类别与已知防御要点），无需会话。供操作员复核覆盖度。",
		Risk:        core.RiskLow,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"category":{"type":"string","enum":["edr","av","ngav","epp","logging","firewall"]}}}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "count":{"type":"integer"},
    "products":{"type":"array","items":{"type":"object"}}
  }
}`),
	}
}

// ---- handlers ----

func (c *Capability) detect(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		SessionID string `json:"session_id"`
		Platform  string `json:"platform"`
		Category  string `json:"category"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return core.FailResult(e), nil
	}
	to := core.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout)
	platform := strings.ToLower(strings.TrimSpace(in.Platform))
	if platform == "" || platform == "auto" {
		platform = detectPlatform(ctx, c, s, to)
	}
	cmds := detectCommands(platform)
	outs := make([]cmdOut, 0, len(cmds))
	var raws []core.Output
	fail := 0
	for _, cm := range cmds {
		o, ok := c.run(ctx, s, cm.Command, perCmdTimeout)
		if !ok {
			fail++
		}
		raws = append(raws, o)
		outs = append(outs, cmdOut{Label: cm.Label, Command: cm.Command, Output: core.Truncate(o.Stdout, 8192), ExitCode: o.ExitCode, OK: ok})
	}
	merged := mergeOutputs(outs)
	cat := strings.ToLower(strings.TrimSpace(in.Category))
	detections := c.matchAll(merged, platform, cat)

	status := core.StatusSuccess
	summary := fmt.Sprintf("%s 平台识别到 %d 个杀软/EDR 产品", platform, len(detections))
	if fail > 0 {
		status = core.StatusPartial
		summary = fmt.Sprintf("识别完成：%d/%d 命令失败，命中 %d 个产品", fail, len(cmds), len(detections))
	}
	if len(detections) == 0 {
		summary = fmt.Sprintf("%s 平台未在指纹库中发现已知杀软/EDR（命令失败 %d 项）", platform, fail)
	}
	data, _ := core.DataResult(map[string]any{
		"session_id": in.SessionID, "platform": platform,
		"count": len(detections), "detections": detections, "commands": outs,
	})
	data.Status = status
	data.OK = status == core.StatusSuccess
	data.Summary = core.ClampSummary(summary)
	data.Evidence = core.EvidenceRefs(raws...)
	if len(detections) > 0 {
		data.Findings = findingsFor(detections)
		data.Next = []core.NextStep{{
			Tool:          "av_list",
			Reason:        "复核库内覆盖度与每个产品的防御要点，决定后续规避策略（仅决策支持）",
			Risk:          core.RiskLow,
			Preconditions: []string{"av.detected"},
		}}
	}
	return data, nil
}

func (c *Capability) list(call core.Call) (core.Result, error) {
	var in struct {
		Category string `json:"category"`
	}
	if len(call.Input) > 0 {
		if err := json.Unmarshal(call.Input, &in); err != nil {
			return core.FailResult(core.InvalidInput(err.Error())), nil
		}
	}
	cat := strings.ToLower(strings.TrimSpace(in.Category))
	prods := c.db.Products
	if cat != "" {
		filtered := make([]Product, 0, len(prods))
		for _, p := range prods {
			if string(p.Category) == cat {
				filtered = append(filtered, p)
			}
		}
		prods = filtered
	}
	// Strip the raw signature lists from the public view; keep metadata + notes.
	type public struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Vendor   string   `json:"vendor"`
		Category Category `json:"category"`
		Platform string   `json:"platform"`
		Notes    string   `json:"notes,omitempty"`
	}
	out := make([]public, 0, len(prods))
	for _, p := range prods {
		out = append(out, public{p.ID, p.Name, p.Vendor, p.Category, p.Platform, p.Notes})
	}
	data, _ := core.SuccessResult(fmt.Sprintf("库内已知产品 %d 个", len(out)), map[string]any{"count": len(out), "products": out})
	return data, nil
}

// ---- matching ----

func (c *Capability) matchAll(merged string, platform, category string) []Detection {
	lower := strings.ToLower(merged)
	var dets []Detection
	for _, p := range c.db.Products {
		if platform != "" && p.Platform != platform {
			continue
		}
		var matches []Match
		matches = append(matches, matchList(lower, merged, p.Processes, "process")...)
		matches = append(matches, matchList(lower, merged, p.Services, "service")...)
		matches = append(matches, matchList(lower, merged, p.Drivers, "driver")...)
		matches = append(matches, matchList(lower, merged, p.Registry, "registry")...)
		matches = append(matches, matchList(lower, merged, p.Files, "file")...)
		if len(matches) == 0 {
			continue
		}
		if category != "" && string(p.Category) != category {
			continue
		}
		dets = append(dets, Detection{
			ProductID: p.ID, Name: p.Name, Category: p.Category, Platform: p.Platform, Matches: matches,
		})
	}
	return dets
}

func matchList(lower, full string, needles []string, kind string) []Match {
	if len(needles) == 0 {
		return nil
	}
	var out []Match
	for _, n := range needles {
		nl := strings.ToLower(n)
		if idx := strings.Index(lower, nl); idx >= 0 {
			out = append(out, Match{Kind: kind, Value: n, Sample: sampleAt(full, idx, len(n))})
		}
	}
	return out
}

func sampleAt(full string, idx, n int) string {
	start := idx
	if start > 60 {
		start = idx - 60
	}
	end := idx + n + 80
	if end > len(full) {
		end = len(full)
	}
	return strings.TrimSpace(full[start:end])
}

func mergeOutputs(outs []cmdOut) string {
	var b strings.Builder
	for _, o := range outs {
		b.WriteString(o.Output)
		b.WriteString("\n")
	}
	return b.String()
}

func findingsFor(dets []Detection) []core.Finding {
	out := make([]core.Finding, 0, len(dets))
	for _, d := range dets {
		var sigs []string
		for _, m := range d.Matches {
			sigs = append(sigs, m.Kind+":"+m.Value)
		}
		out = append(out, core.Finding{
			Kind:        "av:" + string(d.Category),
			Confirmed:   true,
			Fingerprint: "av|" + d.ProductID + "|" + strings.Join(sigs, ","),
			Source:      "avkit",
		})
	}
	return out
}

// ---- helpers ----
