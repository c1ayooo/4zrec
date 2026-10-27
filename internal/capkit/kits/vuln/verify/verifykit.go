package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Kit composes fingerprinting, template search and engine execution through
// capkit interfaces only. It never imports fingerprintkit/templatekit/httpkit
// or any concrete engine.
type Kit struct {
	fingerprints core.FingerprintProvider
	catalog      core.TemplateCatalog
	engines      map[string]core.TemplateEngine
}

func New(deps core.Deps) (*Kit, error) {
	if deps.Fingerprints == nil {
		return nil, fmt.Errorf("verifykit: fingerprint provider is required")
	}
	if deps.Templates == nil {
		return nil, fmt.Errorf("verifykit: template catalog is required")
	}
	if len(deps.TemplateEngines) == 0 {
		return nil, fmt.Errorf("verifykit: at least one template engine is required")
	}
	return &Kit{fingerprints: deps.Fingerprints, catalog: deps.Templates, engines: deps.TemplateEngines}, nil
}

func NewCapability(deps core.Deps) (core.Capability, error) { return New(deps) }

func (k *Kit) Manifest() core.Manifest { return Manifest() }

// Manifest is the static declaration, usable before providers are available.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: "verifykit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "fingerprints", "templates", "template_engines"},
		Tools: []core.ToolSpec{
			{
				Name:        "verify_plan",
				Description: "Fingerprint the target, then search the predefined template catalog for matching products/CVEs. Returns a plan only; it does not execute anything.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":{"type":"string","description":"URL/host/domain/IP"},
    "products":{"type":"array","items":{"type":"string"},"description":"override fingerprint products"},
    "cve":{"type":"string"},
    "tags":{"type":"array","items":{"type":"string"}},
    "severity":{"type":"array","items":{"type":"string"}},
    "kind":{"type":"string","description":"http | nuclei | shell | chain"},
    "limit":{"type":"integer","description":"max candidates (default 50)"}
  },
  "required":["target"]
}`),
				Risk:         core.RiskLow,
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"plan_id":{"type":"string"},"target":{"type":"object"},"fingerprints":{"type":"array","items":{"type":"object"}},"templates":{"type":"array","items":{"type":"object"}}}}`),
				RateLimit:    core.RateLimitSpec{PerSecond: 5, Burst: 2, Concurrency: 2},
				ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
					var in planInput
					if err := json.Unmarshal(input, &in); err != nil {
						return nil, err
					}
					t, err := core.TargetFromString(0, in.Target)
					if err != nil {
						return nil, err
					}
					return []core.Target{t}, nil
				},
			},
			{
				Name:        "verify_execute",
				Description: "Execute selected predefined template IDs against the target through the matching engine (kind). High risk: the runtime requires approval and scope validation.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":{"type":"string","description":"URL/host/domain/IP"},
    "template_ids":{"type":"array","items":{"type":"string"},"description":"IDs returned by verify_plan"},
    "options":{"type":"object","description":"engine-specific options"}
  },
  "required":["target","template_ids"]
}`),
				Risk:         core.RiskHigh,
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"plan_id":{"type":"string"},"status":{"type":"string"},"results":{"type":"array","items":{"type":"object"}}}}`),
				RateLimit:    core.RateLimitSpec{PerSecond: 2, Burst: 1, Concurrency: 1},
				ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
					var in executeInput
					if err := json.Unmarshal(input, &in); err != nil {
						return nil, err
					}
					t, err := core.TargetFromString(0, in.Target)
					if err != nil {
						return nil, err
					}
					return []core.Target{t}, nil
				},
			},
		},
	}
}

type planInput struct {
	Target   string   `json:"target"`
	Products []string `json:"products"`
	CVE      string   `json:"cve"`
	Tags     []string `json:"tags"`
	Severity []string `json:"severity"`
	Kind     string   `json:"kind"`
	Limit    int      `json:"limit"`
}

type executeInput struct {
	Target      string         `json:"target"`
	TemplateIDs []string       `json:"template_ids"`
	Options     map[string]any `json:"options"`
}

// kitVersion mirrors the Manifest Version; Normalize stamps it into Meta.
const kitVersion = "0.1.0"

// Call is the envelope shell: every return path from dispatch is normalized so
// Status/OK/Meta and a clamped Summary hold on success and failure alike.
func (k *Kit) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := k.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

func (k *Kit) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "verify_plan":
		return k.plan(ctx, call)
	case "verify_execute":
		return k.execute(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) plan(ctx context.Context, call core.Call) (core.Result, error) {
	var in planInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	target, err := core.TargetFromString(call.Context.ProjectID, in.Target)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	fps, err := k.fingerprints.Fingerprint(ctx, target)
	if err != nil {
		return core.FailResult(err), nil
	}
	products := append([]string(nil), in.Products...)
	if len(products) == 0 {
		for _, fp := range fps {
			if fp.Product != "" {
				products = append(products, fp.Product)
			}
		}
	}
	q := core.TemplateQuery{
		Products: unique(products), CVE: in.CVE, Tags: in.Tags,
		Severity: in.Severity, Kind: in.Kind, Limit: in.Limit,
	}
	refs, err := k.catalog.Search(ctx, q)
	if err != nil {
		return core.FailResult(err), nil
	}
	type candidate struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		Engine string `json:"engine,omitempty"`
	}
	cands := make([]candidate, 0, len(refs))
	highRisk := 0
	for _, ref := range refs {
		cands = append(cands, candidate{ID: ref.ID, Name: ref.Name, Kind: ref.Kind, Engine: ref.Engine})
		if isHighSeverity(ref.Meta["severity"]) {
			highRisk++
		}
	}
	out := map[string]any{
		"target": target, "fingerprints": fps, "products": unique(products),
		"candidates": cands, "count": len(cands),
	}
	summary := fmt.Sprintf("按 %d 个指纹为 %s 规划 %d 个模板（高危 %d 个）",
		len(fps), strings.TrimSpace(in.Target), len(cands), highRisk)
	return core.SuccessResult(summary, out)
}

// isHighSeverity reports whether a template meta severity counts as high risk.
func isHighSeverity(sev string) bool {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "high", "critical":
		return true
	}
	return false
}

func (k *Kit) execute(ctx context.Context, call core.Call) (core.Result, error) {
	var in executeInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if len(in.TemplateIDs) == 0 {
		return core.FailResult(core.InvalidInput("template_ids is required")), nil
	}
	target, err := core.TargetFromString(call.Context.ProjectID, in.Target)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	byKind := map[string][]core.TemplateRef{}
	var missing []string
	for _, id := range in.TemplateIDs {
		ref, ok, err := k.catalog.Get(ctx, id)
		if err != nil {
			return core.FailResult(err), nil
		}
		if !ok {
			missing = append(missing, id)
			continue
		}
		kind := ref.Kind
		if ref.Engine != "" {
			kind = ref.Engine
		}
		byKind[kind] = append(byKind[kind], ref)
	}
	if len(missing) > 0 {
		return core.FailResult(core.NotFound("templates not found: " + strings.Join(missing, ", "))), nil
	}
	results := make([]map[string]any, 0, len(byKind))
	hits, confirmed := 0, 0
	for kind, refs := range byKind {
		engine, ok := k.engines[kind]
		if !ok {
			return core.FailResult(core.Unavailable("no template engine for kind " + kind)), nil
		}
		engineRes, err := engine.Execute(ctx, refs, target, in.Options)
		if err != nil {
			return core.FailResult(err), nil
		}
		hits += len(engineRes.Findings)
		for _, f := range engineRes.Findings {
			if f.Confirmed {
				confirmed++
			}
		}
		results = append(results, map[string]any{"kind": kind, "result": engineRes})
	}
	summary := fmt.Sprintf("对 %s 执行 %d 个模板，命中 %d 项，其中确认 %d 项",
		strings.TrimSpace(in.Target), len(in.TemplateIDs), hits, confirmed)
	return core.SuccessResult(summary, map[string]any{
		"target": target, "results": results, "engine_count": len(results),
	})
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[strings.ToLower(v)] {
			continue
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
	}
	return out
}
