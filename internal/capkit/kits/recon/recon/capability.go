package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Capability exposes the reconnaissance pipeline as an agent tool. Providers
// (subdomain/DNS/ports/HTTP) are host-injected; the pipeline composes them and
// emits assets through an AssetSink. It never writes the host's asset graph.
type Capability struct {
	pipeline *Pipeline
}

// kitVersion mirrors the Manifest version and is stamped into every envelope.
const kitVersion = "0.2.0"

// NewCapability builds the recon capability from the host's providers. The
// pipeline is expected to be pre-wired by the host (providers + sink + scope +
// limiter); a zero pipeline is accepted but returns unavailable at call time.
func NewCapability(deps core.Deps) (core.Capability, error) {
	return &Capability{pipeline: &Pipeline{
		Scope: deps.Scope, Limiter: deps.Limiter, Evidence: deps.Evidence,
	}}, nil
}

// Manifest declares the recon tools.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: "reconkit", Version: kitVersion, APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit"},
		Tools: []core.ToolSpec{{
			Name:        "recon_run",
			Description: "对域名列表执行侦察流水线：子域枚举、DNS 解析、端口扫描、HTTP 探测按开关组合，资产经 AssetSink 输出。scope 每个目标校验，limiter 限速。",
			Risk:        core.RiskMedium,
			RateLimit:   core.RateLimitSpec{PerSecond: 5, Burst: 5, Concurrency: 4},
			InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "domains":{"type":"array","items":{"type":"string"}},
    "ports":{"type":"array","items":{"type":"integer"}},
    "enable_subdomain":{"type":"boolean"},
    "enable_resolve":{"type":"boolean"},
    "enable_ports":{"type":"boolean"},
    "enable_http":{"type":"boolean"},
    "max_hosts":{"type":"integer"}
  },
  "required":["domains"]
}`),
			OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "domains":{"type":"integer"},"subdomains":{"type":"integer"},"resolved":{"type":"integer"},
    "hosts":{"type":"integer"},"ports":{"type":"integer"},"http":{"type":"integer"},
    "assets":{"type":"integer"},"errors":{"type":"array","items":{"type":"string"}}
  }
}`),
			ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
				var in struct {
					Domains []string `json:"domains"`
				}
				if err := json.Unmarshal(input, &in); err != nil {
					return nil, err
				}
				if len(in.Domains) == 0 {
					return nil, fmt.Errorf("domains 必填")
				}
				return core.TargetsFromStrings(0, in.Domains)
			},
		}},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches the recon tools and normalizes the envelope on every return
// path (Status/OK/Meta.Tool/Meta.Version/Summary clamp).
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := c.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

// dispatch routes the call to the tool implementation.
func (c *Capability) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "recon_run":
		return c.run(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (c *Capability) run(ctx context.Context, call core.Call) (core.Result, error) {
	if c.pipeline == nil || c.pipeline.Sink == nil {
		return core.FailResult(core.ToolMissing("recon 流水线未接线：宿主需注入 SubdomainProvider/Resolver/PortScanner/HTTPProber/AssetSink")), nil
	}
	var in Options
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if len(in.Domains) == 0 {
		return core.FailResult(core.InvalidInput("domains 必填")), nil
	}
	stats, err := c.pipeline.Run(ctx, in)
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	res, _ := core.SuccessResult(
		fmt.Sprintf("对 %d 个域名执行侦察流水线：子域 %d、解析 %d、主机 %d、端口 %d、HTTP %d，资产 %d 条",
			stats.Domains, stats.Subdomains, stats.Resolved, stats.Hosts, stats.Ports, stats.HTTP, stats.Assets),
		stats,
	)
	if len(stats.Errors) > 0 {
		res.Status = core.StatusPartial
		res.Summary = core.ClampSummary(res.Summary + fmt.Sprintf("（%d 个错误）", len(stats.Errors)))
	}
	return res, nil
}

// WithPipeline replaces the pipeline (host wiring helper).
func (c *Capability) WithPipeline(p *Pipeline) *Capability {
	c.pipeline = p
	return c
}

// trimHost normalizes a domain for logging.
func trimHost(s string) string { return strings.TrimSpace(strings.ToLower(s)) }
