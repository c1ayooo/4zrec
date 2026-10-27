package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Capability exposes the fingerprint provider as an agent tool. It uses the
// gate-aware HTTPDoer, so scope/rate/audit cannot be bypassed.
type Capability struct {
	provider core.FingerprintProvider
	deps     core.Deps
}

// NewCapability builds the capability. Rules come from the host: if it already
// provides a *Provider as Deps.Fingerprints it is reused (so verifykit and this
// tool share one rule set); otherwise an empty provider is created and the tool
// reports unavailable until rules are loaded.
func NewCapability(deps core.Deps) (core.Capability, error) {
	c := &Capability{deps: deps}
	switch p := deps.Fingerprints.(type) {
	case *Provider:
		c.provider = p
	case core.FingerprintProvider:
		if p != nil {
			c.provider = p
		}
	}
	if c.provider == nil && deps.HTTP != nil {
		c.provider = &Provider{HTTP: deps.HTTP, Evidence: deps.Evidence}
	}
	return c, nil
}

// Manifest declares the fingerprint toolkit.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: "fingerprintkit", Version: "0.2.0", APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "http"},
		Tools: []core.ToolSpec{{
			Name:        "fingerprint_detect",
			Description: "对单个目标做 HTTP 指纹识别：按已加载的规则集匹配响应头/正文/Cookie/favicon，返回产品、版本、分类与置信度。只读，不写入资产图。",
			Risk:        core.RiskLow,
			RateLimit:   core.RateLimitSpec{PerSecond: 10, Burst: 5, Concurrency: 4},
			InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "url":{"type":"string","description":"http(s) URL"},
    "host":{"type":"string","description":"host[:port]，url 缺省时使用"},
    "port":{"type":"integer"}
  }
}`),
			OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "fingerprints":{"type":"array","items":{
      "type":"object",
      "properties":{"product":{"type":"string"},"version":{"type":"string"},"category":{"type":"string"},"source":{"type":"string"},"confidence":{"type":"integer"}}
    }}
  }
}`),
			ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
				var in struct {
					URL  string `json:"url"`
					Host string `json:"host"`
					Port int    `json:"port"`
				}
				if err := json.Unmarshal(input, &in); err != nil {
					return nil, err
				}
				if strings.TrimSpace(in.URL) == "" && strings.TrimSpace(in.Host) == "" {
					return nil, fmt.Errorf("url 或 host 必填")
				}
				raw := in.URL
				if raw == "" {
					raw = in.Host
					if in.Port > 0 {
						raw = fmt.Sprintf("%s:%d", in.Host, in.Port)
					}
				}
				t, err := core.TargetFromString(0, raw)
				if err != nil {
					return nil, err
				}
				return []core.Target{t}, nil
			},
		}},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches the fingerprint tools.
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "fingerprint_detect":
		return c.detect(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (c *Capability) detect(ctx context.Context, call core.Call) (core.Result, error) {
	if c.provider == nil {
		return core.FailResult(core.ToolMissing("指纹规则未加载：宿主需注入 FingerprintProvider 或 HTTPDoer")), nil
	}
	var in struct {
		URL  string `json:"url"`
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	raw := strings.TrimSpace(in.URL)
	if raw == "" {
		raw = strings.TrimSpace(in.Host)
		if in.Port > 0 {
			raw = fmt.Sprintf("%s:%d", in.Host, in.Port)
		}
	}
	target, err := core.TargetFromString(0, raw)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	techs, err := c.provider.Fingerprint(ctx, target)
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	res, _ := core.SuccessResult(fmt.Sprintf("命中 %d 项指纹", len(techs)), map[string]any{"fingerprints": techs})
	res.Meta.Target = target.Key()
	if len(techs) == 0 {
		res.Summary = "未命中已知指纹"
	}
	return res, nil
}
