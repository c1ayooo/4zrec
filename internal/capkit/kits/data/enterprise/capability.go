package enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// ProviderResolver returns a configured provider for a data-source name. Hosts
// implement it from their session vault; the kit never stores cookies/passwords.
type ProviderResolver interface {
	Resolve(ctx context.Context, provider string) (Provider, error)
}

// ResolverFunc adapts a function to ProviderResolver.
type ResolverFunc func(ctx context.Context, provider string) (Provider, error)

func (f ResolverFunc) Resolve(ctx context.Context, provider string) (Provider, error) {
	return f(ctx, provider)
}

// Kit exposes the provider search/detail surface as a capkit capability. The
// BFS collector is a library (Collector + Store) because it needs host
// persistence and background-job semantics.
type Kit struct{ Resolver ProviderResolver }

// kitVersion mirrors the Manifest version and is stamped into every envelope.
const kitVersion = "0.1.0"

func NewKit(resolver ProviderResolver) *Kit { return &Kit{Resolver: resolver} }

func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "enterprisekit", Version: kitVersion, APIVersion: "v1",
		Tools: []core.ToolSpec{
			{
				Name:        "enterprise_search",
				Description: "Search a configured enterprise data source (aqc/tyc/kuaicha/fengniao) by company keyword and return stable ext_id references.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "provider":{"type":"string","description":"aqc|tyc|kuaicha|fengniao"},
    "keyword":{"type":"string"},
    "limit":{"type":"integer","description":"max results (default 10)"}
  },
  "required":["provider","keyword"]
}`),
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"},"count":{"type":"integer"},"items":{"type":"array","items":{"type":"object","properties":{"ext_id":{"type":"string"},"name":{"type":"string"}}}}}}`),
				Risk:         core.RiskLow,
			},
			{
				Name:        "enterprise_detail",
				Description: "Fetch company detail and related ICP/domain hints by provider and ext_id.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "provider":{"type":"string"},
    "ext_id":{"type":"string"}
  },
  "required":["provider","ext_id"]
}`),
				OutputSchema: json.RawMessage(`{"type":"object","description":"Provider-specific company detail (fields drift across providers)."}`),
				Risk:         core.RiskLow,
			},
			{
				Name:         "enterprise_providers",
				Description:  "List supported enterprise data sources, auth mode, availability and configuration hint.",
				InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"providers":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"label":{"type":"string"},"auth":{"type":"string"},"available":{"type":"boolean"},"hint":{"type":"string"}}}}}}`),
				Risk:         core.RiskLow,
			},
		},
	}
}

// Call dispatches one tool invocation and normalizes the envelope on every
// return path (Status/OK/Meta.Tool/Meta.Version/Summary clamp).
func (k *Kit) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := k.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

// dispatch routes the call to the tool implementation.
func (k *Kit) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "enterprise_search":
		return k.search(ctx, call.Input)
	case "enterprise_detail":
		return k.detail(ctx, call.Input)
	case "enterprise_providers":
		available := 0
		for _, p := range Registry {
			if p.Available {
				available++
			}
		}
		return core.SuccessResult(fmt.Sprintf("返回 %d 个企业数据源，其中 %d 个可用", len(Registry), available),
			map[string]any{"providers": Registry, "count": len(Registry)})
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) provider(ctx context.Context, name string) (Provider, error) {
	if k == nil || k.Resolver == nil {
		return nil, core.Unavailable("enterprise provider resolver 未配置")
	}
	return k.Resolver.Resolve(ctx, strings.TrimSpace(name))
}

func (k *Kit) search(ctx context.Context, input json.RawMessage) (core.Result, error) {
	var in struct {
		Provider string `json:"provider"`
		Keyword  string `json:"keyword"`
		Limit    int    `json:"limit"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if in.Limit <= 0 {
		in.Limit = 10
	}
	p, err := k.provider(ctx, in.Provider)
	if err != nil {
		return core.FailResult(err), nil
	}
	refs, err := p.Search(ctx, in.Keyword, in.Limit)
	if err != nil {
		return core.FailResult(err), nil
	}
	return core.SuccessResult(
		fmt.Sprintf("在 %s 检索企业关键词 %q，返回 %d 条", p.Name(), in.Keyword, len(refs)),
		map[string]any{"provider": p.Name(), "items": refs, "count": len(refs)})
}

func (k *Kit) detail(ctx context.Context, input json.RawMessage) (core.Result, error) {
	var in struct {
		Provider string `json:"provider"`
		ExtID    string `json:"ext_id"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	p, err := k.provider(ctx, in.Provider)
	if err != nil {
		return core.FailResult(err), nil
	}
	detail, err := p.Detail(ctx, in.ExtID)
	if err != nil {
		return core.FailResult(err), nil
	}
	domains := 0
	if detail != nil {
		domains = len(detail.Domains)
	}
	return core.SuccessResult(
		fmt.Sprintf("从 %s 获取企业 %s 详情，关联域名 %d 个", p.Name(), in.ExtID, domains), detail)
}
