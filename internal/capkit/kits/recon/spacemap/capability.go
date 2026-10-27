package spacemap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// kitVersion is the manifest version Normalize stamps into Result.Meta.Version.
const kitVersion = "0.1.0"

// Manifest exposes the engine search surface. Space-mapping queries hit
// external provider APIs, so the host wires these tools with a Fetcher.
func (c *Client) Manifest() core.Manifest {
	return core.Manifest{
		Name: "spacemapkit", Version: kitVersion, APIVersion: "v1",
		Requires: []string{"fetcher"},
		Tools: []core.ToolSpec{
			{
				Name:        "space_search",
				Description: "Query one space-mapping engine (fofa/zoomeye/quake/shodan/hunter) and return normalized rows. API key comes from the injected resolver, settings or environment.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "engine":{"type":"string","enum":["fofa","zoomeye","quake","shodan","hunter"],"description":"engine (default fofa)"},
    "query":{"type":"string","description":"engine query, e.g. domain=\"example.com\""},
    "size":{"type":"integer","description":"result size (default 100, max 10000)"},
    "page":{"type":"integer","description":"page (default 1)"},
    "fields":{"type":"string","description":"comma-separated engine fields (default provider set)"},
    "full":{"type":"boolean","description":"engine full/history flag where supported"}
  },
  "required":["query"]
}`),
				Risk:           core.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"hits":{"type":"array","items":{"type":"object"}}}}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name:        "space_domain_search",
				Description: "Query one engine for assets of a domain using the engine-specific domain syntax.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "engine":{"type":"string","enum":["fofa","zoomeye","quake","shodan","hunter"]},
    "domain":{"type":"string"},
    "size":{"type":"integer"},
    "page":{"type":"integer"}
  },
  "required":["domain"]
}`),
				Risk:           core.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"hits":{"type":"array","items":{"type":"object"}}}}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name:         "space_providers",
				Description:  "List supported space-mapping engines, whether each key is configured, and the domain query template.",
				InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
				Risk:         core.RiskLow,
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"providers":{"type":"array","items":{"type":"object"}}}}`),
			},
		},
	}
}

// Call routes one tool invocation. It is a thin envelope shell: dispatch does
// the work, then Normalize completes Status/OK/Meta.Tool/Meta.Version and clamps
// Summary, so every return path — happy or error — carries the same envelope.
func (c *Client) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := c.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

func (c *Client) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "space_search":
		return c.search(ctx, call.Input)
	case "space_domain_search":
		return c.domainSearch(ctx, call.Input)
	case "space_providers":
		return c.providers(), nil
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (c *Client) search(ctx context.Context, input json.RawMessage) (core.Result, error) {
	var in struct {
		Engine string `json:"engine"`
		Query  string `json:"query"`
		Size   int    `json:"size"`
		Page   int    `json:"page"`
		Fields string `json:"fields"`
		Full   bool   `json:"full"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return core.FailResult(fmt.Errorf("invalid input: %w", err)), nil
	}
	if strings.TrimSpace(in.Query) == "" {
		return core.FailResult(fmt.Errorf("query is required")), nil
	}
	resp, err := c.SearchProviderCtx(ctx, in.Engine, SearchRequest{
		Query: in.Query, Size: in.Size, Page: in.Page, Fields: in.Fields, Full: in.Full,
	})
	if err != nil {
		return core.FailResult(err), nil
	}
	return core.SuccessResult(fmt.Sprintf("用 %s 查询 %s，返回 %d 条资产",
		ProviderDisplayName(resp.Provider), strings.TrimSpace(in.Query), resp.ResultsCount), resp)
}

func (c *Client) domainSearch(ctx context.Context, input json.RawMessage) (core.Result, error) {
	var in struct {
		Engine string `json:"engine"`
		Domain string `json:"domain"`
		Size   int    `json:"size"`
		Page   int    `json:"page"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return core.FailResult(fmt.Errorf("invalid input: %w", err)), nil
	}
	domain := strings.TrimSpace(in.Domain)
	if domain == "" {
		return core.FailResult(fmt.Errorf("domain is required")), nil
	}
	resp, err := c.SearchProviderCtx(ctx, in.Engine, SearchRequest{
		Query: DomainQuery(in.Engine, domain), Size: in.Size, Page: in.Page,
	})
	if err != nil {
		return core.FailResult(err), nil
	}
	return core.SuccessResult(fmt.Sprintf("用 %s 查询域名 %s 的资产，返回 %d 条",
		ProviderDisplayName(resp.Provider), domain, resp.ResultsCount), resp)
}

func (c *Client) providers() core.Result {
	rows := make([]map[string]any, 0, len(Providers))
	configured := 0
	for _, p := range Providers {
		ok := c.SourceConfigured(p)
		if ok {
			configured++
		}
		rows = append(rows, map[string]any{
			"provider": p, "display": ProviderDisplayName(p),
			"configured": ok, "domain_query": DomainQueryTemplate(p),
		})
	}
	res, _ := core.SuccessResult(
		fmt.Sprintf("返回 %d 个测绘引擎，其中 %d 个密钥已配置", len(Providers), configured), rows)
	return res
}
