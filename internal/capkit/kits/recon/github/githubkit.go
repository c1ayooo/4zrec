package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Kit exposes GitHub Code Search for leaked secrets. It uses the external
// Fetcher port (not target-scoped HTTP) and the host's GitHub token setting.
type Kit struct {
	client   *Client
	evidence core.EvidenceSink
}

func New(deps core.Deps) *Kit {
	return &Kit{
		client:   &Client{Fetcher: deps.Fetcher, Settings: deps.Settings, Limiter: deps.Limiter},
		evidence: deps.Evidence,
	}
}

func NewCapability(deps core.Deps) (core.Capability, error) { return New(deps), nil }

// SetProxyURL sets the egress proxy for GitHub API requests.
func (k *Kit) SetProxyURL(proxy string) {
	if k != nil && k.client != nil {
		k.client.ProxyURL = proxy
	}
}

func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "githubkit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "fetcher", "settings"},
		Tools: []core.ToolSpec{
			{
				Name:        "github_secret_search",
				Description: "Search GitHub code for leaked secrets using a built-in dork template or a custom query. Returns repo/path/fragments, secret type and a static credibility hint; it does not validate the credential. Requires a GitHub token in settings (github.token).",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "template_id":{"type":"string","description":"built-in dork template id (see github_dork_templates)"},
    "query":{"type":"string","description":"custom GitHub code-search query; used when template_id is empty"},
    "org":{"type":"string","description":"substitute {org} in the template"},
    "domain":{"type":"string","description":"substitute {domain} in the template; also used as the scope target"},
    "page":{"type":"integer","description":"1-based page (default 1)"},
    "per_page":{"type":"integer","description":"1-100 (default 30)"},
    "cursor":{"type":"string","description":"分页游标，用上一次返回的 page.cursor 续取下一页"}
  }
}`),
				Risk:         core.RiskMedium,
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"total_count":{"type":"integer","description":"GitHub 报告的真实命中总数"},"incomplete":{"type":"boolean"},"truncated":{"type":"boolean"},"page":{"type":"integer"},"per_page":{"type":"integer"},"query":{"type":"string"},"items":{"type":"array","items":{"type":"object"}}}}`),
				RateLimit:    core.RateLimitSpec{PerSecond: 0.15, Burst: 2, Concurrency: 1},
				ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
					var in searchInput
					if err := json.Unmarshal(input, &in); err != nil {
						return nil, err
					}
					if strings.TrimSpace(in.Domain) == "" {
						return nil, nil
					}
					t, err := core.TargetFromString(0, in.Domain)
					if err != nil {
						return nil, err
					}
					return []core.Target{t}, nil
				},
			},
			{
				Name:           "github_dork_templates",
				Description:    "List the built-in GitHub secret-search dork templates (id, category, title, query, note).",
				InputSchema:    json.RawMessage(`{"type":"object","properties":{}}`),
				Risk:           core.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"templates":{"type":"array","items":{"type":"object"}}}}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
		},
		Settings: []core.SettingSpec{{
			Key: "github.token", Type: "string", Secret: true,
			Description: "GitHub personal access token for Code Search (requires code search permission).",
		}},
	}
}

// searchDefaultPerPage mirrors the client's default so the cursor arithmetic
// matches what was actually requested.
const (
	searchDefaultPerPage = 30
	// searchMaxPerPage mirrors the API's own ceiling.
	searchMaxPerPage = 100
)

type searchInput struct {
	TemplateID string `json:"template_id"`
	Query      string `json:"query"`
	Org        string `json:"org"`
	Domain     string `json:"domain"`
	Page       int    `json:"page"`
	PerPage    int    `json:"per_page"`
	// Cursor continues a listing the way every other tool does (§5.5.4); it
	// wins over Page when both are present.
	Cursor string `json:"cursor"`
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
	case "github_secret_search":
		return k.search(ctx, call)
	case "github_dork_templates":
		return k.templates(ctx)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) templates(context.Context) (core.Result, error) {
	list := Templates()
	return core.SuccessResult(fmt.Sprintf("返回 %d 条 dork 模板", len(list)),
		map[string]any{"templates": list, "count": len(list)})
}

func (k *Kit) search(ctx context.Context, call core.Call) (core.Result, error) {
	var in searchInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	query := strings.TrimSpace(in.Query)
	label := "custom"
	if strings.TrimSpace(in.TemplateID) != "" {
		t, ok := TemplateByID(strings.TrimSpace(in.TemplateID))
		if !ok {
			return core.FailResult(core.NotFound("unknown dork template: " + in.TemplateID)), nil
		}
		query = BuildQuery(t, in.Org, in.Domain)
		label = t.ID
	}
	if query == "" {
		return core.FailResult(core.InvalidInput("query or template_id is required")), nil
	}
	perPage := core.FirstPositive(in.PerPage, searchDefaultPerPage)
	if perPage > searchMaxPerPage {
		perPage = searchMaxPerPage
	}
	page := in.Page
	if c := strings.TrimSpace(in.Cursor); c != "" {
		// Code search pages by page number, so translate the shared offset
		// cursor back into one.
		start, _, _, perr := core.PageWindow(1<<30, c, perPage)
		if perr != nil {
			return core.FailResult(perr), nil
		}
		if start%perPage != 0 {
			return core.FailResult(core.InvalidInput("cursor 非法，需使用上一次返回的 page.cursor")), nil
		}
		page = start/perPage + 1
	}
	if page <= 0 {
		page = 1
	}
	result, err := k.client.Search(ctx, query, page, perPage)
	if err != nil {
		return core.FailResult(err), nil
	}
	highConfidence := 0
	for _, item := range result.Items {
		if item.Credibility.Level == "high" {
			highConfidence++
		}
	}
	summary := fmt.Sprintf("在 GitHub 检索 %s，命中 %d 条疑似泄露，高置信 %d 条",
		query, result.TotalCount, highConfidence)
	res, err := core.SuccessResult(summary, result)
	if err != nil {
		return core.Result{}, err
	}
	// A code search can match far more than one page; report the true total and
	// the cursor that reaches the next page.
	next := (page-1)*perPage + len(result.Items)
	res.Page = &core.Page{Total: result.TotalCount, HasMore: next < result.TotalCount}
	if res.Page.HasMore {
		res.Page.Cursor = core.CursorFor(next)
	}
	res.Truncated = result.Truncated
	if k.evidence != nil {
		data, _ := json.Marshal(result)
		target := core.Target{}
		if strings.TrimSpace(in.Domain) != "" {
			target, _ = core.TargetFromString(call.Context.ProjectID, in.Domain)
		}
		id, eerr := k.evidence.Record(ctx, core.Evidence{
			Kind: "github_secret", Title: "GitHub secret search: " + label, Target: target,
			Data: data, CreatedAt: time.Now(),
			Metadata: map[string]string{
				"query": query, "template": label,
				"total": fmt.Sprint(result.TotalCount), "items": fmt.Sprint(len(result.Items)),
			},
		})
		if eerr == nil && id != "" {
			res.EvidenceIDs = []string{id}
		}
	}
	return res, nil
}

// SearchURL is a helper for host UIs/tests.
func SearchURL(base, query string, page, perPage int) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = "https://api.github.com"
	}
	return fmt.Sprintf("%s/search/code?q=%s&page=%d&per_page=%d", base, url.QueryEscape(query), page, perPage)
}
