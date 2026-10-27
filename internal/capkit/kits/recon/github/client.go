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

type SearchItem struct {
	Repo        string      `json:"repo"`
	RepoURL     string      `json:"repo_url"`
	Path        string      `json:"path"`
	FileURL     string      `json:"file_url"`
	Stars       int         `json:"stars"`
	Fork        bool        `json:"fork"`
	OwnerLogin  string      `json:"owner_login,omitempty"`
	PushedAt    string      `json:"pushed_at,omitempty"`
	Fragments   []string    `json:"fragments,omitempty"`
	SecretType  string      `json:"secret_type"`
	Credibility Credibility `json:"credibility"`
}

type SearchResult struct {
	TotalCount int          `json:"total_count"`
	Incomplete bool         `json:"incomplete"`
	Items      []SearchItem `json:"items"`
	Query      string       `json:"query"`
	Page       int          `json:"page"`
	PerPage    int          `json:"per_page"`
	Truncated  bool         `json:"truncated"`
}

// Client runs GitHub Code Search through the external Fetcher port.
type Client struct {
	Fetcher  core.Fetcher
	Settings core.Settings
	Limiter  core.Limiter
	BaseURL  string
	ProxyURL string
}

const searchResultCap = 1000

func (c *Client) Search(ctx context.Context, query string, page, perPage int) (*SearchResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, core.InvalidInput("query is required")
	}
	if c.Fetcher == nil {
		return nil, core.Unavailable("github fetcher is not configured")
	}
	token := c.token(ctx)
	if token == "" {
		return nil, core.Unavailable("GitHub token is not configured (settings: github.token)")
	}
	if page <= 0 {
		page = 1
	}
	if perPage <= 0 {
		perPage = 30
	}
	if perPage > 100 {
		perPage = 100
	}
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		base = "https://api.github.com"
	}
	endpoint := fmt.Sprintf("%s/search/code?q=%s&page=%d&per_page=%d",
		base, url.QueryEscape(query), page, perPage)

	if c.Limiter != nil {
		release, err := c.Limiter.Acquire(ctx, "api.github.com", core.RateLimitSpec{
			PerSecond: 0.15, Burst: 2, Concurrency: 1,
		})
		if err != nil {
			return nil, err
		}
		defer release()
	}
	res, err := c.Fetcher.Fetch(ctx, core.Request{
		Method: "GET", URL: endpoint, Timeout: 25 * time.Second, Proxy: c.ProxyURL,
		Headers: map[string]string{
			"Accept":               "application/vnd.github.text-match+json",
			"X-GitHub-Api-Version": "2022-11-28",
			"Authorization":        "Bearer " + token,
			"User-Agent":           "capkit-githubkit",
		},
	})
	if err != nil {
		return nil, err
	}
	switch res.Status {
	case 200:
		// ok
	case 401, 403:
		return nil, core.NewError(core.CodeUnavailable,
			fmt.Sprintf("GitHub API rejected the request (%d): %s", res.Status, ghMessage(res.Body)))
	case 422:
		return nil, core.InvalidInput("GitHub rejected the query: " + ghMessage(res.Body))
	default:
		return nil, core.NewError(core.CodeUnavailable,
			fmt.Sprintf("GitHub API %d: %s", res.Status, ghMessage(res.Body)))
	}
	var raw githubCodeResponse
	if err := json.Unmarshal(res.Body, &raw); err != nil {
		return nil, core.NewError(core.CodeInternal, "parse GitHub response: "+err.Error())
	}
	out := &SearchResult{
		TotalCount: raw.TotalCount, Incomplete: raw.IncompleteResults,
		Query: query, Page: page, PerPage: perPage,
		Truncated: page*perPage >= searchResultCap || raw.TotalCount > searchResultCap,
	}
	for _, item := range raw.Items {
		fragments := make([]string, 0, len(item.TextMatches))
		for _, tm := range item.TextMatches {
			if strings.TrimSpace(tm.Fragment) != "" {
				fragments = append(fragments, tm.Fragment)
			}
		}
		out.Items = append(out.Items, SearchItem{
			Repo: item.Repository.FullName, RepoURL: item.Repository.HTMLURL,
			Path: item.Path, FileURL: item.HTMLURL,
			Stars: item.Repository.StargazersCount, Fork: item.Repository.Fork,
			OwnerLogin: item.Repository.Owner.Login, PushedAt: item.Repository.PushedAt,
			Fragments: fragments, SecretType: Classify(fragments),
			Credibility: ScoreCredibility(item.Repository.FullName, item.Repository.StargazersCount,
				item.Repository.Fork, item.Path),
		})
	}
	return out, nil
}

func (c *Client) token(ctx context.Context) string {
	if c.Settings == nil {
		return ""
	}
	for _, key := range []string{"github.token", "githubsearch.token"} {
		if v, ok := c.Settings.GetString(ctx, key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

type githubCodeItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName        string `json:"full_name"`
		HTMLURL         string `json:"html_url"`
		StargazersCount int    `json:"stargazers_count"`
		PushedAt        string `json:"pushed_at"`
		Fork            bool   `json:"fork"`
		Owner           struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
	TextMatches []struct {
		Fragment string `json:"fragment"`
	} `json:"text_matches"`
}

type githubCodeResponse struct {
	TotalCount        int              `json:"total_count"`
	IncompleteResults bool             `json:"incomplete_results"`
	Items             []githubCodeItem `json:"items"`
	Message           string           `json:"message"`
}

func ghMessage(body []byte) string {
	var v struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &v); err == nil && v.Message != "" {
		return v.Message
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
