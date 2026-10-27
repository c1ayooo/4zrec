// Package oastkit provides out-of-band interaction helpers backed by dnslog.cn
// (or a compatible self-hosted dnslog service). It uses the external Fetcher
// port, so it is rate-limited/audited but not project-scope-checked.
package oast

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

const DefaultBaseURL = "http://dnslog.cn"

// kitVersion is stamped into every Result envelope (mirrors the manifest).
const kitVersion = "0.1.0"

type Client struct {
	Fetcher core.Fetcher
	BaseURL string

	mu     sync.Mutex
	cookie string
}

func (c *Client) base() string {
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		base = DefaultBaseURL
	}
	return base
}

func (c *Client) GetDomain(ctx context.Context) (string, error) {
	if c.Fetcher == nil {
		return "", core.Unavailable("oast fetcher is not configured")
	}
	res, err := c.Fetcher.Fetch(ctx, core.Request{
		Method: "GET", URL: c.base() + "/getdomain.php", Timeout: 15 * time.Second,
		Headers: map[string]string{"User-Agent": "capkit-oastkit"},
	})
	if err != nil {
		return "", err
	}
	if res.Status != 200 {
		return "", core.Unavailable(fmt.Sprintf("dnslog getdomain HTTP %d", res.Status))
	}
	cookie := firstHeader(res.Headers, "Set-Cookie")
	domain := strings.TrimSpace(string(res.Body))
	if domain == "" {
		return "", core.Unavailable("dnslog returned an empty domain")
	}
	c.mu.Lock()
	c.cookie = cookie
	c.mu.Unlock()
	return domain, nil
}

func (c *Client) GetRecords(ctx context.Context, domain string, waitSec int) ([]string, error) {
	if c.Fetcher == nil {
		return nil, core.Unavailable("oast fetcher is not configured")
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, core.InvalidInput("domain is required")
	}
	if waitSec > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(waitSec) * time.Second):
		}
	}
	headers := map[string]string{"User-Agent": "capkit-oastkit"}
	c.mu.Lock()
	if c.cookie != "" {
		headers["Cookie"] = c.cookie
	}
	c.mu.Unlock()
	res, err := c.Fetcher.Fetch(ctx, core.Request{
		Method: "GET", URL: c.base() + "/getrecords.php?t=" + url.QueryEscape(domain),
		Timeout: 15 * time.Second, Headers: headers,
	})
	if err != nil {
		return nil, err
	}
	if res.Status != 200 {
		return nil, core.Unavailable(fmt.Sprintf("dnslog getrecords HTTP %d", res.Status))
	}
	return parseRecords(res.Body), nil
}

func parseRecords(body []byte) []string {
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil
	}
	var arr []string
	if json.Unmarshal([]byte(raw), &arr) == nil {
		out := make([]string, 0, len(arr))
		for _, v := range arr {
			if s := strings.TrimSpace(v); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasSuffix(line, "%") {
			line = strings.TrimSuffix(line, "%")
		}
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func firstHeader(headers map[string][]string, name string) string {
	for k, vs := range headers {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// Kit exposes dnslog.cn as two tools.
type Kit struct {
	client   *Client
	evidence core.EvidenceSink
}

func New(deps core.Deps) *Kit {
	return &Kit{
		client:   &Client{Fetcher: deps.Fetcher},
		evidence: deps.Evidence,
	}
}

func NewCapability(deps core.Deps) (core.Capability, error) { return New(deps), nil }

func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "oastkit", Version: kitVersion, APIVersion: "v1",
		Requires: []string{"limiter", "audit", "fetcher"},
		Tools: []core.ToolSpec{
			{
				Name:           "oast_get_domain",
				Description:    "Get a fresh dnslog.cn callback domain for blind SSRF/XXE/injection verification. The domain is bound to an in-memory session cookie; follow with oast_get_records.",
				InputSchema:    json.RawMessage(`{"type":"object","properties":{}}`),
				Risk:           core.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"domain":{"type":"string"}}}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name:        "oast_get_records",
				Description: "Fetch DNS interaction records for a domain returned by oast_get_domain. wait_seconds gives the target time to resolve (recommended 3-10s).",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "domain":{"type":"string","description":"domain from oast_get_domain"},
    "wait_seconds":{"type":"integer","description":"wait before querying (default 0, recommended 3-10)"}
  },
  "required":["domain"]
}`),
				Risk:           core.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"records":{"type":"array","items":{"type":"object"}},"count":{"type":"integer"}}}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
		},
	}
}

// Call is the envelope shell: it runs the tool and normalizes the Result so
// every return path carries a valid Status, Meta.Tool and a clamped Summary.
func (k *Kit) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := k.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

// dispatch routes a call to its tool implementation, exactly as before.
func (k *Kit) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "oast_get_domain":
		return k.getDomain(ctx)
	case "oast_get_records":
		return k.getRecords(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) getDomain(ctx context.Context) (core.Result, error) {
	domain, err := k.client.GetDomain(ctx)
	if err != nil {
		return core.FailResult(err), nil
	}
	res, _ := core.SuccessResult("申请到 dnslog 回连域名 "+domain, map[string]any{"domain": domain})
	return res, nil
}

func (k *Kit) getRecords(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		Domain      string `json:"domain"`
		WaitSeconds int    `json:"wait_seconds"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	records, err := k.client.GetRecords(ctx, in.Domain, in.WaitSeconds)
	if err != nil {
		return core.FailResult(err), nil
	}
	summary := fmt.Sprintf("查询 %s 的 DNS 交互记录，命中 %d 条", strings.TrimSpace(in.Domain), len(records))
	res, _ := core.SuccessResult(summary, map[string]any{"domain": in.Domain, "records": records, "count": len(records)})
	if k.evidence != nil && len(records) > 0 {
		data, _ := json.Marshal(records)
		id, eerr := k.evidence.Record(ctx, core.Evidence{
			Kind: "oast", Title: "dnslog records " + in.Domain, Data: data, CreatedAt: time.Now(),
			Metadata: map[string]string{"domain": in.Domain, "records": fmt.Sprint(len(records))},
		})
		if eerr == nil && id != "" {
			res.EvidenceIDs = []string{id}
		}
	}
	return res, nil
}
