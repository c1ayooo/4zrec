package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// The kit's only outbound path is core.Fetcher. Sources are public advisory
// endpoints, not project targets, so they belong on the fetcher port: the
// host still applies proxy, timeout, rate limit and audit policy, but not
// project target scope (see core.Fetcher).
const (
	defaultTimeout = 30 * time.Second
	// defaultUserAgent identifies the tool politely; several sources reject
	// empty agent strings.
	defaultUserAgent = "capkit-vulnintel/0.1 (+https://github.com/c1ayooo/4zrec/internal/capkit)"
)

// client is the shared fetch helper. It is deliberately dumb: request, status
// check, bounded body. Retry and backoff belong to the host port.
type client struct {
	fetcher core.Fetcher
	timeout time.Duration
	proxy   string
	// backoff is how long to wait before retrying a throttled request. It is a
	// field (not the constant) so tests can exercise the retry without sleeping.
	backoff time.Duration
}

func newClient(fetcher core.Fetcher) *client {
	return &client{fetcher: fetcher, timeout: defaultTimeout, backoff: throttleBackoff}
}

func (c *client) get(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	return c.do(ctx, core.Request{Method: "GET", URL: url, Headers: c.headers(headers)})
}

func (c *client) postJSON(ctx context.Context, url string, headers map[string]string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, core.Request{
		Method: "POST", URL: url, Headers: c.headers(headers), Body: raw,
	})
}

func (c *client) do(ctx context.Context, req core.Request) ([]byte, error) {
	if c == nil || c.fetcher == nil {
		return nil, core.Unavailable("vulnintelkit: fetcher 端口未配置，无法抓取情报源")
	}
	if req.Timeout <= 0 {
		req.Timeout = c.timeout
	}
	if req.Proxy == "" {
		req.Proxy = c.proxy
	}
	resp, err := c.fetcher.Fetch(ctx, req)
	if err != nil {
		return nil, err
	}
	// A throttle is a temporary refusal, not a parse failure. Backing off once
	// turns it back into a usable feed: chaitin's WAF answers 465 after a
	// handful of rapid requests and seebug answers 403 when several sources are
	// polled in quick succession, and both clear within seconds (verified live,
	// 2026-10-20). Without this, a normal poll of all nine sources makes the
	// later ones look broken.
	if retryableThrottle(resp.Status) {
		wait := c.backoff
		if wait <= 0 {
			wait = throttleBackoff
		}
		select {
		case <-ctx.Done():
			return nil, core.Unavailable(fmt.Sprintf("上游返回 HTTP %d（%s）", resp.Status, shortURL(req.URL)))
		case <-time.After(wait):
		}
		resp, err = c.fetcher.Fetch(ctx, req)
		if err != nil {
			return nil, err
		}
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return nil, core.Unavailable(fmt.Sprintf("上游返回 HTTP %d（%s）", resp.Status, shortURL(req.URL)))
	}
	return resp.Body, nil
}

// retryableThrottle reports whether a status is a rate-limit refusal that a
// single pause is likely to clear. 403 is included deliberately: the sources
// here use it for rate limiting rather than for a permanent authorisation
// failure, and a genuinely permanent 403 costs one extra attempt, not a loop.
func retryableThrottle(status int) bool {
	switch status {
	case http.StatusForbidden, http.StatusTooManyRequests, 465:
		return true
	}
	return false
}

// throttleBackoff is the pause before one retry of a throttled request.
const throttleBackoff = 5 * time.Second

// headers merges the caller's headers over the defaults. An explicit
// User-Agent or Content-Type always wins.
func (c *client) headers(extra map[string]string) map[string]string {
	out := map[string]string{"User-Agent": defaultUserAgent}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func shortURL(raw string) string {
	if len(raw) <= 80 {
		return raw
	}
	return raw[:80] + "…"
}

// dedupeByKey keeps the first item per unique key, preserving input order.
// Sources that paginate can return the same advisory twice across pages.
func dedupeByKey(items []core.IntelItem) []core.IntelItem {
	seen := make(map[string]bool, len(items))
	out := make([]core.IntelItem, 0, len(items))
	for _, it := range items {
		if it.UniqueKey == "" || seen[it.UniqueKey] {
			continue
		}
		seen[it.UniqueKey] = true
		out = append(out, it)
	}
	return out
}

// capItems truncates to limit (<=0 means "the source's own default").
func capItems(items []core.IntelItem, limit int) []core.IntelItem {
	if limit > 0 && len(items) > limit {
		return items[:limit]
	}
	return items
}

// parseTime accepts the date shapes the scrapers meet. An unparseable value
// yields the zero time, which callers render as an empty disclosure date.
func parseTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02", "2006/01/02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

// dedupeStrings drops blanks and case-insensitive duplicates, preserving order.
// Sources synthesize tags from several fields (explicit tag list, category
// string, exploit/patch flags), so the same value can arrive twice.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	return out
}

// trimPtr dereferences an optional string from a source payload.
func trimPtr(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

// dayOnly normalizes a disclosure timestamp to YYYY-MM-DD. Sources publish
// timestamps, dates and RFC3339 strings; a stable format keeps the host's
// diffs meaningful.
func dayOnly(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}
