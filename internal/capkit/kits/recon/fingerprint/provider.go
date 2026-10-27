package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Provider implements core.FingerprintProvider. It probes the target through
// the gate-aware HTTPDoer, matches the rule set, and optionally records
// evidence. It never writes assets.
type Provider struct {
	HTTP     core.HTTPDoer
	Rules    *RuleSet
	Evidence core.EvidenceSink
}

func (p *Provider) Fingerprint(ctx context.Context, target core.Target) ([]core.Fingerprint, error) {
	if p == nil || p.HTTP == nil || p.Rules == nil {
		return nil, core.Unavailable("fingerprint provider is not configured")
	}
	rawURL := strings.TrimSpace(target.URL)
	if rawURL == "" {
		host := core.FirstNonEmpty(target.Host, target.IP, target.CIDR)
		if host == "" {
			return nil, core.InvalidInput("target has no URL/host")
		}
		if target.Port > 0 {
			host = net.JoinHostPort(host, strconv.Itoa(target.Port))
		}
		rawURL = "http://" + host
	}
	res, err := p.HTTP.Do(ctx, core.Request{Method: "GET", URL: rawURL, Timeout: 20 * time.Second})
	if err != nil {
		return nil, err
	}
	cookies := parseSetCookies(res.Headers)
	techs := p.Rules.Match(Response{
		URL: res.FinalURL, Status: res.Status, Headers: res.Headers,
		Body: res.Body, Cookies: cookies,
	})
	out := make([]core.Fingerprint, 0, len(techs))
	for _, t := range techs {
		out = append(out, core.Fingerprint{
			Product: t.Product, Version: t.Version, Category: t.Category,
			Source: t.Source, Confidence: t.Confidence,
		})
	}
	if p.Evidence != nil {
		data, _ := json.Marshal(techs)
		_, err := p.Evidence.Record(ctx, core.Evidence{
			Kind: "fingerprint", Title: "fingerprint " + target.Key(), Target: target,
			Data: data, CreatedAt: time.Now(),
			Metadata: map[string]string{"url": rawURL, "hits": fmt.Sprint(len(techs))},
		})
		if err != nil {
			// Evidence failure must not hide the detection result.
			_ = err
		}
	}
	return out, nil
}

func parseSetCookies(headers map[string][]string) map[string]string {
	out := map[string]string{}
	for k, vs := range headers {
		if !strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		for _, raw := range vs {
			parts := strings.SplitN(raw, ";", 2)
			kv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
			if len(kv) == 2 && strings.TrimSpace(kv[0]) != "" {
				out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	return out
}
