package httpx

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Fetcher is the non-target-scoped external download client. It applies rate
// limiting and audit but deliberately does not enforce project scope (rule
// updates, GitHub search and threat intel are external infrastructure).
type Fetcher struct {
	Base         *http.Client
	Limiter      core.Limiter
	Audit        core.AuditSink
	Clock        core.Clock
	MaxBodyBytes int64
	RateLimit    core.RateLimitSpec
}

func NewFetcher(limiter core.Limiter, audit core.AuditSink) *Fetcher {
	return &Fetcher{Limiter: limiter, Audit: audit, MaxBodyBytes: 10 << 20}
}

func (f *Fetcher) Fetch(ctx context.Context, req core.Request) (*core.Response, error) {
	target, err := core.TargetFromURL(0, req.URL)
	if err != nil {
		return nil, core.InvalidInput(err.Error())
	}
	spec := f.RateLimit
	if spec.PerSecond <= 0 {
		spec = core.RateLimitSpec{PerSecond: 5, Burst: 2, Concurrency: 2}
	}
	if f.Limiter != nil {
		release, err := f.Limiter.Acquire(ctx, target.Key(), spec)
		if err != nil {
			return nil, err
		}
		defer release()
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	base := f.Base
	if base == nil {
		base = &http.Client{}
	}
	client := *base
	client.Timeout = timeout
	if req.Proxy != "" {
		var transport http.RoundTripper = http.DefaultTransport
		if t, ok := http.DefaultTransport.(*http.Transport); ok {
			transport = t.Clone()
		}
		if u, perr := url.Parse(req.Proxy); perr == nil {
			if t, ok := transport.(*http.Transport); ok {
				t.Proxy = http.ProxyURL(u)
			}
		}
		client.Transport = transport
	}
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return nil, core.InvalidInput(err.Error())
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	started := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		f.audit(ctx, target, "error", err.Error(), time.Since(started))
		return nil, core.Unavailable(err.Error())
	}
	defer resp.Body.Close()
	max := f.MaxBodyBytes
	if max <= 0 {
		max = 10 << 20
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, max))
	if readErr != nil {
		return nil, core.Unavailable("read response: " + readErr.Error())
	}
	headers := map[string][]string{}
	for k, vs := range resp.Header {
		headers[k] = append([]string(nil), vs...)
	}
	finalURL := req.URL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	f.audit(ctx, target, "ok", "", time.Since(started))
	return &core.Response{
		Status: resp.StatusCode, Headers: headers, Body: data,
		Duration: time.Since(started), FinalURL: finalURL,
	}, nil
}

func (f *Fetcher) audit(ctx context.Context, target core.Target, status, errMsg string, d time.Duration) {
	if f.Audit == nil {
		return
	}
	cc, _ := core.CallContextFrom(ctx)
	f.Audit.Record(ctx, core.AuditEvent{
		TraceID: cc.TraceID, Actor: cc.Actor, ProjectID: cc.ProjectID, TaskID: cc.TaskID,
		Capability: "fetcher", Tool: "fetch", Risk: core.RiskLow,
		Targets: []core.Target{target}, Phase: "fetch", Status: status, Error: errMsg,
		DurationMS: d.Milliseconds(), StartedAt: time.Now().Add(-d), FinishedAt: time.Now(),
	})
}
