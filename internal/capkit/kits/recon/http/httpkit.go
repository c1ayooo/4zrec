package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// kitVersion is the version stamped into every Result envelope. It mirrors the
// manifest version so a host can attribute an envelope to a build.
const kitVersion = "0.1.0"

// Kit exposes structured HTTP probing. It uses only the injected HTTPDoer,
// so scope/rate/audit gates cannot be bypassed.
type Kit struct {
	HTTP     core.HTTPDoer
	Evidence core.EvidenceSink
	IDs      core.IDGenerator
}

func New(deps core.Deps) *Kit {
	return &Kit{HTTP: deps.HTTP, Evidence: deps.Evidence, IDs: deps.IDs}
}

func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "httpkit", Version: kitVersion, APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "http"},
		Tools: []core.ToolSpec{{
			Name:        "http_probe",
			Description: "Structured HTTP request through the runtime's gate-aware client. Returns status, headers and a bounded body preview; the full exchange is recorded as evidence when an EvidenceSink is configured.",
			InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "url":{"type":"string","description":"http(s) URL"},
    "method":{"type":"string","description":"HTTP method (default GET)"},
    "headers":{"type":"object","description":"request headers"},
    "body":{"type":"string","description":"request body"},
    "timeout_ms":{"type":"integer","description":"overall timeout in ms (default 20000)"},
    "proxy":{"type":"string","description":"optional http/socks5 proxy URL"}
  },
  "required":["url"]
}`),
			Risk:         core.RiskMedium,
			OutputSchema: json.RawMessage(`{"type":"object","properties":{"status":{"type":"integer"},"headers":{"type":"object"},"body":{"type":"string"},"body_bytes":{"type":"integer"},"duration_ms":{"type":"integer"},"final_url":{"type":"string"}}}`),
			RateLimit:    core.RateLimitSpec{PerSecond: 10, Burst: 5, Concurrency: 4},
			ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
				var in probeInput
				if err := json.Unmarshal(input, &in); err != nil {
					return nil, err
				}
				if strings.TrimSpace(in.URL) == "" {
					return nil, fmt.Errorf("url is required")
				}
				t, err := core.TargetFromURL(0, in.URL)
				if err != nil {
					return nil, err
				}
				return []core.Target{t}, nil
			},
		}},
	}
}

type probeInput struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	TimeoutMS int               `json:"timeout_ms"`
	Proxy     string            `json:"proxy"`
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
	case "http_probe":
		return k.probe(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) probe(ctx context.Context, call core.Call) (core.Result, error) {
	var in probeInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if k.HTTP == nil {
		return core.FailResult(core.Unavailable(
			"对 " + in.URL + " 探测不可用：http doer is not configured")), nil
	}
	timeout := time.Duration(in.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = "GET"
	}
	req := core.Request{
		Method: method, URL: in.URL, Headers: in.Headers,
		Body: []byte(in.Body), Proxy: in.Proxy, Timeout: timeout,
	}
	res, err := k.HTTP.Do(ctx, req)
	if err != nil {
		return core.FailResult(err), nil
	}

	preview := res.Body
	if len(preview) > 64*1024 {
		preview = preview[:64*1024]
	}
	out := map[string]any{
		"status": res.Status, "headers": res.Headers, "body": string(preview),
		"body_bytes": len(res.Body), "duration_ms": res.Duration.Milliseconds(),
		"final_url": res.FinalURL,
	}
	// Summary is the agent-readable line: target + action + the real result.
	// The body itself is never inlined here — only its byte count is reported;
	// the full exchange lives behind EvidenceIDs.
	server := headerValue(res.Headers, "Server")
	if server == "" {
		server = "-"
	}
	summary := fmt.Sprintf("对 %s 发 %s 探测，HTTP %d，%d 字节，Server=%s",
		in.URL, method, res.Status, len(res.Body), server)
	result, _ := core.SuccessResult(summary, out)

	if k.Evidence != nil {
		target, _ := core.TargetFromURL(call.Context.ProjectID, in.URL)
		reqText := fmt.Sprintf("%s %s\n", method, in.URL)
		for key, value := range in.Headers {
			reqText += key + ": " + value + "\n"
		}
		reqText += "\n" + in.Body
		respText := fmt.Sprintf("HTTP %d\n", res.Status)
		for key, values := range res.Headers {
			for _, value := range values {
				respText += key + ": " + value + "\n"
			}
		}
		respText += "\n" + string(res.Body)
		id, err := k.Evidence.Record(ctx, core.Evidence{
			Kind: "http", Title: method + " " + hostOf(in.URL), Target: target,
			Request: []byte(reqText), Response: []byte(respText), CreatedAt: time.Now(),
		})
		if err == nil && id != "" {
			result.EvidenceIDs = []string{id}
		}
	}
	return result, nil
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

// headerValue returns the first value of name (case-insensitive), or "".
func headerValue(headers map[string][]string, name string) string {
	for k, vs := range headers {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}
