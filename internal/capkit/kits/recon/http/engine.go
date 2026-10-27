package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Kind implements core.TemplateEngine for kind=http.
func (k *Kit) Kind() string { return "http" }

type engineRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type engineMatcher struct {
	Type   string   `json:"type"`
	Part   string   `json:"part,omitempty"`
	Status []int    `json:"status,omitempty"`
	Words  []string `json:"words,omitempty"`
	Regex  []string `json:"regex,omitempty"`
	DSL    string   `json:"dsl,omitempty"`
}

type engineExtract struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
	Group int    `json:"group,omitempty"`
}

type engineTemplate struct {
	Request  engineRequest   `json:"request"`
	Matchers []engineMatcher `json:"matchers,omitempty"`
	Extract  []engineExtract `json:"extract,omitempty"`
}

type engineResult struct {
	ID        string            `json:"id"`
	Matched   bool              `json:"matched"`
	Status    int               `json:"status"`
	URL       string            `json:"url"`
	Extracted map[string]string `json:"extracted,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// Execute runs engine-neutral http templates against one target. Matchers are
// ANDed; a template with no matchers is treated as "request succeeded".
func (k *Kit) Execute(ctx context.Context, refs []core.TemplateRef, target core.Target, _ map[string]any) (core.Result, error) {
	if k.HTTP == nil {
		return core.FailResult(core.Unavailable("http doer is not configured")), nil
	}
	base, err := engineBaseURL(target)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	results := make([]engineResult, 0, len(refs))
	for _, ref := range refs {
		res := engineResult{ID: ref.ID}
		var tpl engineTemplate
		if err := json.Unmarshal(ref.Artifact, &tpl); err != nil {
			res.Error = "parse template: " + err.Error()
			results = append(results, res)
			continue
		}
		if strings.TrimSpace(tpl.Request.Path) == "" {
			res.Error = "template request.path is required"
			results = append(results, res)
			continue
		}
		full := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(tpl.Request.Path, "/")
		method := strings.ToUpper(strings.TrimSpace(tpl.Request.Method))
		if method == "" {
			method = "GET"
		}
		res.URL = full
		httpRes, derr := k.HTTP.Do(ctx, core.Request{
			Method: method, URL: full, Headers: tpl.Request.Headers, Body: []byte(tpl.Request.Body),
		})
		if derr != nil {
			res.Error = derr.Error()
			results = append(results, res)
			continue
		}
		res.Status = httpRes.Status
		matched, merr := matchEngineTemplate(tpl.Matchers, httpRes)
		if merr != nil {
			res.Error = merr.Error()
			results = append(results, res)
			continue
		}
		res.Matched = matched
		res.Extracted = extractEngineValues(tpl.Extract, httpRes)
		if k.Evidence != nil {
			id, eerr := k.Evidence.Record(ctx, core.Evidence{
				Kind: "template_http", Title: "http template " + ref.ID, Target: target,
				Request:  []byte(fmt.Sprintf("%s %s\n", method, full)),
				Response: []byte(fmt.Sprintf("HTTP %d\n%s", httpRes.Status, truncateBody(httpRes.Body, 256<<10))),
				Metadata: map[string]string{"template": ref.ID, "matched": fmt.Sprint(matched)},
			})
			_ = eerr
			_ = id
		}
		results = append(results, res)
	}
	out, _ := core.DataResult(map[string]any{"target": target, "results": results, "count": len(results)})
	return out, nil
}

func engineBaseURL(target core.Target) (string, error) {
	if strings.TrimSpace(target.URL) != "" {
		u, err := url.Parse(target.URL)
		if err == nil && u.Scheme != "" && u.Host != "" {
			return u.Scheme + "://" + u.Host, nil
		}
		return "", fmt.Errorf("invalid target URL %q", target.URL)
	}
	host := target.Host
	if host == "" {
		host = target.IP
	}
	if host == "" {
		return "", fmt.Errorf("target has no URL/host")
	}
	scheme := "http"
	if target.Port == 443 {
		scheme = "https"
	}
	if target.Port > 0 && target.Port != 80 && target.Port != 443 {
		host = fmt.Sprintf("%s:%d", host, target.Port)
	}
	return scheme + "://" + host, nil
}

func matchEngineTemplate(matchers []engineMatcher, res *core.Response) (bool, error) {
	if len(matchers) == 0 {
		return res.Status >= 200 && res.Status < 400, nil
	}
	for _, m := range matchers {
		ok, err := matchOne(m, res)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func matchOne(m engineMatcher, res *core.Response) (bool, error) {
	part := strings.ToLower(strings.TrimSpace(m.Part))
	if part == "" {
		part = "body"
	}
	text := string(res.Body)
	switch part {
	case "header", "headers":
		var b strings.Builder
		for k, vs := range res.Headers {
			for _, v := range vs {
				b.WriteString(k)
				b.WriteString(": ")
				b.WriteString(v)
				b.WriteString("\n")
			}
		}
		text = b.String()
	case "status":
		// status is handled by matcher type below
	case "body":
	default:
		return false, fmt.Errorf("unsupported matcher part %q", m.Part)
	}
	switch strings.ToLower(strings.TrimSpace(m.Type)) {
	case "status":
		for _, s := range m.Status {
			if res.Status == s {
				return true, nil
			}
		}
		return false, nil
	case "word":
		for _, w := range m.Words {
			if strings.Contains(strings.ToLower(text), strings.ToLower(w)) {
				return true, nil
			}
		}
		return false, nil
	case "regex":
		for _, expr := range m.Regex {
			re, err := regexp.Compile(expr)
			if err != nil {
				return false, fmt.Errorf("invalid regex %q: %w", expr, err)
			}
			if re.MatchString(text) {
				return true, nil
			}
		}
		return false, nil
	case "dsl":
		return false, fmt.Errorf("dsl matchers are not supported by httpkit; use regex/word")
	default:
		return false, fmt.Errorf("unsupported matcher type %q", m.Type)
	}
}

func extractEngineValues(extracts []engineExtract, res *core.Response) map[string]string {
	out := map[string]string{}
	text := string(res.Body)
	for _, ex := range extracts {
		re, err := regexp.Compile(ex.Regex)
		if err != nil {
			continue
		}
		m := re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		group := ex.Group
		if group <= 0 {
			if len(m) > 1 {
				group = 1
			} else {
				group = 0
			}
		}
		if group < len(m) {
			out[ex.Name] = m[group]
		}
	}
	return out
}

func truncateBody(body []byte, max int) []byte {
	if max <= 0 || len(body) <= max {
		return body
	}
	out := append([]byte(nil), body[:max]...)
	return append(out, []byte("\n…[truncated]")...)
}
