package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// This file exposes the identity primitives as agent-facing tools. The
// primitives (identity.go) stay plain functions; what a tool adds is the
// envelope plus the decision about which ports a call needs.
//
// Credential handling is the point of the design: credentials enter through the
// tool input and are handed straight to the flow. They are never logged, never
// written to the evidence store, and never echoed in a Summary or a Data field —
// a result reports which identity came back, not what it cost.

// Capability exposes the three identity tools. It reads the host's registered
// flows for identity_login and the gate-aware HTTPDoer for identity_csrf.
type Capability struct {
	deps  core.Deps
	flows *AuthFlowRegistry
}

// NewCapability builds the identity capability with an empty flow registry. Use
// it when the host has nothing to register yet; identity_login will report the
// kind as unregistered rather than pretend to log in.
func NewCapability(deps core.Deps) (core.Capability, error) {
	return &Capability{deps: deps, flows: NewAuthFlowRegistry()}, nil
}

// NewCapabilityWithFlows builds the capability over a registry the host has
// already assembled. This is the constructor a real wiring uses: the registry
// is the thing that carries the sites.
func NewCapabilityWithFlows(deps core.Deps, flows *AuthFlowRegistry) (core.Capability, error) {
	if flows == nil {
		flows = NewAuthFlowRegistry()
	}
	return &Capability{deps: deps, flows: flows}, nil
}

// Manifest declares the identity tools.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: "identitykit", Version: "0.3.0", APIVersion: "v1",
		Requires: []string{"http"},
		Tools: []core.ToolSpec{
			identityLoginSpec(), identityCSRFSpec(), identityTokenCheckSpec(),
		},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches the identity tools.
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "identity_login":
		return c.login(ctx, call)
	case "identity_csrf":
		return c.csrf(ctx, call)
	case "identity_token_check":
		return c.tokenCheck(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

// --- tool specs ---

func identityLoginSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "identity_login",
		Description: "在目标站点上登录并返回一个可用身份。kind 决定走宿主注册的哪种登录流程（form/json/oauth/cas/bearer）；凭据只从入参读取，不落盘也不明文进日志与证据。返回身份的用户名、作用域主机与标签，供后续 HTTP 工具注入登录态。",
		Risk:        core.RiskHigh,
		RateLimit:   core.RateLimitSpec{PerSecond: 2, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":{"type":"string","description":"站点 URL；会写到凭据的 fields.target，供一个 flow 服务多站点时分派"},
    "kind":{"type":"string","enum":["form","json","oauth","cas","bearer"]},
    "username":{"type":"string"},
    "password":{"type":"string","description":"仅用于本次登录，不返回、不落盘"},
    "token":{"type":"string","description":"bearer/oauth 场景的既有 token"},
    "cookies":{"type":"object","additionalProperties":{"type":"string"}},
    "fields":{"type":"object","additionalProperties":{"type":"string"},"description":"站点专属字段，原样透传给 AuthFlow"}
  },
  "required":["target","kind"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "kind":{"type":"string"},
    "user":{"type":"string"},
    "hosts":{"type":"array","items":{"type":"string"}},
    "label":{"type":"string"},
    "project_id":{"type":"integer"},
    "headers":{"type":"object","additionalProperties":{"type":"array","items":{"type":"string"}}}
  }
}`),
		ExtractTargets: extractURLTarget("target"),
	}
}

func identityCSRFSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "identity_csrf",
		Description: "GET 一个页面并抽取其中的 CSRF token（hidden input 或 meta 标签），返回 token 名、值与来源，可直接填进登录表单。只读单个页面，不提交任何表单。",
		Risk:        core.RiskLow,
		RateLimit:   core.RateLimitSpec{PerSecond: 5, Burst: 3, Concurrency: 2},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "url":{"type":"string"},
    "name":{"type":"string","description":"指定 token 名；缺省按默认识别顺序取第一个"}
  },
  "required":["url"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "found":{"type":"boolean"},
    "name":{"type":"string"},
    "token":{"type":"string"},
    "source":{"type":"string","enum":["hidden_input","meta","none"]},
    "status":{"type":"integer"},
    "evidence_id":{"type":"string"}
  }
}`),
		ExtractTargets: extractURLTarget("url"),
	}
}

func identityTokenCheckSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "identity_token_check",
		Description: "判定一个 token 现在是否需要刷新，给出 needs_refresh 与判断依据（剩余寿命对比安全余量）。expires_at 为空视为「无过期信息」，单独不触发刷新。token 本体不出现在任何返回里。",
		Risk:        core.RiskLow,
		RateLimit:   core.RateLimitSpec{PerSecond: 10, Burst: 5, Concurrency: 2},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "access_token":{"type":"string","description":"只用于判空，不返回"},
    "expires_at":{"type":"string","description":"RFC3339；缺省视为无过期信息"},
    "issued_at":{"type":"string","description":"RFC3339，可选"},
    "skew_ms":{"type":"integer","description":"安全余量，默认 30000"}
  },
  "required":["access_token"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "needs_refresh":{"type":"boolean"},
    "reason":{"type":"string"},
    "remaining_ms":{"type":"integer"},
    "skew_ms":{"type":"integer"},
    "has_expiry":{"type":"boolean"},
    "expires_at":{"type":"string"},
    "age_ms":{"type":"integer"}
  }
}`),
	}
}

// --- handlers ---

// loginInput is kept separate from core.Credentials so the JSON shape stays
// flat (username/password at the top level) while the flow still receives the
// full credential set.
type loginInput struct {
	Target   string            `json:"target"`
	Kind     string            `json:"kind"`
	Username string            `json:"username"`
	Password string            `json:"password"`
	Token    string            `json:"token"`
	Cookies  map[string]string `json:"cookies"`
	Fields   map[string]string `json:"fields"`
}

func (c *Capability) login(ctx context.Context, call core.Call) (core.Result, error) {
	var in loginInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if strings.TrimSpace(in.Target) == "" {
		return core.FailResult(core.InvalidInput("target 必填")), nil
	}
	kind, err := NormalizeAuthKind(in.Kind)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if in.Username == "" && in.Token == "" && len(in.Cookies) == 0 {
		return core.FailResult(core.InvalidInput("username / token / cookies 至少给一项")), nil
	}
	flow, ok := c.flows.Lookup(kind)
	if !ok {
		return core.FailResult(core.ToolMissing(
			"未注册 kind=" + kind + " 的 AuthFlow（已注册：" + kindHint(c.flows) + "）")), nil
	}

	fields := map[string]string{}
	for k, v := range in.Fields {
		fields[k] = v
	}
	// The target rides in Fields so one flow can serve several sites and pick
	// the right site parameters, instead of capkit inventing a routing scheme.
	fields["target"] = strings.TrimSpace(in.Target)

	id, err := flow.Login(ctx, core.Credentials{
		Username: in.Username, Password: in.Password, Token: in.Token,
		Cookies: in.Cookies, Fields: fields,
	})
	if err != nil {
		return core.FailResult(core.UpstreamError("登录失败：" + sanitizeLoginError(err.Error()))), nil
	}
	if id == nil {
		return core.FailResult(core.UpstreamError("登录流程未返回身份")), nil
	}
	scope := id.Scope()
	headers, herr := id.Headers(ctx)
	if herr != nil {
		return core.FailResult(core.UpstreamError("身份头部生成失败：" + herr.Error())), nil
	}

	// The header values are live session material. The envelope reports that an
	// identity exists and what it covers; the raw values stay with the host
	// (red line 7: credentials never in logs or evidence).
	data, _ := core.DataResult(map[string]any{
		"kind": kind, "user": scope.User, "hosts": scope.Hosts,
		"label": scope.Label, "project_id": scope.ProjectID,
		"headers": redactHeaders(headers),
	})
	data.Summary = core.ClampSummary(fmt.Sprintf("已在 %s 登录（kind=%s，身份 %s，作用域 %s）",
		targetLabel(in.Target), kind, identityUserLabel(scope.User), hostsLabel(scope.Hosts)))
	data.Meta.Target = strings.TrimSpace(in.Target)
	data.Next = []core.NextStep{{
		Tool:          "identity_csrf",
		Reason:        "登录后如要发写操作，先取该站点当前 CSRF token",
		Risk:          core.RiskLow,
		Preconditions: []string{"identity.login"},
		Params:        mustJSON(map[string]any{"url": strings.TrimSpace(in.Target)}),
	}}
	return data, nil
}

func (c *Capability) csrf(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		URL  string `json:"url"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if strings.TrimSpace(in.URL) == "" {
		return core.FailResult(core.InvalidInput("url 必填")), nil
	}
	if c.deps.HTTP == nil {
		return core.FailResult(core.ToolMissing("HTTPDoer 未注入（宿主需提供 core.Deps.HTTP）")), nil
	}
	res, err := c.deps.HTTP.Do(ctx, core.Request{
		Method: http.MethodGet, URL: strings.TrimSpace(in.URL), Timeout: 20 * time.Second,
	})
	if err != nil {
		return core.FailResult(core.TargetUnreachable("页面获取失败：" + err.Error())), nil
	}
	name, token, source := ExtractCSRFWithSource(string(res.Body), strings.TrimSpace(in.Name))
	if token == "" {
		source = "none"
	}
	// The page body may hold a session cookie echo or an embedded token, so it is
	// referenced (evidence) rather than echoed; the Summary carries the name and
	// whether a token was found.
	ref := c.recordPage(ctx, in.URL, res)
	out, _ := core.DataResult(map[string]any{
		"found": token != "", "name": name, "token": token,
		"source": source, "status": res.Status, "evidence_id": ref.ID,
	})
	out.Summary = core.ClampSummary(csrfSummary(token != "", name, source, res.Status, strings.TrimSpace(in.URL)))
	out.Meta.Target = strings.TrimSpace(in.URL)
	if ref.ID != "" {
		out.Evidence = []core.EvidenceRef{ref}
	}
	return out, nil
}

func (c *Capability) tokenCheck(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
		IssuedAt    string `json:"issued_at"`
		SkewMS      int    `json:"skew_ms"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if strings.TrimSpace(in.AccessToken) == "" {
		return core.FailResult(core.InvalidInput("access_token 必填")), nil
	}
	snap := core.TokenSnapshot{AccessToken: in.AccessToken}
	if strings.TrimSpace(in.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(in.ExpiresAt))
		if err != nil {
			return core.FailResult(core.InvalidInput("expires_at 不是 RFC3339：" + err.Error())), nil
		}
		snap.ExpiresAt = t
	}
	if strings.TrimSpace(in.IssuedAt) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(in.IssuedAt))
		if err != nil {
			return core.FailResult(core.InvalidInput("issued_at 不是 RFC3339：" + err.Error())), nil
		}
		snap.IssuedAt = t
	}
	skew := time.Duration(in.SkewMS) * time.Millisecond
	if skew <= 0 {
		skew = 30 * time.Second
	}
	now := c.now()
	need := snap.NeedsRefresh(now, skew)

	// The reason is the actionable half: "expires in 4s, below the 30s skew" is
	// decidable, "needs refresh" on its own is not.
	var reason string
	var remainingMS int64
	switch {
	case snap.ExpiresAt.IsZero():
		reason = "expires_at 为空，无过期信息，按不刷新处理"
	case need:
		remainingMS = snap.ExpiresAt.Sub(now).Milliseconds()
		if remainingMS < 0 {
			reason = fmt.Sprintf("已过期 %dms", -remainingMS)
		} else {
			reason = fmt.Sprintf("剩余 %dms 低于安全余量 %dms", remainingMS, skew.Milliseconds())
		}
	default:
		remainingMS = snap.ExpiresAt.Sub(now).Milliseconds()
		reason = fmt.Sprintf("剩余 %dms 高于安全余量 %dms", remainingMS, skew.Milliseconds())
	}
	ageMS := int64(0)
	if !snap.IssuedAt.IsZero() {
		ageMS = now.Sub(snap.IssuedAt).Milliseconds()
	}
	res, _ := core.DataResult(map[string]any{
		"needs_refresh": need, "reason": reason, "remaining_ms": remainingMS,
		"skew_ms": skew.Milliseconds(), "has_expiry": !snap.ExpiresAt.IsZero(),
		"expires_at": formatTime(snap.ExpiresAt), "age_ms": ageMS,
	})
	res.Summary = core.ClampSummary(fmt.Sprintf("token 刷新判定 needs_refresh=%v：%s", need, reason))
	return res, nil
}

// --- helpers ---

func (c *Capability) now() time.Time {
	if c.deps.Clock != nil {
		return c.deps.Clock.Now()
	}
	return time.Now()
}

// extractURLTarget builds an ExtractTargets for a tool whose target is a URL
// field, so the scope gate sees the host before the kit is called.
func extractURLTarget(field string) func(json.RawMessage) ([]core.Target, error) {
	return func(input json.RawMessage) ([]core.Target, error) {
		var in map[string]any
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, err
		}
		raw, _ := in[field].(string)
		if strings.TrimSpace(raw) == "" {
			return nil, fmt.Errorf("%s 必填", field)
		}
		t, err := core.TargetFromURL(0, strings.TrimSpace(raw))
		if err != nil {
			return nil, err
		}
		return []core.Target{t}, nil
	}
}

// recordPage stores the fetched page as evidence. CSRF pages are usually small,
// but the rule is the rule: the body is referenced, never inlined in Data.
func (c *Capability) recordPage(ctx context.Context, url string, res *core.Response) core.EvidenceRef {
	if res == nil {
		return core.EvidenceRef{}
	}
	ref := core.EvidenceRef{
		Kind: "http_exchange", Size: len(res.Body), Preview: core.PreviewRunes(string(res.Body), 200),
	}
	if c.deps.Evidence == nil {
		return ref
	}
	ev := core.Evidence{
		Kind: "http_exchange", Title: "identity_csrf " + url,
		Response: res.Body, CreatedAt: time.Now(),
		Metadata: map[string]string{"tool": "identity_csrf", "url": url, "status": fmt.Sprint(res.Status)},
	}
	if id, err := c.deps.Evidence.Record(ctx, ev); err == nil && id != "" {
		ref.ID = id
	}
	return ref
}

// redactHeaders reports header names and value shapes without leaking session
// material: a cookie header becomes "<3 cookies>", a bearer token "<redacted>".
func redactHeaders(h http.Header) map[string][]string {
	out := map[string][]string{}
	for k, vs := range h {
		switch {
		case len(vs) == 0:
			out[k] = vs
		case strings.EqualFold(k, "Cookie"):
			out[k] = []string{fmt.Sprintf("<%d cookies>", len(strings.Split(vs[0], "; ")))}
		case strings.EqualFold(k, "Authorization"):
			out[k] = []string{"<redacted>"}
		case len(vs[0]) > 64:
			out[k] = []string{fmt.Sprintf("<%d bytes redacted>", len(vs[0]))}
		default:
			out[k] = vs
		}
	}
	return out
}

// sanitizeLoginError keeps a failure message usable for the agent while
// stripping anything that looks like credential material. Login failures are
// notoriously verbose about what was submitted, so the rule is deliberately
// blunt: everything from a credential field name onward is dropped. Losing the
// tail of a message is the right trade — the agent still learns that the login
// was refused, and a host that needs the detail can put it in Error.Detail.
func sanitizeLoginError(msg string) string {
	cleaned := msg
	lower := strings.ToLower(cleaned)
	for _, field := range credentialFieldNames {
		if idx := strings.Index(lower, field); idx >= 0 {
			if idx < len(cleaned) {
				cleaned = cleaned[:idx]
			}
			lower = strings.ToLower(cleaned)
		}
	}
	// Drop the separator the cut left behind so the line reads cleanly.
	cleaned = strings.TrimRight(strings.TrimSpace(cleaned), " :：=，,;；")
	if cleaned == "" {
		cleaned = "登录被拒绝（详情已脱敏）"
	}
	return core.Truncate(cleaned, 160)
}

// credentialFieldNames are the words whose appearance in a login error means
// the message is about to describe submitted material.
var credentialFieldNames = []string{"password", "passwd", "token", "cookie", "secret", "credential"}

func csrfSummary(found bool, name, source string, status int, url string) string {
	if !found {
		return fmt.Sprintf("页面 %s（状态 %d）未发现 CSRF token", targetLabel(url), status)
	}
	return fmt.Sprintf("页面 %s（状态 %d）抽到 CSRF token %s（来源 %s）", targetLabel(url), status, name, source)
}

func targetLabel(raw string) string {
	u := strings.TrimSpace(raw)
	if u == "" {
		return "(未指定)"
	}
	if len([]rune(u)) > 60 {
		return string([]rune(u)[:60])
	}
	return u
}

func identityUserLabel(user string) string {
	if strings.TrimSpace(user) == "" {
		return "(未标注用户)"
	}
	return strings.TrimSpace(user)
}

func hostsLabel(hosts []string) string {
	if len(hosts) == 0 {
		return "未限定"
	}
	return strings.Join(hosts, ",")
}

func kindHint(r *AuthFlowRegistry) string {
	kinds := r.Kinds()
	if len(kinds) == 0 {
		return "无"
	}
	return strings.Join(kinds, ",")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
