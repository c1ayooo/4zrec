package identity_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/data/identity"
)

// This file covers the identity tools and the AuthFlow registry. The two
// registry cases the ROADMAP names are explicit: an unregistered kind is an
// error, and a registered kind is what identity_login calls.

type stubFlow struct {
	kind   string
	calls  int
	got    core.Credentials
	fail   error
	ident  core.Identity
	labels []string
}

func (f *stubFlow) Kind() string { return f.kind }

func (f *stubFlow) Login(_ context.Context, creds core.Credentials) (core.Identity, error) {
	f.calls++
	f.got = creds
	if f.fail != nil {
		return nil, f.fail
	}
	return f.ident, nil
}

type stubIdentity struct {
	scope   core.IdentityScope
	headers http.Header
	err     error
}

func (s stubIdentity) Headers(context.Context) (http.Header, error) { return s.headers, s.err }
func (s stubIdentity) Refresh(context.Context) error                { return nil }
func (s stubIdentity) Scope() core.IdentityScope                    { return s.scope }

func loginJSON(t *testing.T, v map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func callTool(t *testing.T, cap0 core.Capability, tool string, input json.RawMessage) core.Result {
	t.Helper()
	res, err := cap0.Call(context.Background(), core.Call{Tool: tool, Input: input})
	if err != nil {
		t.Fatalf("%s returned a transport error: %v", tool, err)
	}
	return res
}

// ---- AuthFlowRegistry ----

func TestRegistryRejectsUnsupportedKind(t *testing.T) {
	reg := identity.NewAuthFlowRegistry()
	if err := reg.Register(&stubFlow{kind: "saml"}); err == nil {
		t.Fatal("expected an unsupported kind to be rejected")
	}
	if _, ok := reg.Lookup("saml"); ok {
		t.Fatal("an unsupported kind must not be registered")
	}
	// The lookup error is silent by design: identity_login turns "not found"
	// into a tool_missing result with the registered kinds in the hint.
	if len(reg.Kinds()) != 0 {
		t.Fatalf("kinds = %v", reg.Kinds())
	}
}

func TestRegistryRejectsDuplicateKind(t *testing.T) {
	reg := identity.NewAuthFlowRegistry()
	if err := reg.Register(&stubFlow{kind: "form"}); err != nil {
		t.Fatal(err)
	}
	// A second form site must not silently replace the first: credentials would
	// go to the wrong host.
	if err := reg.Register(&stubFlow{kind: "form"}); err == nil {
		t.Fatal("expected a duplicate kind to be rejected")
	}
}

func TestRegistryNormalizesKind(t *testing.T) {
	reg := identity.NewAuthFlowRegistry()
	if err := reg.RegisterSite("  FORM ", func(context.Context, core.Credentials) (core.Identity, error) {
		return stubIdentity{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Lookup("form"); !ok {
		t.Fatal("kind should be normalized to lowercase before storage")
	}
}

func TestRegisterFormSiteRequiresTransport(t *testing.T) {
	reg := identity.NewAuthFlowRegistry()
	if err := reg.RegisterFormSite(identity.FormFlow{LoginURL: "http://x/login"}); err == nil {
		t.Fatal("a FormFlow without an HTTPDoer must be refused")
	}
	// A host-owned stub satisfies the port; the registry does not care which.
	if err := reg.RegisterFormSite(identity.FormFlow{
		LoginURL: "http://x/login", HTTP: nopDoer{},
	}); err != nil {
		t.Fatalf("RegisterFormSite: %v", err)
	}
	if _, ok := reg.Lookup("form"); !ok {
		t.Fatal("form flow was not registered")
	}
}

// nopDoer stands in for the host's gate-aware HTTPDoer.
type nopDoer struct{}

func (nopDoer) Do(context.Context, core.Request) (*core.Response, error) {
	return &core.Response{Status: 200}, nil
}

// ---- identity_login ----

func newLoginCapability(t *testing.T, flow core.AuthFlow) core.Capability {
	t.Helper()
	reg := identity.NewAuthFlowRegistry()
	if flow != nil {
		if err := reg.Register(flow); err != nil {
			t.Fatal(err)
		}
	}
	c, err := identity.NewCapabilityWithFlows(core.Deps{}, reg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoginCallsRegisteredFlow(t *testing.T) {
	flow := &stubFlow{kind: "form", ident: stubIdentity{
		scope:   core.IdentityScope{User: "alice", Hosts: []string{"127.0.0.1"}, Label: "site-a"},
		headers: http.Header{"Cookie": []string{"sid=abc123"}},
	}}
	cap0 := newLoginCapability(t, flow)

	res := callTool(t, cap0, "identity_login", loginJSON(t, map[string]any{
		"target": "http://127.0.0.1:8080/", "kind": "form",
		"username": "alice", "password": "pw", "fields": map[string]string{"extra": "1"},
	}))
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %s (summary %q)", res.Status, res.Summary)
	}
	if flow.calls != 1 {
		t.Fatalf("flow.Login called %d times", flow.calls)
	}
	// Credentials must reach the flow intact, and the target must be present so a
	// single flow can dispatch across sites.
	if flow.got.Username != "alice" || flow.got.Password != "pw" || flow.got.Fields["extra"] != "1" {
		t.Fatalf("credentials = %+v", flow.got)
	}
	if flow.got.Fields["target"] != "http://127.0.0.1:8080/" {
		t.Fatalf("target not injected into fields: %+v", flow.got.Fields)
	}

	var out struct {
		Kind  string   `json:"kind"`
		User  string   `json:"user"`
		Hosts []string `json:"hosts"`
		Label string   `json:"label"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Kind != "form" || out.User != "alice" || out.Label != "site-a" {
		t.Fatalf("data = %+v", out)
	}
	if len(out.Hosts) != 1 || out.Hosts[0] != "127.0.0.1" {
		t.Fatalf("hosts = %v", out.Hosts)
	}
	// Red line 7: the live cookie must not appear anywhere in the envelope.
	if strings.Contains(res.Summary, "sid=abc123") || strings.Contains(string(res.Data), "sid=abc123") {
		t.Fatalf("session material leaked into the result: %s", string(res.Data))
	}
}

func TestLoginUnregisteredKindIsToolMissing(t *testing.T) {
	cap0 := newLoginCapability(t, nil)
	res := callTool(t, cap0, "identity_login", loginJSON(t, map[string]any{
		"target": "http://127.0.0.1:8080/", "kind": "form", "username": "a",
	}))
	if res.Error == nil || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("error = %+v", res.Error)
	}
	if !strings.Contains(res.Error.Message, "已注册：无") {
		t.Fatalf("message should name the registered kinds: %q", res.Error.Message)
	}
}

func TestLoginRejectsBadKindBeforeTouchingCredentials(t *testing.T) {
	flow := &stubFlow{kind: "form", ident: stubIdentity{}}
	cap0 := newLoginCapability(t, flow)
	res := callTool(t, cap0, "identity_login", loginJSON(t, map[string]any{
		"target": "http://127.0.0.1/", "kind": "saml", "username": "a", "password": "p",
	}))
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("error = %+v", res.Error)
	}
	if flow.calls != 0 {
		t.Fatal("a bad kind must not reach the flow")
	}
}

func TestLoginRequiresSomeCredential(t *testing.T) {
	cap0 := newLoginCapability(t, &stubFlow{kind: "form", ident: stubIdentity{}})
	res := callTool(t, cap0, "identity_login", loginJSON(t, map[string]any{
		"target": "http://127.0.0.1/", "kind": "form",
	}))
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("error = %+v", res.Error)
	}
}

func TestLoginFailureMessageIsSanitized(t *testing.T) {
	cap0 := newLoginCapability(t, &stubFlow{
		kind: "form",
		fail: errString("登录失败：password 提交值 hunter2 被拒"),
	})
	res := callTool(t, cap0, "identity_login", loginJSON(t, map[string]any{
		"target": "http://127.0.0.1/", "kind": "form", "username": "a", "password": "hunter2",
	}))
	if res.Error == nil || res.Error.Code != core.CodeUpstreamError {
		t.Fatalf("error = %+v", res.Error)
	}
	if strings.Contains(res.Error.Message, "hunter2") {
		t.Fatalf("credential survived in the error: %q", res.Error.Message)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// ---- identity_csrf ----

func TestCSRFExtractsHiddenInput(t *testing.T) {
	ports := newPorts(t)
	cap0, err := identity.NewCapabilityWithFlows(ports.deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := callTool(t, cap0, "identity_csrf", loginJSON(t, map[string]any{
		"url": "http://127.0.0.1/login",
	}))
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %s (summary %q)", res.Status, res.Summary)
	}
	var out struct {
		Found  bool   `json:"found"`
		Name   string `json:"name"`
		Token  string `json:"token"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Found || out.Name != "csrf_token" || out.Token != "tok-abc" || out.Source != "hidden_input" {
		t.Fatalf("data = %+v", out)
	}
	if len(ports.evidence.Records()) != 1 {
		t.Fatalf("page should be stored as evidence: %d records", len(ports.evidence.Records()))
	}
}

func TestCSRFNamedMissReportsNotFound(t *testing.T) {
	ports := newPorts(t)
	cap0, err := identity.NewCapabilityWithFlows(ports.deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := callTool(t, cap0, "identity_csrf", loginJSON(t, map[string]any{
		"url": "http://127.0.0.1/login", "name": "not_there",
	}))
	var out struct {
		Found bool `json:"found"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Found {
		t.Fatal("a named miss must report found=false, not the first token on the page")
	}
	if !strings.Contains(res.Summary, "未发现 CSRF token") {
		t.Fatalf("summary = %q", res.Summary)
	}
}

func TestCSRFNeedsHTTPDoer(t *testing.T) {
	c, err := identity.NewCapabilityWithFlows(core.Deps{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := callTool(t, c, "identity_csrf", loginJSON(t, map[string]any{"url": "http://127.0.0.1/"}))
	if res.Error == nil || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("error = %+v", res.Error)
	}
}

// ---- identity_token_check ----

func TestTokenCheckNeedsRefreshInsideSkew(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	c, err := identity.NewCapabilityWithFlows(core.Deps{Clock: clock}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := callTool(t, c, "identity_token_check", loginJSON(t, map[string]any{
		"access_token": "tok",
		"expires_at":   now.Add(10 * time.Second).Format(time.RFC3339),
		"skew_ms":      30000,
	}))
	var out struct {
		NeedsRefresh bool   `json:"needs_refresh"`
		Reason       string `json:"reason"`
		RemainingMS  int64  `json:"remaining_ms"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if !out.NeedsRefresh {
		t.Fatalf("10s remaining under a 30s skew must need refresh: %s", res.Summary)
	}
	if !strings.Contains(out.Reason, "低于安全余量") {
		t.Fatalf("reason must say why: %q", out.Reason)
	}
	if out.RemainingMS != 10_000 {
		t.Fatalf("remaining_ms = %d", out.RemainingMS)
	}
}

func TestTokenCheckHealthyTokenNeedsNoRefresh(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	c, err := identity.NewCapabilityWithFlows(core.Deps{Clock: clock}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := callTool(t, c, "identity_token_check", loginJSON(t, map[string]any{
		"access_token": "tok",
		"expires_at":   now.Add(time.Hour).Format(time.RFC3339),
		"skew_ms":      30000,
	}))
	var out struct {
		NeedsRefresh bool `json:"needs_refresh"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out.NeedsRefresh {
		t.Fatalf("an hour of life left must not refresh: %s", res.Summary)
	}
}

func TestTokenCheckNoExpiryNeverRefreshes(t *testing.T) {
	c, err := identity.NewCapabilityWithFlows(core.Deps{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := callTool(t, c, "identity_token_check", loginJSON(t, map[string]any{
		"access_token": "tok",
	}))
	var out struct {
		NeedsRefresh bool   `json:"needs_refresh"`
		HasExpiry    bool   `json:"has_expiry"`
		Reason       string `json:"reason"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out.NeedsRefresh || out.HasExpiry {
		t.Fatalf("no expiry information must not trigger a refresh: %+v", out)
	}
	if !strings.Contains(out.Reason, "无过期信息") {
		t.Fatalf("reason = %q", out.Reason)
	}
}

func TestTokenCheckExpiredReportsElapsed(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	c, err := identity.NewCapabilityWithFlows(core.Deps{Clock: clock}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := callTool(t, c, "identity_token_check", loginJSON(t, map[string]any{
		"access_token": "tok",
		"expires_at":   now.Add(-90 * time.Second).Format(time.RFC3339),
	}))
	var out struct {
		NeedsRefresh bool   `json:"needs_refresh"`
		Reason       string `json:"reason"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if !out.NeedsRefresh || !strings.Contains(out.Reason, "已过期") {
		t.Fatalf("data = %+v", out)
	}
}

func TestTokenCheckRejectsBadTimestamp(t *testing.T) {
	c, err := identity.NewCapabilityWithFlows(core.Deps{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := callTool(t, c, "identity_token_check", loginJSON(t, map[string]any{
		"access_token": "tok", "expires_at": "yesterday",
	}))
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("error = %+v", res.Error)
	}
}

func TestUnknownToolIsNotFound(t *testing.T) {
	c, err := identity.NewCapability(core.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	res := callTool(t, c, "identity_login2", json.RawMessage(`{}`))
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("error = %+v", res.Error)
	}
}

// ---- test plumbing ----

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

type testPorts struct {
	deps     core.Deps
	http     *stubHTTP
	evidence *stubEvidence
}

func newPorts(t *testing.T) testPorts {
	t.Helper()
	h := &stubHTTP{body: loginPage}
	ev := &stubEvidence{}
	return testPorts{
		http: h, evidence: ev,
		deps: core.Deps{HTTP: h, Evidence: ev, Clock: &fakeClock{now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}},
	}
}

// loginPage is a minimal CSRF-bearing login form: hidden input first (so the
// default extractor finds it), meta tag second (so source reporting differs).
const loginPage = `<html><body><form method="post">
<input type="hidden" name="csrf_token" value="tok-abc">
<input name="username" value="">
</form><meta name="csrf-token" content="meta-tok"></body></html>`

type stubHTTP struct {
	body string
	err  error
	last core.Request
}

func (s *stubHTTP) Do(_ context.Context, req core.Request) (*core.Response, error) {
	s.last = req
	if s.err != nil {
		return nil, s.err
	}
	return &core.Response{Status: 200, Body: []byte(s.body)}, nil
}

func (s *stubHTTP) Fetch(_ context.Context, req core.Request) (*core.Response, error) {
	return s.Do(context.Background(), req)
}

type stubEvidence struct{ records []core.Evidence }

func (s *stubEvidence) Record(_ context.Context, ev core.Evidence) (string, error) {
	s.records = append(s.records, ev)
	return "ev-1", nil
}

func (s *stubEvidence) Records() []core.Evidence { return s.records }
