// Package identitykit implements the target-side identity contract (docs
// §5.2): a cookie jar, CSRF token extraction, bearer-token refresh decisions,
// and form/JSON login flows. A host implements a site-specific flow with these
// building blocks; the resulting Identity feeds the gate-aware HTTPDoer.
package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// ---- CSRF extraction ----

var csrfInputRE = regexp.MustCompile(`(?is)<input[^>]*name=["']([^"']*(?:csrf|token|authenticity|xsrf)[^"']*)["'][^>]*value=["']([^"']*)["']`)
var csrfInputRE2 = regexp.MustCompile(`(?is)<input[^>]*value=["']([^"']*)["'][^>]*name=["']([^"']*(?:csrf|token|authenticity|xsrf)[^"']*)["']`)
var metaCSRFRE = regexp.MustCompile(`(?is)<meta[^>]*name=["']([^"']*(?:csrf|token)[^"']*)["'][^>]*content=["']([^"']*)["']`)

// CSRFNames are the token names the extractor recognizes by default.
var CSRFNames = []string{"csrf_token", "csrfmiddlewaretoken", "_csrf", "authenticity_token", "xsrf-token", "xsrf_token", "_token", "__RequestVerificationToken"}

// ExtractCSRF pulls a CSRF token out of HTML (hidden inputs or meta tags),
// preferring the well-known names. Returns "" when none is found.
func ExtractCSRF(html string) (name, token string) {
	for _, m := range csrfInputRE.FindAllStringSubmatch(html, -1) {
		if len(m) == 3 && m[2] != "" {
			return m[1], m[2]
		}
	}
	for _, m := range csrfInputRE2.FindAllStringSubmatch(html, -1) {
		if len(m) == 3 && m[1] != "" {
			return m[2], m[1]
		}
	}
	for _, m := range metaCSRFRE.FindAllStringSubmatch(html, -1) {
		if len(m) == 3 && m[2] != "" {
			return m[1], m[2]
		}
	}
	return "", ""
}

// ExtractCSRFNamed pulls a specific token name from HTML.
func ExtractCSRFNamed(html, name string) string {
	if name == "" {
		_, t := ExtractCSRF(html)
		return t
	}
	re := regexp.MustCompile(`(?is)<input[^>]*name=["']` + regexp.QuoteMeta(name) + `["'][^>]*value=["']([^"']*)["']`)
	if m := re.FindStringSubmatch(html); len(m) == 2 {
		return m[1]
	}
	return ""
}

// ExtractCSRFWithSource is ExtractCSRF/ExtractCSRFNamed plus where the token
// came from ("hidden_input" or "meta"). A caller that fills a login form needs
// the distinction, because the two are submitted differently: a hidden input
// goes back as a form field, a meta tag as a request header. Returns an empty
// name and token when nothing matched.
func ExtractCSRFWithSource(html, want string) (name, token, source string) {
	if strings.TrimSpace(want) != "" {
		re := regexp.MustCompile(`(?is)<input[^>]*name=["']` + regexp.QuoteMeta(want) + `["'][^>]*value=["']([^"']*)["']`)
		if m := re.FindStringSubmatch(html); len(m) == 2 && m[1] != "" {
			return want, m[1], "hidden_input"
		}
		re2 := regexp.MustCompile(`(?is)<input[^>]*value=["']([^"']*)["'][^>]*name=["']` + regexp.QuoteMeta(want) + `["']`)
		if m := re2.FindStringSubmatch(html); len(m) == 2 && m[1] != "" {
			return want, m[1], "hidden_input"
		}
		re3 := regexp.MustCompile(`(?is)<meta[^>]*name=["']` + regexp.QuoteMeta(want) + `["'][^>]*content=["']([^"']*)["']`)
		if m := re3.FindStringSubmatch(html); len(m) == 2 && m[1] != "" {
			return want, m[1], "meta"
		}
		return "", "", ""
	}
	for _, m := range csrfInputRE.FindAllStringSubmatch(html, -1) {
		if len(m) == 3 && m[2] != "" {
			return m[1], m[2], "hidden_input"
		}
	}
	for _, m := range csrfInputRE2.FindAllStringSubmatch(html, -1) {
		if len(m) == 3 && m[1] != "" {
			return m[2], m[1], "hidden_input"
		}
	}
	for _, m := range metaCSRFRE.FindAllStringSubmatch(html, -1) {
		if len(m) == 3 && m[2] != "" {
			return m[1], m[2], "meta"
		}
	}
	return "", "", ""
}

// ---- Cookie-jar identity ----

// JarIdentity is an Identity backed by an http cookie jar plus extra static
// headers (e.g. Authorization). Headers() returns the jar's cookies for the
// requested URL and merges the extra headers.
type JarIdentity struct {
	mu      sync.Mutex
	jar     http.CookieJar
	headers http.Header
	scope   core.IdentityScope
	target  string // base URL the jar was primed against
}

// NewJarIdentity builds a cookie-jar identity for one target origin.
func NewJarIdentity(target string, headers http.Header, scope core.IdentityScope) (*JarIdentity, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("target 无效: %q", target)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for k, vs := range headers {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	return &JarIdentity{jar: jar, headers: h, scope: scope, target: target}, nil
}

// SetCookies stores cookies (e.g. parsed from a Set-Cookie or a credential).
func (j *JarIdentity) SetCookies(cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if u, err := url.Parse(j.target); err == nil {
		j.jar.SetCookies(u, cookies)
	}
}

// AddCookie stores one cookie by name/value.
func (j *JarIdentity) AddCookie(name, value string) {
	j.SetCookies([]*http.Cookie{{Name: name, Value: value}})
}

// Headers returns the jar cookies plus extra headers.
func (j *JarIdentity) Headers(context.Context) (http.Header, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := j.headers.Clone()
	if out == nil {
		out = http.Header{}
	}
	if u, err := url.Parse(j.target); err == nil {
		if jarCookie := j.jar.Cookies(u); len(jarCookie) > 0 {
			var parts []string
			for _, c := range jarCookie {
				parts = append(parts, c.Name+"="+c.Value)
			}
			out.Set("Cookie", strings.Join(parts, "; "))
		}
	}
	return out, nil
}

// Refresh is a no-op for a static jar (cookies do not expire client-side).
func (j *JarIdentity) Refresh(context.Context) error { return nil }

// Scope returns the identity's authorized scope.
func (j *JarIdentity) Scope() core.IdentityScope { return j.scope }

// ---- Bearer-token identity ----

// TokenIdentity is an Identity backed by a bearer token that can be refreshed.
type TokenIdentity struct {
	mu       sync.Mutex
	token    string
	kind     string // Bearer | X-Auth-Token | ...
	snapshot core.TokenSnapshot
	refresh  func(ctx context.Context, current string) (core.TokenSnapshot, error)
	scope    core.IdentityScope
	skew     time.Duration
}

// NewTokenIdentity builds a token identity. refresh may be nil for a static
// token; when set, Headers() refreshes proactively once the token nears expiry.
func NewTokenIdentity(kind, token string, snap core.TokenSnapshot, refresh func(ctx context.Context, current string) (core.TokenSnapshot, error), scope core.IdentityScope) *TokenIdentity {
	if kind == "" {
		kind = "Bearer"
	}
	if snap.AccessToken == "" {
		snap.AccessToken = token
	}
	return &TokenIdentity{token: token, kind: kind, snapshot: snap, refresh: refresh, scope: scope, skew: 30 * time.Second}
}

// Headers refreshes if needed, then returns the auth header. The default kind
// is the standard "Authorization: Bearer <token>"; any other value (e.g.
// X-Auth-Token) is used as the header name directly.
func (t *TokenIdentity) Headers(ctx context.Context) (http.Header, error) {
	t.mu.Lock()
	need := t.snapshot.NeedsRefresh(time.Now(), t.skew)
	kind, token := t.kind, t.token
	t.mu.Unlock()
	if need && t.refresh != nil {
		if err := t.Refresh(ctx); err != nil {
			return nil, err
		}
		t.mu.Lock()
		kind, token = t.kind, t.token
		t.mu.Unlock()
	}
	h := http.Header{}
	if strings.EqualFold(kind, "Bearer") {
		h.Add("Authorization", "Bearer "+token)
	} else {
		h.Add(kind, token)
	}
	return h, nil
}

// Refresh forces a token refresh and updates the snapshot.
func (t *TokenIdentity) Refresh(ctx context.Context) error {
	t.mu.Lock()
	refresh := t.refresh
	current := t.token
	t.mu.Unlock()
	if refresh == nil {
		return nil
	}
	snap, err := refresh(ctx, current)
	if err != nil {
		return err
	}
	if snap.AccessToken == "" {
		return fmt.Errorf("刷新未返回新 token")
	}
	t.mu.Lock()
	t.token = snap.AccessToken
	t.snapshot = snap
	t.mu.Unlock()
	return nil
}

// Scope returns the identity's authorized scope.
func (t *TokenIdentity) Scope() core.IdentityScope { return t.scope }

// Token returns the current token value.
func (t *TokenIdentity) Token() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.token
}

// ---- Login flows ----

// FormFlow is a cookie-jar form login (POST username/password + optional CSRF
// fetched from the login page). It implements core.AuthFlow.
type FormFlow struct {
	LoginURL     string
	Method       string // default POST
	UserField    string // default "username"
	PassField    string // default "password"
	ExtraFields  map[string]string
	CSRFRequired bool
	SuccessCheck func(status int, body string) bool
	HTTP         core.HTTPDoer
	Scope        core.IdentityScope
	Target       string
}

func (f *FormFlow) Kind() string { return "form" }

// Login performs the form login and returns a cookie-jar identity.
func (f *FormFlow) Login(ctx context.Context, creds core.Credentials) (core.Identity, error) {
	if f.HTTP == nil {
		return nil, fmt.Errorf("FormFlow 需要 HTTPDoer")
	}
	id, err := NewJarIdentity(f.targetOrLogin(), nil, f.Scope)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set(core.FirstNonEmpty(f.UserField, "username"), creds.Username)
	form.Set(core.FirstNonEmpty(f.PassField, "password"), creds.Password)
	for k, v := range f.ExtraFields {
		form.Set(k, v)
	}
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

	if f.CSRFRequired {
		page, err := f.HTTP.Do(ctx, core.Request{Method: "GET", URL: f.LoginURL, Timeout: 20 * time.Second})
		if err != nil {
			return nil, fmt.Errorf("获取登录页失败: %w", err)
		}
		id.SetCookies(cookiesFromHeaders(page.Headers))
		cname, ctoken := ExtractCSRF(string(page.Body))
		if ctoken == "" {
			// fall back to the cookie form (XSRF-TOKEN)
			if h, _ := id.Headers(ctx); h != nil {
				if ck := h.Get("Cookie"); strings.Contains(strings.ToLower(ck), "xsrf") {
					cname = "X-XSRF-TOKEN"
				}
			}
		}
		if ctoken != "" {
			if cname == "" {
				cname = "csrf_token"
			}
			form.Set(cname, ctoken)
		}
	}

	method := strings.ToUpper(core.FirstNonEmpty(f.Method, "POST"))
	// The login page may have set a session cookie that the CSRF token is bound
	// to (Django, Laravel, Rails, PHP all do this). Sending the form without that
	// cookie is what a browser would never do, and the server rejects it as
	// "bad csrf" — so the jar's cookies go out with the POST, not just the fields.
	if h, herr := id.Headers(ctx); herr == nil && h.Get("Cookie") != "" {
		headers["Cookie"] = h.Get("Cookie")
	}
	res, err := f.HTTP.Do(ctx, core.Request{
		Method: method, URL: f.LoginURL, Headers: headers,
		Body: []byte(form.Encode()), Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("登录请求失败: %w", err)
	}
	id.SetCookies(cookiesFromHeaders(res.Headers))
	if f.SuccessCheck != nil && !f.SuccessCheck(res.Status, string(res.Body)) {
		return nil, fmt.Errorf("登录判定失败（status %d）", res.Status)
	}
	if f.SuccessCheck == nil && res.Status >= 400 {
		return nil, fmt.Errorf("登录失败（status %d）", res.Status)
	}
	return id, nil
}

func (f *FormFlow) targetOrLogin() string {
	if f.Target != "" {
		return f.Target
	}
	return f.LoginURL
}

func cookiesFromHeaders(headers map[string][]string) []*http.Cookie {
	var out []*http.Cookie
	resp := &http.Response{Header: http.Header{}}
	for k, vs := range headers {
		if !strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		for _, v := range vs {
			resp.Header.Add("Set-Cookie", v)
		}
	}
	out = append(out, resp.Cookies()...)
	return out
}
