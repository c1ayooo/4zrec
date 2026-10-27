package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/data/identity"
)

func TestExtractCSRF(t *testing.T) {
	html := `<html><body><form><input type="hidden" name="csrfmiddlewaretoken" value="tok123"></form></body></html>`
	name, token := identity.ExtractCSRF(html)
	if name != "csrfmiddlewaretoken" || token != "tok123" {
		t.Fatalf("got %q/%q", name, token)
	}
	// value-before-name ordering
	html2 := `<input value="abc" name="_csrf">`
	_, tok2 := identity.ExtractCSRF(html2)
	if tok2 != "abc" {
		t.Fatalf("reverse-order token = %q", tok2)
	}
	// none present
	if _, tok := identity.ExtractCSRF("<html>no token</html>"); tok != "" {
		t.Fatalf("unexpected token %q", tok)
	}
	if got := identity.ExtractCSRFNamed(html, "csrfmiddlewaretoken"); got != "tok123" {
		t.Fatalf("named = %q", got)
	}
	if got := identity.ExtractCSRFNamed(html, "missing"); got != "" {
		t.Fatalf("named missing = %q", got)
	}
}

func TestJarIdentityHeaders(t *testing.T) {
	id, err := identity.NewJarIdentity("https://app.test/", http.Header{"X-Api-Key": []string{"k"}}, core.IdentityScope{Hosts: []string{"app.test"}})
	if err != nil {
		t.Fatal(err)
	}
	id.AddCookie("session", "abc")
	h, err := id.Headers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Api-Key") != "k" {
		t.Fatalf("extra header lost: %v", h)
	}
	if !strings.Contains(h.Get("Cookie"), "session=abc") {
		t.Fatalf("cookie header = %q", h.Get("Cookie"))
	}
	if id.Scope().Hosts[0] != "app.test" {
		t.Fatal("scope mismatch")
	}
	if err := id.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewJarIdentity("not a url", nil, core.IdentityScope{}); err == nil {
		t.Fatal("expected invalid target error")
	}
}

func TestTokenIdentityRefresh(t *testing.T) {
	refreshCalls := 0
	id := identity.NewTokenIdentity("Bearer", "old", core.TokenSnapshot{
		AccessToken: "old",
		ExpiresAt:   time.Now().Add(-time.Minute), // already expired
	}, func(context.Context, string) (core.TokenSnapshot, error) {
		refreshCalls++
		return core.TokenSnapshot{AccessToken: "new", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}, core.IdentityScope{})

	h, err := id.Headers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if refreshCalls != 1 {
		t.Fatalf("refresh calls = %d", refreshCalls)
	}
	if h.Get("Authorization") != "Bearer new" {
		t.Fatalf("auth = %q", h.Get("Authorization"))
	}
	// second call must not refresh again (fresh token)
	if _, err := id.Headers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if refreshCalls != 1 {
		t.Fatalf("unexpected extra refresh: %d", refreshCalls)
	}
	if id.Token() != "new" {
		t.Fatalf("token = %q", id.Token())
	}
}

func TestTokenIdentityRefreshError(t *testing.T) {
	id := identity.NewTokenIdentity("Bearer", "t", core.TokenSnapshot{ExpiresAt: time.Now().Add(-time.Hour)},
		func(context.Context, string) (core.TokenSnapshot, error) {
			return core.TokenSnapshot{}, context.DeadlineExceeded
		},
		core.IdentityScope{})
	if _, err := id.Headers(context.Background()); err == nil {
		t.Fatal("expected refresh error")
	}
	// A static token (no refresh fn) never errors.
	static := identity.NewTokenIdentity("Bearer", "s", core.TokenSnapshot{}, nil, core.IdentityScope{})
	if _, err := static.Headers(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTokenSnapshotNeedsRefresh(t *testing.T) {
	now := time.Now()
	if (core.TokenSnapshot{}).NeedsRefresh(now, time.Minute) {
		t.Fatal("zero expiry must not trigger refresh")
	}
	if !(core.TokenSnapshot{ExpiresAt: now.Add(10 * time.Second)}).NeedsRefresh(now, time.Minute) {
		t.Fatal("token expiring within skew must refresh")
	}
	if (core.TokenSnapshot{ExpiresAt: now.Add(time.Hour)}).NeedsRefresh(now, time.Minute) {
		t.Fatal("fresh token must not refresh")
	}
}

func TestFormFlowLogin(t *testing.T) {
	var gotBody string
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			http.SetCookie(w, &http.Cookie{Name: "pre", Value: "1"})
			_, _ = w.Write([]byte(`<input name="csrf_token" value="tok">`))
			return
		}
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		gotCookie = r.Header.Get("Cookie")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess1"})
		_, _ = w.Write([]byte("welcome"))
	}))
	defer srv.Close()

	doer := httpDoer{}
	flow := &identity.FormFlow{
		LoginURL: srv.URL + "/login", CSRFRequired: true,
		HTTP: doer, Target: srv.URL,
		SuccessCheck: func(status int, body string) bool { return strings.Contains(body, "welcome") },
	}
	id, err := flow.Login(context.Background(), core.Credentials{Username: "admin", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if flow.Kind() != "form" {
		t.Fatalf("kind = %q", flow.Kind())
	}
	if !strings.Contains(gotBody, "csrf_token=tok") {
		t.Fatalf("csrf token not submitted: %q", gotBody)
	}
	// A CSRF token is normally bound to the session cookie the login page just
	// set (PHP, Django, Rails all do this), so the POST must carry the jar's
	// cookies. Without them the server answers "bad csrf" and the login can never
	// succeed — which is exactly the bug this assertion pins.
	if !strings.Contains(gotCookie, "pre=1") {
		t.Fatalf("the login POST did not carry the page's cookie: %q", gotCookie)
	}
	h, _ := id.Headers(context.Background())
	if !strings.Contains(h.Get("Cookie"), "session=sess1") {
		t.Fatalf("login cookie not captured: %q", h.Get("Cookie"))
	}
}

func TestFormFlowMissingHTTPDoer(t *testing.T) {
	flow := &identity.FormFlow{LoginURL: "http://x/login"}
	if _, err := flow.Login(context.Background(), core.Credentials{}); err == nil {
		t.Fatal("expected HTTPDoer requirement error")
	}
}

// httpDoer adapts net/http to core.HTTPDoer for tests.
type httpDoer struct{}

func (httpDoer) Do(ctx context.Context, req core.Request) (*core.Response, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, strings.NewReader(string(req.Body)))
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	return &core.Response{Status: resp.StatusCode, Headers: resp.Header, Body: body}, nil
}
