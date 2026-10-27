package httpx_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
)

// recordLimiter records the keys it admits (or fails).
type recordLimiter struct {
	keys []string
	err  error
}

func (l *recordLimiter) Acquire(_ context.Context, key string, _ core.RateLimitSpec) (func(), error) {
	l.keys = append(l.keys, key)
	if l.err != nil {
		return nil, l.err
	}
	return func() {}, nil
}

// recordAudit keeps every audit event.
type recordAudit struct{ events []core.AuditEvent }

func (a *recordAudit) Record(_ context.Context, ev core.AuditEvent) {
	a.events = append(a.events, ev)
}

// fixedClock is a deterministic core.Clock.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// roundTripFunc adapts a function to http.RoundTripper so a fetch can fail
// offline without opening a socket.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func ctxWithProject() context.Context {
	return core.WithCallContext(context.Background(), core.CallContext{ProjectID: 1, Actor: "test"})
}

func TestClientRateLimitAcquire(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	lim := &recordLimiter{}
	c := httpx.New(gates.StaticScope("127.0.0.1"), lim, nil)
	if _, err := c.Do(ctxWithProject(), core.Request{URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if len(lim.keys) != 1 {
		t.Fatalf("limiter keys = %v", lim.keys)
	}
}

func TestClientRateLimitError(t *testing.T) {
	c := httpx.New(gates.StaticScope("127.0.0.1"), &recordLimiter{err: core.NewError(core.CodeRateLimited, "busy")}, nil)
	_, err := c.Do(ctxWithProject(), core.Request{URL: "http://127.0.0.1:18080/"})
	if err == nil || !strings.Contains(err.Error(), core.CodeRateLimited) {
		t.Fatalf("err = %v", err)
	}
}

func TestClientNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, nil)
	res, err := c.Do(ctxWithProject(), core.Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 500 || string(res.Body) != "boom" {
		t.Fatalf("res = %+v", res)
	}
}

func TestClientBodyTruncation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer srv.Close()
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, nil)
	c.MaxBodyBytes = 4
	res, err := c.Do(ctxWithProject(), core.Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "0123" {
		t.Fatalf("body = %q", res.Body)
	}
}

func TestClientProxyBranch(t *testing.T) {
	// Point the proxy at the test server itself: the request is answered
	// offline, exercising the proxy transport setup without real egress.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("via-proxy"))
	}))
	defer srv.Close()
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, nil)
	res, err := c.Do(ctxWithProject(), core.Request{URL: srv.URL, Proxy: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || string(res.Body) != "via-proxy" {
		t.Fatalf("res = %+v", res)
	}
}

func TestClientInvalidProxyIsIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, nil)
	res, err := c.Do(ctxWithProject(), core.Request{URL: srv.URL, Proxy: ":// not-a-url"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 {
		t.Fatalf("res = %+v", res)
	}
}

func TestClientInvalidURL(t *testing.T) {
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, nil)
	if _, err := c.Do(ctxWithProject(), core.Request{URL: "://bad"}); err == nil {
		t.Fatal("expected invalid URL error")
	}
}

func TestClientNilScopeDenied(t *testing.T) {
	c := httpx.New(nil, nil, nil)
	_, err := c.Do(ctxWithProject(), core.Request{URL: "http://127.0.0.1:18080/"})
	if err == nil || !strings.Contains(err.Error(), core.CodeScopeDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRedirectLoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer srv.Close()
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, nil)
	_, err := c.Do(ctxWithProject(), core.Request{URL: srv.URL})
	if err == nil {
		t.Fatal("expected too-many-redirects error")
	}
}

func TestClientAuditAndClock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	audit := &recordAudit{}
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, audit)
	c.Clock = fixedClock{t: time.Now()}
	if _, err := c.Do(ctxWithProject(), core.Request{URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if len(audit.events) != 1 || audit.events[0].Status != "ok" {
		t.Fatalf("audit = %+v", audit.events)
	}
}

func TestClientTransportError(t *testing.T) {
	c := httpx.New(gates.StaticScope("127.0.0.1"), nil, nil)
	c.Base = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial refused")
	})}
	_, err := c.Do(ctxWithProject(), core.Request{URL: "http://127.0.0.1:18081/"})
	if err == nil || !strings.Contains(err.Error(), "dial refused") {
		t.Fatalf("err = %v", err)
	}
}

// ───────────────────────────── fetcher ─────────────────────────────

func TestFetcherOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("rules"))
	}))
	defer srv.Close()
	lim := &recordLimiter{}
	audit := &recordAudit{}
	f := httpx.NewFetcher(lim, audit)
	res, err := f.Fetch(context.Background(), core.Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || string(res.Body) != "rules" {
		t.Fatalf("res = %+v", res)
	}
	if len(lim.keys) != 1 || len(audit.events) != 1 {
		t.Fatalf("limiter=%v audit=%v", lim.keys, audit.events)
	}
}

func TestFetcherInvalidURL(t *testing.T) {
	f := httpx.NewFetcher(nil, nil)
	if _, err := f.Fetch(context.Background(), core.Request{URL: "://bad"}); err == nil {
		t.Fatal("expected invalid URL error")
	}
}

func TestFetcherLimiterError(t *testing.T) {
	f := httpx.NewFetcher(&recordLimiter{err: core.NewError(core.CodeRateLimited, "slow down")}, nil)
	_, err := f.Fetch(context.Background(), core.Request{URL: "http://127.0.0.1:18082/"})
	if err == nil || !strings.Contains(err.Error(), core.CodeRateLimited) {
		t.Fatalf("err = %v", err)
	}
}

func TestFetcherTransportError(t *testing.T) {
	audit := &recordAudit{}
	f := httpx.NewFetcher(nil, audit)
	f.Base = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("no route")
	})}
	f.Clock = fixedClock{t: time.Now()}
	_, err := f.Fetch(context.Background(), core.Request{URL: "http://127.0.0.1:18083/"})
	if err == nil || !strings.Contains(err.Error(), "no route") {
		t.Fatalf("err = %v", err)
	}
	if len(audit.events) != 1 || audit.events[0].Status != "error" {
		t.Fatalf("audit = %+v", audit.events)
	}
}

func TestFetcherBodyTruncation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer srv.Close()
	f := httpx.NewFetcher(nil, nil)
	f.MaxBodyBytes = 3
	res, err := f.Fetch(context.Background(), core.Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "012" {
		t.Fatalf("body = %q", res.Body)
	}
}

func TestFetcherProxyBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fetched"))
	}))
	defer srv.Close()
	f := httpx.NewFetcher(nil, nil)
	res, err := f.Fetch(context.Background(), core.Request{URL: srv.URL, Proxy: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || string(res.Body) != "fetched" {
		t.Fatalf("res = %+v", res)
	}
}
