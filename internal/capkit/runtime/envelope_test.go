package runtime_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/auditlog"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/settings"
	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
)

// bigBody writes a response far past the 8KB Data ceiling.
func bigBody(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`{"padding":"`)
	for sb.Len() < 32<<10 {
		sb.WriteString("capkit-envelope-clamp-")
	}
	sb.WriteString(`"}`)
	return sb.String()
}

func TestEnvelopeInvariants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello capkit"))
	}))
	defer srv.Close()

	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, audit := newRuntime(t, reg)
	input, _ := json.Marshal(map[string]any{"url": srv.URL})
	res, err := rt.Call(context.Background(), "http_probe", input, core.CallContext{ProjectID: 7, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	// Status is a valid six-state value and consistent with OK.
	if !res.Status.Valid() {
		t.Fatalf("status = %q", res.Status)
	}
	if res.Status != core.StatusSuccess || !res.OK {
		t.Fatalf("status/ok = %q/%v", res.Status, res.OK)
	}
	// Summary is non-empty and bounded.
	if res.Summary == "" || len([]rune(res.Summary)) > core.MaxSummaryRunes {
		t.Fatalf("summary = %q", res.Summary)
	}
	// Meta is fully populated.
	if res.Meta.Tool != "http_probe" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
	if res.Meta.DurationMS <= 0 {
		t.Fatalf("meta.duration_ms = %d", res.Meta.DurationMS)
	}
	if len(res.Meta.GateTrace) == 0 {
		t.Fatal("gate trace is empty; agent cannot see why a call was slow")
	}
	// Data stays within the ceiling.
	if len(res.Data) > core.MaxDataBytes {
		t.Fatalf("data = %d bytes", len(res.Data))
	}
	if len(audit.Events()) < 2 {
		t.Fatalf("audit events = %d", len(audit.Events()))
	}
}

func TestDataCeilingIsEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(bigBody(t)))
	}))
	defer srv.Close()

	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, _ := newRuntime(t, reg)
	input, _ := json.Marshal(map[string]any{"url": srv.URL})
	res, err := rt.Call(context.Background(), "http_probe", input, core.CallContext{ProjectID: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Fatal("expected truncated=true on oversized data")
	}
	if len(res.Data) > core.MaxDataBytes {
		t.Fatalf("clamped data = %d bytes", len(res.Data))
	}
	var data map[string]any
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatalf("clamped data is not valid JSON: %v", err)
	}
	if data["_truncated"] != true {
		t.Fatalf("data = %v", data)
	}
	// §5.5.4: the real size of the dropped payload is reported in Page.Total.
	if res.Page == nil || res.Page.Total <= 0 {
		t.Fatalf("page total not set: %+v", res.Page)
	}
	if orig, _ := data["original_bytes"].(float64); int(orig) != res.Page.Total {
		t.Fatalf("page.total %d != original_bytes %v", res.Page.Total, orig)
	}
}

func TestBlockedResultMapsStatus(t *testing.T) {
	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, _ := newRuntime(t, reg)
	input, _ := json.Marshal(map[string]any{"url": "http://example.com/"})
	res, err := rt.Call(context.Background(), "http_probe", input, core.CallContext{ProjectID: 1})
	if err == nil {
		t.Fatal("expected scope denial")
	}
	if res.Status != core.StatusBlocked {
		t.Fatalf("status = %q, want blocked", res.Status)
	}
	if res.OK {
		t.Fatal("blocked result must not be ok")
	}
	var e *core.Error
	if res.Error == nil || res.Error.Code != core.CodeScopeDenied {
		t.Fatalf("error = %+v", res.Error)
	}
	// scope_denied is never retryable: the agent must not loop on it.
	_ = e
	if res.Error.Retryable {
		t.Fatal("scope_denied must not be retryable")
	}
	if res.Summary == "" {
		t.Fatal("blocked result needs a summary the agent can read")
	}
}

func TestUnknownToolStillReturnsEnvelope(t *testing.T) {
	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, _ := newRuntime(t, reg)
	res, err := rt.Call(context.Background(), "nope", json.RawMessage(`{}`), core.CallContext{})
	if err == nil {
		t.Fatal("expected not found")
	}
	if res.Status != core.StatusFailed {
		t.Fatalf("status = %q", res.Status)
	}
	if res.Meta.Tool != "nope" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
	if res.Summary == "" {
		t.Fatal("unknown tool needs a summary")
	}
}

func TestIdempotentRetryReturnsCachedResult(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("one shot"))
	}))
	defer srv.Close()

	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	scope := gates.StaticScope("127.0.0.1")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		HTTP: httpx.New(scope, lim, audit), Settings: settings.New(nil),
		IdempotencyWindow: 5 * 60 * 1e9, // 5 minutes in ns
	}, reg)
	if err != nil {
		t.Fatal(err)
	}

	input, _ := json.Marshal(map[string]any{"url": srv.URL})
	cc := core.CallContext{ProjectID: 3, Actor: "retry-bot", TaskID: "t1"}
	first, err := rt.Call(context.Background(), "http_probe", input, cc)
	if err != nil {
		t.Fatal(err)
	}
	if first.Meta.Cached {
		t.Fatal("first call must not be cached")
	}
	// A timeout-retry with the same project/actor/task/input reuses the result.
	second, err := rt.Call(context.Background(), "http_probe", input, cc)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Meta.Cached {
		t.Fatal("retry within window must reuse the result")
	}
	if hits != 1 {
		t.Fatalf("target was hit %d times; retry must not re-probe", hits)
	}
}

func TestDifferentInputIsNotCached(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hit"))
	}))
	defer srv.Close()

	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	scope := gates.StaticScope("127.0.0.1")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		HTTP: httpx.New(scope, lim, audit), Settings: settings.New(nil),
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	cc := core.CallContext{ProjectID: 3, Actor: "retry-bot", TaskID: "t1"}
	first, _ := json.Marshal(map[string]any{"url": srv.URL + "/a"})
	second, _ := json.Marshal(map[string]any{"url": srv.URL + "/b"})
	r1, err := rt.Call(context.Background(), "http_probe", first, cc)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := rt.Call(context.Background(), "http_probe", second, cc)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Meta.Cached || r2.Meta.Cached {
		t.Fatal("different inputs must not share a cache entry")
	}
}
