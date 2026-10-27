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
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/sealer"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/settings"
	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/harness/fakenuclei"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
)

func newRuntime(t *testing.T, reg *core.Registry) (*runtime.Runtime, *auditlog.Memory) {
	t.Helper()
	scope := gates.StaticScope("127.0.0.1")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	client := httpx.New(scope, lim, audit)
	seal, err := sealer.New([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		HTTP: client, Settings: settings.New(nil), Sealer: seal,
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	return rt, audit
}

func TestHTTPProbeThroughRuntime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello capkit"))
	}))
	defer srv.Close()

	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, audit := newRuntime(t, reg)
	// http_probe plus the runtime-owned job_status poll tool.
	if len(rt.Tools()) != 2 {
		t.Fatalf("tools = %d", len(rt.Tools()))
	}
	input, _ := json.Marshal(map[string]any{"url": srv.URL})
	res, err := rt.Call(context.Background(), "http_probe", input, core.CallContext{ProjectID: 7, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	var data map[string]any
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data["status"].(float64) != 200 {
		t.Fatalf("status = %v", data["status"])
	}
	if !strings.Contains(data["body"].(string), "hello capkit") {
		t.Fatalf("body = %v", data["body"])
	}
	if len(audit.Events()) < 2 {
		t.Fatalf("audit events = %d", len(audit.Events()))
	}
	phases := map[string]bool{}
	for _, ev := range audit.Events() {
		phases[ev.Phase] = true
	}
	if !phases["start"] || !phases["finish"] {
		t.Fatalf("missing chain audit phases: %+v", phases)
	}
}

// TestMetaRequestsCountsOutboundCalls proves docs §5.5.7: the runtime counts
// every outbound request a tool makes, via the decorated ports, and surfaces the
// total in the envelope without any kit cooperation.
func TestMetaRequestsCountsOutboundCalls(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("counted"))
	}))
	defer srv.Close()

	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, _ := newRuntime(t, reg)
	input, _ := json.Marshal(map[string]any{"url": srv.URL})
	res, err := rt.Call(context.Background(), "http_probe", input, core.CallContext{ProjectID: 1, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta.Requests < 1 {
		t.Fatalf("meta.requests = %d, want >= 1 for a tool that issued an HTTP call", res.Meta.Requests)
	}
}

func TestScopeDenied(t *testing.T) {
	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, _ := newRuntime(t, reg)
	input, _ := json.Marshal(map[string]any{"url": "http://example.com/"})
	_, err := rt.Call(context.Background(), "http_probe", input, core.CallContext{ProjectID: 1})
	if err == nil {
		t.Fatal("expected scope denial")
	}
	if !strings.Contains(err.Error(), core.CodeScopeDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownTool(t *testing.T) {
	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, _ := newRuntime(t, reg)
	_, err := rt.Call(context.Background(), "nope", json.RawMessage(`{}`), core.CallContext{})
	if err == nil || !strings.Contains(err.Error(), core.CodeNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestHighRiskRequiresApproval(t *testing.T) {
	reg := core.NewRegistry()
	if err := all.RegisterNuclei(reg); err != nil {
		t.Fatal(err)
	}
	scope := gates.StaticScope("127.0.0.1")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	_, err := runtime.New(runtime.Config{
		Scope: scope, Limiter: lim, Audit: audit,
		Processes: &fakenuclei.Runner{}, Binaries: &fakenuclei.Binaries{Path: "/fake/nuclei"},
	}, reg)
	if err == nil || !strings.Contains(err.Error(), "approval gate") {
		t.Fatalf("err = %v", err)
	}
}

func TestRegistryRejectsDuplicateCapability(t *testing.T) {
	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	if err := all.RegisterHTTP(reg); err == nil {
		t.Fatal("expected duplicate registration error")
	}
}
