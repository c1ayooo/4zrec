package verify_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/auditlog"
	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/verify"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
)

type fakeFP struct{ products []string }

func (f *fakeFP) Fingerprint(context.Context, core.Target) ([]core.Fingerprint, error) {
	out := make([]core.Fingerprint, 0, len(f.products))
	for _, p := range f.products {
		out = append(out, core.Fingerprint{Product: p, Source: "fake"})
	}
	return out, nil
}

type fakeCatalog struct{ refs map[string]core.TemplateRef }

func (f *fakeCatalog) Search(_ context.Context, q core.TemplateQuery) ([]core.TemplateRef, error) {
	var out []core.TemplateRef
	for _, ref := range f.refs {
		if len(q.Products) == 0 {
			out = append(out, ref)
			continue
		}
		for _, p := range q.Products {
			if strings.Contains(strings.ToLower(ref.Meta["products"]), strings.ToLower(p)) {
				out = append(out, ref)
				break
			}
		}
	}
	return out, nil
}

func (f *fakeCatalog) Get(_ context.Context, id string) (core.TemplateRef, bool, error) {
	ref, ok := f.refs[id]
	return ref, ok, nil
}

type fakeEngine struct {
	kind     string
	calls    int
	findings []core.Finding
}

func (f *fakeEngine) Kind() string { return f.kind }
func (f *fakeEngine) Execute(_ context.Context, refs []core.TemplateRef, _ core.Target, _ map[string]any) (core.Result, error) {
	f.calls++
	res := core.TextResult("executed " + strings.Join(ids(refs), ","))
	res.Findings = f.findings
	return res, nil
}

func ids(refs []core.TemplateRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.ID)
	}
	return out
}

func newRuntime(t *testing.T, engine *fakeEngine) *runtime.Runtime {
	t.Helper()
	reg := core.NewRegistry()
	if err := all.RegisterVerify(reg); err != nil {
		t.Fatal(err)
	}
	scope := gates.StaticScope("127.0.0.1")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	catalog := &fakeCatalog{refs: map[string]core.TemplateRef{
		"t1": {ID: "t1", Name: "T1", Kind: "http", Engine: "http", Meta: map[string]string{"products": "nginx"}},
	}}
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		Fingerprints: &fakeFP{products: []string{"nginx"}}, Templates: catalog,
		TemplateEngines: map[string]core.TemplateEngine{"http": engine},
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func TestVerifyPlan(t *testing.T) {
	rt := newRuntime(t, &fakeEngine{kind: "http"})
	input, _ := json.Marshal(map[string]any{"target": "http://127.0.0.1"})
	res, err := rt.Call(context.Background(), "verify_plan", input, core.CallContext{ProjectID: 1, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	var data struct {
		Fingerprints []core.Fingerprint `json:"fingerprints"`
		Candidates   []struct {
			ID string `json:"id"`
		} `json:"candidates"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Fingerprints) != 1 || data.Fingerprints[0].Product != "nginx" {
		t.Fatalf("fingerprints = %+v", data.Fingerprints)
	}
	if data.Count != 1 || data.Candidates[0].ID != "t1" {
		t.Fatalf("candidates = %+v", data.Candidates)
	}
}

func TestVerifyExecute(t *testing.T) {
	engine := &fakeEngine{kind: "http"}
	rt := newRuntime(t, engine)
	input, _ := json.Marshal(map[string]any{"target": "http://127.0.0.1", "template_ids": []string{"t1"}})
	res, err := rt.Call(context.Background(), "verify_execute", input, core.CallContext{ProjectID: 1, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	if engine.calls != 1 {
		t.Fatalf("engine calls = %d", engine.calls)
	}
}

func TestVerifyExecuteMissingTemplate(t *testing.T) {
	rt := newRuntime(t, &fakeEngine{kind: "http"})
	input, _ := json.Marshal(map[string]any{"target": "http://127.0.0.1", "template_ids": []string{"nope"}})
	res, err := rt.Call(context.Background(), "verify_execute", input, core.CallContext{ProjectID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("result = %+v", res)
	}
}

// newDirectKit builds a verifykit capability with scripted fakes so the
// envelope (Summary/Status/Meta) can be asserted without the runtime's
// back-fill, mirroring what the contract gate does.
func newDirectKit(t *testing.T, fp core.FingerprintProvider, cat core.TemplateCatalog, engines map[string]core.TemplateEngine) *verify.Kit {
	t.Helper()
	k, err := verify.New(core.Deps{Fingerprints: fp, Templates: cat, TemplateEngines: engines})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	return k
}

func TestVerifyPlanSummary(t *testing.T) {
	cat := &fakeCatalog{refs: map[string]core.TemplateRef{
		"t1": {ID: "t1", Kind: "http", Engine: "http", Meta: map[string]string{"products": "nginx", "severity": "high"}},
		"t2": {ID: "t2", Kind: "http", Engine: "http", Meta: map[string]string{"products": "nginx", "severity": "low"}},
	}}
	k := newDirectKit(t, &fakeFP{products: []string{"nginx"}}, cat,
		map[string]core.TemplateEngine{"http": &fakeEngine{kind: "http"}})
	res, err := k.Call(context.Background(), core.Call{
		Tool: "verify_plan", Input: json.RawMessage(`{"target":"http://127.0.0.1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess || !res.OK {
		t.Fatalf("status = %s", res.Status)
	}
	if res.Meta.Tool != "verify_plan" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
	want := "按 1 个指纹为 http://127.0.0.1 规划 2 个模板（高危 1 个）"
	if res.Summary != want {
		t.Fatalf("summary = %q, want %q", res.Summary, want)
	}
}

func TestVerifyExecuteSummary(t *testing.T) {
	eng := &fakeEngine{kind: "http", findings: []core.Finding{
		{Kind: "sqli", Confirmed: true}, {Kind: "xss", Confirmed: false},
	}}
	cat := &fakeCatalog{refs: map[string]core.TemplateRef{
		"t1": {ID: "t1", Kind: "http", Engine: "http"},
	}}
	k := newDirectKit(t, &fakeFP{}, cat, map[string]core.TemplateEngine{"http": eng})
	res, err := k.Call(context.Background(), core.Call{
		Tool: "verify_execute", Input: json.RawMessage(`{"target":"http://127.0.0.1","template_ids":["t1"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta.Tool != "verify_execute" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
	want := "对 http://127.0.0.1 执行 1 个模板，命中 2 项，其中确认 1 项"
	if res.Summary != want {
		t.Fatalf("summary = %q, want %q", res.Summary, want)
	}
}

// TestVerifyExecuteBadInputEnvelope: a failure path must still carry a real
// Summary and a Meta.Tool, not a generic phrase.
func TestVerifyExecuteBadInputEnvelope(t *testing.T) {
	k := newDirectKit(t, &fakeFP{}, &fakeCatalog{refs: map[string]core.TemplateRef{}},
		map[string]core.TemplateEngine{"http": &fakeEngine{kind: "http"}})
	res, err := k.Call(context.Background(), core.Call{
		Tool: "verify_execute", Input: json.RawMessage(`{"target":"http://127.0.0.1","template_ids":[]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("res = %+v", res)
	}
	if strings.TrimSpace(res.Summary) == "" || res.Meta.Tool != "verify_execute" {
		t.Fatalf("envelope = %+v", res)
	}
}

// TestVerifyExecuteEngineUnavailableEnvelope: an unavailable dependency must
// surface as StatusUnavailable with the fixed error code, not a bare error.
func TestVerifyExecuteEngineUnavailableEnvelope(t *testing.T) {
	cat := &fakeCatalog{refs: map[string]core.TemplateRef{
		"t1": {ID: "t1", Kind: "nuclei", Engine: "nuclei"},
	}}
	k := newDirectKit(t, &fakeFP{}, cat,
		map[string]core.TemplateEngine{"http": &fakeEngine{kind: "http"}})
	res, err := k.Call(context.Background(), core.Call{
		Tool: "verify_execute", Input: json.RawMessage(`{"target":"http://127.0.0.1","template_ids":["t1"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusUnavailable || res.Error == nil || res.Error.Code != core.CodeUnavailable {
		t.Fatalf("res = %+v", res)
	}
	if res.Meta.Tool != "verify_execute" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
}

func TestVerifyUnknownToolEnvelope(t *testing.T) {
	k := newDirectKit(t, &fakeFP{}, &fakeCatalog{refs: map[string]core.TemplateRef{}},
		map[string]core.TemplateEngine{"http": &fakeEngine{kind: "http"}})
	res, _ := k.Call(context.Background(), core.Call{Tool: "nope", Input: json.RawMessage(`{}`)})
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("res = %+v", res)
	}
	if res.Meta.Tool != "nope" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
}
