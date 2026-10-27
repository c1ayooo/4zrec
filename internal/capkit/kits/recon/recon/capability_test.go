package recon_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/recon/recon"
)

// errorSink fails every emit so the pipeline records errors and the call is
// reported as partial rather than success.
type errorSink struct{}

func (errorSink) Emit(context.Context, recon.Asset) error { return errors.New("sink down") }

func reconCapability(t *testing.T, p *recon.Pipeline) core.Capability {
	t.Helper()
	c, err := recon.NewCapability(core.Deps{})
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	if p != nil {
		return c.(*recon.Capability).WithPipeline(p)
	}
	return c
}

// TestReconEnvelopeUnwired covers the failure path: a capability built without a
// wired pipeline must return a ToolMissing envelope, not a bare result.
func TestReconEnvelopeUnwired(t *testing.T) {
	res, err := reconCapability(t, nil).Call(context.Background(), core.Call{
		Tool: "recon_run", Input: []byte(`{"domains":["example.com"],"enable_subdomain":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusUnavailable || res.Error == nil || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("status=%q err=%+v", res.Status, res.Error)
	}
	if res.Meta.Tool != "recon_run" || res.Meta.Version != "0.2.0" {
		t.Fatalf("meta = %+v", res.Meta)
	}
	if strings.TrimSpace(res.Summary) == "" || res.Summary == "失败" {
		t.Fatalf("summary = %q", res.Summary)
	}
}

// TestReconEnvelopeSuccess drives the pipeline through the capability and checks
// the success envelope and its target-naming Summary.
func TestReconEnvelopeSuccess(t *testing.T) {
	sink := &memSink{}
	p := &recon.Pipeline{
		Subs: fakeSubs{}, HTTP: fakeHTTP{}, Sink: sink,
		Scope: gates.StaticScope("example.com"), Limiter: gates.NewLimiter(),
	}
	res, err := reconCapability(t, p).Call(context.Background(), core.Call{
		Tool:  "recon_run",
		Input: []byte(`{"domains":["example.com"],"enable_subdomain":true,"enable_http":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess || !res.OK {
		t.Fatalf("status=%q ok=%v summary=%q", res.Status, res.OK, res.Summary)
	}
	if res.Meta.Tool != "recon_run" || res.Meta.Version != "0.2.0" {
		t.Fatalf("meta = %+v", res.Meta)
	}
	if !strings.Contains(res.Summary, "对 1 个域名执行侦察流水线") ||
		!strings.Contains(res.Summary, "子域 2") || !strings.Contains(res.Summary, "资产 6 条") {
		t.Fatalf("summary = %q", res.Summary)
	}
	if len([]rune(res.Summary)) > core.MaxSummaryRunes {
		t.Fatalf("summary too long: %d", len([]rune(res.Summary)))
	}
	var v any
	if err := json.Unmarshal(res.Data, &v); err != nil {
		t.Fatalf("Data is not valid JSON: %v", err)
	}
	if len(sink.assets) != 6 {
		t.Fatalf("assets = %d", len(sink.assets))
	}
}

// TestReconEnvelopePartial covers the partial path (stages degraded but the run
// completed) and the invalid-input path.
func TestReconEnvelopePartial(t *testing.T) {
	p := &recon.Pipeline{
		Subs: fakeSubs{}, Sink: errorSink{},
		Scope: gates.StaticScope("example.com"), Limiter: gates.NewLimiter(),
	}
	res, err := reconCapability(t, p).Call(context.Background(), core.Call{
		Tool: "recon_run", Input: []byte(`{"domains":["example.com"],"enable_subdomain":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusPartial || !res.OK {
		t.Fatalf("status=%q ok=%v summary=%q", res.Status, res.OK, res.Summary)
	}
	if !strings.Contains(res.Summary, "个错误") {
		t.Fatalf("partial summary = %q", res.Summary)
	}

	res, err = reconCapability(t, p).Call(context.Background(), core.Call{
		Tool: "recon_run", Input: []byte(`{"domains":[]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("invalid input = %q %+v", res.Status, res.Error)
	}
	if res.Meta.Tool != "recon_run" {
		t.Fatalf("Meta.Tool = %q", res.Meta.Tool)
	}
}

// TestReconUnknownTool pins the not-found envelope for an unregistered tool.
func TestReconUnknownTool(t *testing.T) {
	res, err := reconCapability(t, nil).Call(context.Background(), core.Call{Tool: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("res = %q %+v", res.Status, res.Error)
	}
}
