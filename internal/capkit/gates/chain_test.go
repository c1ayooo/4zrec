package gates

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type countingLimiter struct {
	acquires int
	releases int
}

func (c *countingLimiter) Acquire(context.Context, string, core.RateLimitSpec) (func(), error) {
	c.acquires++
	return func() { c.releases++ }, nil
}

type memoryAudit struct{ events []core.AuditEvent }

func (m *memoryAudit) Record(_ context.Context, ev core.AuditEvent) {
	m.events = append(m.events, ev)
}

func testSpec() core.ToolSpec {
	return core.ToolSpec{
		Name: "probe", Description: "probe", Risk: core.RiskHigh,
		RateLimit: core.RateLimitSpec{PerSecond: 10, Burst: 2, Concurrency: 1},
		ExtractTargets: func(json.RawMessage) ([]core.Target, error) {
			return []core.Target{{Kind: core.TargetURL, URL: "http://a.test", Host: "a.test"}}, nil
		},
	}
}

func TestChainScopeDenied(t *testing.T) {
	chain := &Chain{Scope: StaticScope("allowed.test"), Limiter: &countingLimiter{}, Audit: &memoryAudit{}}
	_, _, err := chain.Before(context.Background(), "cap", testSpec(), core.Call{Tool: "probe", Input: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("expected scope denial")
	}
	var ce *core.Error
	if !errors.As(err, &ce) || ce.Code != core.CodeScopeDenied {
		t.Fatalf("err = %v", err)
	}
}

func TestChainRequiresApproval(t *testing.T) {
	chain := &Chain{Scope: AllowAllScope(), Limiter: &countingLimiter{}, Audit: &memoryAudit{}, Approval: nil}
	_, _, err := chain.Before(context.Background(), "cap", testSpec(), core.Call{Tool: "probe", Input: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("expected approval error")
	}
	var ce *core.Error
	if !errors.As(err, &ce) || ce.Code != core.CodeApprovalRequired {
		t.Fatalf("err = %v", err)
	}
}

func TestChainAcquiresAndReleasesAndAudits(t *testing.T) {
	lim := &countingLimiter{}
	audit := &memoryAudit{}
	chain := &Chain{
		Scope: AllowAllScope(), Limiter: lim, Audit: audit,
		Approval: AutoApprove(), RequireApprovalAt: core.RiskHigh,
	}
	_, finish, err := chain.Before(context.Background(), "cap", testSpec(), core.Call{Tool: "probe", Input: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if lim.acquires != 1 {
		t.Fatalf("acquires = %d", lim.acquires)
	}
	finish(core.TextResult("ok"), nil)
	if lim.releases != 1 {
		t.Fatalf("releases = %d", lim.releases)
	}
	if len(audit.events) != 2 {
		t.Fatalf("audit events = %d", len(audit.events))
	}
	if audit.events[0].Phase != "start" || audit.events[1].Phase != "finish" {
		t.Fatalf("phases = %q %q", audit.events[0].Phase, audit.events[1].Phase)
	}
	// finish is idempotent.
	finish(core.TextResult("ok"), nil)
	if lim.releases != 1 || len(audit.events) != 2 {
		t.Fatal("finish was not idempotent")
	}
}
