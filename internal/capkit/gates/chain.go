package gates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Chain is the mandatory gate sequence around every capability call:
// scope -> approval -> rate limit -> audit. It is not optional; the runtime
// always routes calls through it.
type Chain struct {
	Scope             core.ScopeChecker
	Approval          core.Approver
	Limiter           core.Limiter
	Audit             core.AuditSink
	Redactor          Redactor
	RequireApprovalAt core.Risk
	Clock             core.Clock
	IDs               core.IDGenerator
}

func (c *Chain) now() time.Time {
	if c.Clock != nil {
		return c.Clock.Now()
	}
	return time.Now()
}

func (c *Chain) threshold() core.Risk {
	if c.RequireApprovalAt == "" {
		return core.RiskHigh
	}
	return c.RequireApprovalAt
}

type gateTraceKey struct{}

// GateTraceFrom returns the per-stage gate timings recorded by Before, e.g.
// ["scope:1ms", "approval:0ms", "ratelimit:0ms", "audit:2ms"]. It answers
// "why was this call slow" for agent and operator alike.
func GateTraceFrom(ctx context.Context) []string {
	if v, ok := ctx.Value(gateTraceKey{}).([]string); ok {
		return v
	}
	return nil
}

// Before validates targets, obtains approval and rate slots, and writes the
// start audit event. The returned finish function is idempotent and must be
// called by the runtime (typically deferred).
func (c *Chain) Before(ctx context.Context, capName string, spec core.ToolSpec, call core.Call) (context.Context, func(core.Result, error), error) {
	started := c.now()
	cc, _ := core.CallContextFrom(ctx)
	if cc.TraceID == "" {
		if c.IDs != nil {
			cc.TraceID = c.IDs.New("trace")
		} else {
			cc.TraceID = fmt.Sprintf("trace-%d", started.UnixNano())
		}
	}
	ctx = core.WithCallContext(ctx, cc)

	var trace []string
	mark := func(stage string, since time.Time) {
		trace = append(trace, fmt.Sprintf("%s:%dms", stage, c.now().Sub(since).Milliseconds()))
	}

	var targets []core.Target
	if spec.ExtractTargets != nil {
		var err error
		targets, err = spec.ExtractTargets(call.Input)
		if err != nil {
			return ctx, nil, core.InvalidInput(err.Error())
		}
	}
	for i := range targets {
		if targets[i].ProjectID == 0 {
			targets[i].ProjectID = cc.ProjectID
		}
	}

	if len(targets) > 0 {
		t0 := c.now()
		if c.Scope == nil {
			return ctx, nil, core.ScopeDenied("scope checker is not configured")
		}
		for _, target := range targets {
			if err := c.Scope.Check(ctx, target); err != nil {
				return ctx, nil, err
			}
		}
		mark("scope", t0)
	}

	if spec.Risk.AtLeast(c.threshold()) {
		t0 := c.now()
		if c.Approval == nil {
			return ctx, nil, core.NewError(core.CodeApprovalRequired, "approval gate is not configured")
		}
		if err := c.Approval.Require(ctx, core.ApprovalRequest{
			Capability: capName, Tool: spec.Name, Risk: spec.Risk, Targets: targets,
			Actor: cc.Actor, ProjectID: cc.ProjectID,
		}); err != nil {
			return ctx, nil, err
		}
		mark("approval", t0)
	}

	var releases []func()
	seen := map[string]bool{}
	for _, target := range targets {
		key := target.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		if c.Limiter == nil {
			releaseAll(releases)
			return ctx, nil, core.NewError(core.CodeRateLimited, "rate limiter is not configured")
		}
		t0 := c.now()
		release, err := c.Limiter.Acquire(ctx, key, spec.RateLimit)
		if err != nil {
			releaseAll(releases)
			return ctx, nil, err
		}
		mark("ratelimit", t0)
		releases = append(releases, release)
	}

	redactor := c.Redactor
	if redactor == nil {
		redactor = JSONRedactor{}
	}
	auditInput := redactor.Redact(call.Input)
	hash := sha256.Sum256(auditInput)
	t0 := c.now()
	startEvent := core.AuditEvent{
		TraceID: cc.TraceID, Actor: cc.Actor, ProjectID: cc.ProjectID, TaskID: cc.TaskID,
		Capability: capName, Tool: spec.Name, Risk: spec.Risk, Targets: targets,
		Phase: "start", InputHash: hex.EncodeToString(hash[:]), StartedAt: started,
	}
	if c.Audit != nil {
		c.Audit.Record(ctx, startEvent)
	}
	mark("audit", t0)
	ctx = context.WithValue(ctx, gateTraceKey{}, trace)

	var once sync.Once
	finish := func(res core.Result, callErr error) {
		once.Do(func() {
			releaseAll(releases)
			finished := c.now()
			status := "ok"
			errMsg := ""
			if callErr != nil {
				status = "error"
				errMsg = callErr.Error()
			} else if !res.OK && res.Error != nil {
				status = "error"
				errMsg = res.Error.Error()
			}
			if c.Audit != nil {
				c.Audit.Record(ctx, core.AuditEvent{
					TraceID: cc.TraceID, Actor: cc.Actor, ProjectID: cc.ProjectID, TaskID: cc.TaskID,
					Capability: capName, Tool: spec.Name, Risk: spec.Risk, Targets: targets,
					Phase: "finish", Status: status, Error: errMsg, InputHash: startEvent.InputHash,
					DurationMS: finished.Sub(started).Milliseconds(), EvidenceIDs: res.EvidenceIDs,
					StartedAt: started, FinishedAt: finished,
				})
			}
		})
	}
	return ctx, finish, nil
}

func releaseAll(releases []func()) {
	for i := len(releases) - 1; i >= 0; i-- {
		releases[i]()
	}
}
