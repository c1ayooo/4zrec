package exec

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Runner is the gate-aware ProcessRunner injected into kits. It re-checks
// scope and rate limits for the targets a subprocess is about to touch.
type Runner struct {
	Scope   core.ScopeChecker
	Limiter core.Limiter
	Audit   core.AuditSink
	// ExtraEnv is appended after os.Environ(). Hosts can inject proxy vars.
	ExtraEnv []string
}

func New(scope core.ScopeChecker, limiter core.Limiter, audit core.AuditSink) *Runner {
	return &Runner{Scope: scope, Limiter: limiter, Audit: audit}
}

// NewLocal returns a runner for host-side local commands that carry no network
// targets (a CLI session's shell, for example). Scope enforcement is skipped
// because there is no target to check; audit still records the invocation when
// an audit sink is supplied.
func NewLocal(audit core.AuditSink) *Runner {
	return &Runner{Audit: audit}
}

func (r *Runner) Run(ctx context.Context, spec core.ProcessSpec) (*core.ProcessResult, error) {
	if spec.Path == "" {
		return nil, core.InvalidInput("process path is required")
	}
	cc, _ := core.CallContextFrom(ctx)

	var releases []func()
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()
	for _, target := range spec.Targets {
		if target.ProjectID == 0 {
			target.ProjectID = cc.ProjectID
		}
		if r.Scope == nil {
			return nil, core.ScopeDenied("scope checker is not configured")
		}
		if err := r.Scope.Check(ctx, target); err != nil {
			return nil, err
		}
		if r.Limiter != nil {
			release, err := r.Limiter.Acquire(ctx, target.Key(), spec.RateLimit)
			if err != nil {
				return nil, err
			}
			releases = append(releases, release)
		}
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, spec.Path, spec.Args...)
	if spec.Dir != "" {
		cmd.Dir = spec.Dir
	}
	cmd.Env = append(os.Environ(), r.ExtraEnv...)
	cmd.Env = append(cmd.Env, spec.Env...)
	if len(spec.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(spec.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	started := time.Now()
	err := cmd.Run()
	duration := time.Since(started)
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			if r.Audit != nil {
				r.Audit.Record(ctx, core.AuditEvent{
					TraceID: cc.TraceID, Actor: cc.Actor, ProjectID: cc.ProjectID, TaskID: cc.TaskID,
					Capability: "process", Tool: "exec", Risk: core.RiskMedium, Targets: spec.Targets,
					Phase: "process", Status: "error", Error: err.Error(),
					DurationMS: duration.Milliseconds(), StartedAt: started, FinishedAt: time.Now(),
				})
			}
			return nil, core.Unavailable(err.Error())
		}
	}
	if r.Audit != nil {
		status := "ok"
		errMsg := ""
		if exitCode != 0 {
			status = "error"
			errMsg = "exit code " + itoa(exitCode)
		}
		r.Audit.Record(ctx, core.AuditEvent{
			TraceID: cc.TraceID, Actor: cc.Actor, ProjectID: cc.ProjectID, TaskID: cc.TaskID,
			Capability: "process", Tool: "exec", Risk: core.RiskMedium, Targets: spec.Targets,
			Phase: "process", Status: status, Error: errMsg,
			DurationMS: duration.Milliseconds(), StartedAt: started, FinishedAt: time.Now(),
		})
	}
	return &core.ProcessResult{ExitCode: exitCode, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
