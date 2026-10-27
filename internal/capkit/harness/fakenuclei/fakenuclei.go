package fakenuclei

import (
	"context"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Runner is a scripted ProcessRunner for contract tests.
type Runner struct {
	mu       sync.Mutex
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
	Calls    []core.ProcessSpec
}

func (r *Runner) Run(_ context.Context, spec core.ProcessSpec) (*core.ProcessResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Calls = append(r.Calls, spec)
	if r.Err != nil {
		return nil, r.Err
	}
	return &core.ProcessResult{ExitCode: r.ExitCode, Stdout: append([]byte(nil), r.Stdout...), Stderr: append([]byte(nil), r.Stderr...)}, nil
}

func (r *Runner) LastCall() (core.ProcessSpec, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.Calls) == 0 {
		return core.ProcessSpec{}, false
	}
	return r.Calls[len(r.Calls)-1], true
}

// Binaries is a scripted BinaryManager for contract tests.
type Binaries struct {
	Path        string
	State       core.BinaryStatus
	Err         error
	EnsureCalls int
}

func (b *Binaries) Ensure(context.Context, string, string) (string, core.BinaryStatus, error) {
	b.EnsureCalls++
	if b.Err != nil {
		return "", core.BinaryStatus{}, b.Err
	}
	if b.State.Version == "" {
		b.State = core.BinaryStatus{Installed: true, Version: "test", Path: b.Path, UpdatedAt: time.Now()}
	}
	return b.Path, b.State, nil
}

func (b *Binaries) Update(context.Context, string, string) (core.BinaryStatus, error) {
	if b.Err != nil {
		return core.BinaryStatus{}, b.Err
	}
	return b.State, nil
}

func (b *Binaries) Status(context.Context, string) (core.BinaryStatus, error) {
	if b.Err != nil {
		return core.BinaryStatus{}, b.Err
	}
	return b.State, nil
}
