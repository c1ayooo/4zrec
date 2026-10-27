package session

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// CLIOpener runs commands as a local process through the host's ProcessRunner
// port. It is the reference adapter: it needs no credentials and no network, so
// it makes the Session contract testable end to end and is useful for local
// agent-side tasks.
//
// Routing through ProcessRunner (never os/exec) keeps the "kits never spawn a
// subprocess themselves" boundary intact (docs §6.4): the host decides whether
// local execution is gated, audited and sandboxed. A host that wants a fully
// gated local transport passes adapters/exec.New(scope, limiter, audit); one
// that only needs host-side local commands passes adapters/exec.NewLocal().
type CLIOpener struct {
	// Runner is required: CLIOpener holds no execution path of its own.
	Runner core.ProcessRunner
	// AllowedCommands, when non-empty, restricts the first token of every
	// command. Empty means unrestricted (host's responsibility).
	AllowedCommands []string
	// DefaultShell overrides the detected shell interpreter.
	DefaultShell string
}

// Open returns a CLI session. spec.Host is ignored; "local" is conventional.
func (o *CLIOpener) Open(_ context.Context, spec core.SessionSpec) (core.Session, error) {
	if o.Runner == nil {
		return nil, core.Unavailable("cli opener requires a process runner")
	}
	info := core.SessionInfo{
		Kind: "cli", Host: core.FirstNonEmpty(spec.Host, "local"),
		OS: osName(), Arch: runtime.GOARCH, Labels: spec.Labels,
		Meta: map[string]string{"cwd": core.FirstNonEmpty(cwd(), "")},
	}
	if u := hostUser(); u != "" {
		info.User = u
		info.Meta["user"] = u
	}
	if isElevated() {
		info.Elevated = true
	}
	return &CLISession{info: info, allowed: o.AllowedCommands, shell: o.DefaultShell, runner: o.Runner}, nil
}

// CLISession is a local-process Session.
type CLISession struct {
	info    core.SessionInfo
	allowed []string
	shell   string
	runner  core.ProcessRunner
}

func (s *CLISession) Info() core.SessionInfo { return s.info }

func (s *CLISession) Close() error { return nil }

func (s *CLISession) Exec(ctx context.Context, cmd string, opts core.ExecOpts) (core.Output, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return core.Output{}, fmt.Errorf("命令为空")
	}
	if len(s.allowed) > 0 {
		first := strings.Fields(cmd)
		if len(first) == 0 || !containsStr(s.allowed, first[0]) {
			return core.Output{}, fmt.Errorf("命令 %q 不在白名单内", first)
		}
	}
	shell := opts.Shell
	if shell == "" {
		shell = s.shell
	}
	if shell == "" {
		shell = "sh"
	}
	args := []string{"-c", cmd}
	if opts.TTY {
		args = []string{"-i", "-c", cmd}
	}
	spec := core.ProcessSpec{
		Path:    shell,
		Args:    args,
		Dir:     core.FirstNonEmpty(opts.Dir, s.info.Meta["cwd"]),
		Env:     envList(opts.Env),
		Stdin:   opts.Stdin,
		Timeout: opts.Timeout,
	}
	started := time.Now()
	pr, err := s.runner.Run(ctx, spec)
	dur := time.Since(started)
	if err != nil {
		return core.OutputFor(cmd, "", err.Error(), -1, dur, opts.MaxOutput), err
	}
	return core.OutputFor(cmd, string(pr.Stdout), string(pr.Stderr), pr.ExitCode, dur, opts.MaxOutput), nil
}

// envList renders extra environment entries. The runner owns the base
// environment; a session only contributes its overrides.
func envList(extra map[string]string) []string {
	if len(extra) == 0 {
		return nil
	}
	out := make([]string, 0, len(extra))
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

func osName() string {
	switch runtime.GOOS {
	case "darwin":
		return "darwin"
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	default:
		return runtime.GOOS
	}
}

func hostUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return os.Getenv("USERNAME")
}

func cwd() string {
	d, err := os.Getwd()
	if err != nil {
		return ""
	}
	return d
}

func isElevated() bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return false
	}
	return os.Geteuid() == 0
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
