package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// SMBOpener opens an SMB share session. SMB is not an HTTP protocol and capkit
// has no raw-TCP port, so the transport is the sanctioned ProcessRunner route
// (docs §6.4: every external tool is a subprocess): commands are driven through
// smbclient, its password carried in the environment rather than the command
// line so it never lands in the process list or the audit trail.
//
// The session is stateless per command — SMB has no remote shell here, so Exec
// runs smbclient subcommands (ls/get/put/del/mkdir …). An authentication
// failure surfaces on the first Exec, not at Open, because Open issues no
// traffic.
type SMBOpener struct {
	// Runner is required.
	Runner core.ProcessRunner
	// Binary overrides the smbclient path; default "smbclient".
	Binary string
	// Share is the share name when the session spec does not carry one in
	// Options["share"].
	Share string
	// Artifacts stages uploads locally (smbclient needs a real file path).
	// Upload stays unavailable when it is nil.
	Artifacts core.ArtifactStore
	// Timeout bounds one smbclient invocation; default 60s.
	Timeout time.Duration
}

// Open records the target parameters. No traffic is issued, so this only fails
// on a missing runner or an unusable host.
func (o *SMBOpener) Open(_ context.Context, spec core.SessionSpec) (core.Session, error) {
	if o.Runner == nil {
		return nil, core.Unavailable("SMB 需要 ProcessRunner 端口（subprocess 调 smbclient）")
	}
	host := hostFor(spec.Host)
	if host == "" {
		return nil, fmt.Errorf("SMB 会话需要 host")
	}
	share := core.FirstNonEmpty(optionsOf(spec)["share"], o.Share)
	if share == "" {
		share = "C$"
	}
	binary := core.FirstNonEmpty(o.Binary, "smbclient")
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &SMBSession{
		runner: o.Runner, artifacts: o.Artifacts, binary: binary, timeout: timeout,
		unc:  "//" + host + "/" + share,
		user: userSpec(spec.Domain, spec.User),
		pass: spec.Secret,
		info: core.SessionInfo{
			Kind: "smb", Host: host, Port: core.FirstPositive(spec.Port, 445), User: spec.User,
			Labels: spec.Labels,
			Meta:   map[string]string{"unc": "//" + host + "/" + share, "transport": "smbclient"},
		},
	}, nil
}

// SMBSession is an SMB share foothold driven through smbclient.
type SMBSession struct {
	runner    core.ProcessRunner
	artifacts core.ArtifactStore
	binary    string
	timeout   time.Duration
	unc       string
	user      string
	pass      string
	info      core.SessionInfo
}

func (s *SMBSession) Info() core.SessionInfo { return s.info }

// Close is a no-op: smbclient connections live for one invocation.
func (s *SMBSession) Close() error { return nil }

// Exec runs one smbclient command list (e.g. "ls", "get a.txt b.txt").
func (s *SMBSession) Exec(ctx context.Context, cmd string, opts core.ExecOpts) (core.Output, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return core.Output{}, fmt.Errorf("命令为空")
	}
	started := time.Now()
	res, err := s.run(ctx, cmd, opts.Timeout)
	if err != nil {
		return core.OutputFor(cmd, "", err.Error(), -1, time.Since(started), opts.MaxOutput), err
	}
	return core.OutputFor(cmd, string(res.Stdout), string(res.Stderr), res.ExitCode, time.Since(started), opts.MaxOutput), nil
}

// CanUpload reports whether uploads are possible (an ArtifactStore is wired).
func (s *SMBSession) CanUpload() bool { return s.artifacts != nil }

// Upload stages data locally through the ArtifactStore and pushes it with
// smbclient's put command.
func (s *SMBSession) Upload(ctx context.Context, src io.Reader, remote string) error {
	if s.artifacts == nil {
		return core.ToolMissing("SMB 上传需要 ArtifactStore 暂存文件")
	}
	if strings.TrimSpace(remote) == "" {
		return fmt.Errorf("remote 路径必填")
	}
	data, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	local, err := s.artifacts.Put(ctx, "smb-upload", data)
	if err != nil {
		return err
	}
	if _, err := s.run(ctx, "put "+local+" "+remote, 0); err != nil {
		return err
	}
	return nil
}

// Download reads a remote file with smbclient's cat command, so no local
// staging is needed.
func (s *SMBSession) Download(ctx context.Context, remote string) (io.ReadCloser, error) {
	if strings.TrimSpace(remote) == "" {
		return nil, fmt.Errorf("remote 路径必填")
	}
	res, err := s.run(ctx, "cat "+remote, 0)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, core.UpstreamError("smbclient 读取失败: " + strings.TrimSpace(string(res.Stderr)))
	}
	return io.NopCloser(bytes.NewReader(res.Stdout)), nil
}

func (s *SMBSession) run(ctx context.Context, command string, timeout time.Duration) (*core.ProcessResult, error) {
	if timeout <= 0 {
		timeout = s.timeout
	}
	args := []string{s.unc, "-c", command}
	if s.user != "" {
		args = append(args, "-U", s.user)
	}
	spec := core.ProcessSpec{
		Path: s.binary, Args: args, Timeout: timeout,
		// smbclient reaches the target host, so the runner must scope-check it
		// exactly like any other target-touching subprocess.
		Targets: []core.Target{{
			Kind: core.TargetHost, Host: hostFor(s.info.Host), Port: s.info.Port,
		}},
	}
	// The password rides in PASSWD so it stays out of argv.
	if s.pass != "" {
		spec.Env = []string{"PASSWD=" + s.pass}
	}
	return s.runner.Run(ctx, spec)
}

func optionsOf(spec core.SessionSpec) map[string]string {
	if spec.Options == nil {
		return map[string]string{}
	}
	return spec.Options
}

func userSpec(domain, user string) string {
	if user == "" {
		return ""
	}
	if domain != "" {
		return domain + `\` + user
	}
	return user
}
