package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"golang.org/x/crypto/ssh"
)

// SSHOwner opens a real SSH foothold. It implements Session (Exec/Info/Close)
// plus the optional Uploader/Downloader/Tunneler capabilities from §5.1, so
// downstream kits get file transfer and port forwarding for free.
//
// The opener authenticates with a password or a PEM private key supplied in
// SessionSpec.Secret; the host is responsible for resolving that secret from
// the Sealer at the edge and for scope approval before calling Open.
type SSHOwner struct {
	// HostKeyCallback defaults to ssh.InsecureIgnoreHostKey when nil. Hosts
	// should inject a pinned callback.
	HostKeyCallback ssh.HostKeyCallback
	// Dialer overrides the TCP dialer (hosts route through proxies here).
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Open dials, authenticates and returns a live SSH session.
func (o *SSHOwner) Open(ctx context.Context, spec core.SessionSpec) (core.Session, error) {
	port := spec.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(spec.Host, strconv.Itoa(port))
	auth, err := sshAuth(spec)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            spec.User,
		Auth:            auth,
		HostKeyCallback: o.HostKeyCallback,
		Timeout:         spec.Timeout,
	}
	if cfg.HostKeyCallback == nil {
		cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	dial := o.Dialer
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SSH 连接失败 %s: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH 认证失败 %s: %w", addr, err)
	}
	client := ssh.NewClient(c, chans, reqs)
	info := core.SessionInfo{
		Kind: "ssh", Host: spec.Host, Port: port, User: spec.User,
		Labels: spec.Labels, Meta: map[string]string{"server_version": string(client.ServerVersion())},
	}
	s := &SSHSession{client: client, info: info}
	s.probe(ctx)
	return s, nil
}

// SSHSession is a live SSH foothold.
type SSHSession struct {
	client *ssh.Client
	info   core.SessionInfo
}

func (s *SSHSession) Info() core.SessionInfo { return s.info }

func (s *SSHSession) Close() error { return s.client.Close() }

// Exec runs cmd through a new SSH session channel.
func (s *SSHSession) Exec(ctx context.Context, cmd string, opts core.ExecOpts) (core.Output, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return core.Output{}, fmt.Errorf("命令为空")
	}
	sess, err := s.client.NewSession()
	if err != nil {
		return core.Output{}, fmt.Errorf("SSH 新建会话失败: %w", err)
	}
	defer func() { _ = sess.Close() }()

	envList := ""
	var envs []string
	for k, v := range opts.Env {
		envs = append(envs, fmt.Sprintf("export %s=%s; ", k, core.ShellQuote(v)))
	}
	if len(envs) > 0 {
		envList = strings.Join(envs, "")
	}
	if opts.Dir != "" {
		envList += "cd " + core.ShellQuote(opts.Dir) + "; "
	}
	full := envList + cmd

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	if len(opts.Stdin) > 0 {
		sess.Stdin = bytes.NewReader(opts.Stdin)
	}
	if opts.TTY {
		modes := ssh.TerminalModes{ssh.ECHO: 0}
		if err := sess.RequestPty("xterm", 80, 24, modes); err != nil {
			return core.Output{}, err
		}
	}

	type result struct{ err error }
	done := make(chan result, 1)
	started := time.Now()
	go func() { done <- result{err: sess.Run(full)} }()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		return core.Output{}, ctx.Err()
	case <-time.After(timeout):
		_ = sess.Signal(ssh.SIGKILL)
		return core.OutputFor(cmd, stdout.String(), stderr.String(), -1, time.Since(started), opts.MaxOutput), fmt.Errorf("SSH 命令超时")
	case r := <-done:
		exit := 0
		if r.err != nil {
			if ee, ok := r.err.(*ssh.ExitError); ok {
				exit = ee.ExitStatus()
			} else {
				return core.OutputFor(cmd, stdout.String(), stderr.String(), -1, time.Since(started), opts.MaxOutput), r.err
			}
		}
		return core.OutputFor(cmd, stdout.String(), stderr.String(), exit, time.Since(started), opts.MaxOutput), nil
	}
}

// Upload streams src to remote using cat > path (base64-free, binary safe).
func (s *SSHSession) Upload(ctx context.Context, src io.Reader, remote string) error {
	if strings.TrimSpace(remote) == "" {
		return fmt.Errorf("remote 路径必填")
	}
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()
	sess.Stdin = src
	quoted := core.ShellQuote(remote)
	return sess.Run("cat > " + quoted)
}

// Download reads remote via cat (stdout streamed back).
func (s *SSHSession) Download(ctx context.Context, remote string) (io.ReadCloser, error) {
	if strings.TrimSpace(remote) == "" {
		return nil, fmt.Errorf("remote 路径必填")
	}
	sess, err := s.client.NewSession()
	if err != nil {
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	if err := sess.Start("cat " + core.ShellQuote(remote)); err != nil {
		_ = sess.Close()
		return nil, err
	}
	return &sessionReader{r: stdout, sess: sess}, nil
}

// Tunnel opens a remote dial through the SSH connection.
func (s *SSHSession) Tunnel(ctx context.Context, spec core.TunnelSpec) (core.Tunnel, error) {
	network := spec.Network
	if network == "" {
		network = "tcp"
	}
	remote, err := s.client.Dial(network, spec.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("SSH 隧道建立失败: %w", err)
	}
	local := spec.LocalAddr
	if local == "" {
		local = spec.RemoteAddr
	}
	return &tunnel{conn: remote, local: local}, nil
}

// probe fills OS/arch/user metadata with one cheap command.
func (s *SSHSession) probe(ctx context.Context) {
	if s.info.OS != "" {
		return
	}
	out, err := s.Exec(ctx, "uname -s; uname -m; id -un 2>/dev/null; id -u 2>/dev/null", core.ExecOpts{Timeout: 8 * time.Second})
	if err != nil || out.Stdout == "" {
		return
	}
	lines := strings.Split(strings.TrimSpace(out.Stdout), "\n")
	if len(lines) > 0 {
		s.info.OS = osFromUname(lines[0])
	}
	if len(lines) > 1 {
		s.info.Arch = strings.TrimSpace(lines[1])
	}
	if len(lines) > 2 && s.info.User == "" {
		s.info.User = strings.TrimSpace(lines[2])
	}
	if len(lines) > 3 && strings.TrimSpace(lines[3]) == "0" {
		s.info.Elevated = true
	}
}

func osFromUname(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	switch {
	case strings.Contains(u, "linux"):
		return "linux"
	case strings.Contains(u, "darwin"), strings.Contains(u, "bsd"):
		return "darwin"
	case strings.Contains(u, "windows"), strings.Contains(u, "mingw"), strings.Contains(u, "cygwin"):
		return "windows"
	default:
		return u
	}
}

func sshAuth(spec core.SessionSpec) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if key := strings.TrimSpace(spec.Secret); key != "" && strings.Contains(key, "PRIVATE KEY") {
		parsed, err := ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("私钥解析失败: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(parsed))
		return methods, nil
	}
	if pw := strings.TrimSpace(spec.Secret); pw != "" {
		methods = append(methods, ssh.Password(pw))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("需要密码或私钥（SessionSpec.Secret）")
	}
	return methods, nil
}

type tunnel struct {
	conn  net.Conn
	local string
}

func (t *tunnel) LocalAddr() string { return t.local }
func (t *tunnel) Close() error      { return t.conn.Close() }

type sessionReader struct {
	r    io.Reader
	sess *ssh.Session
}

func (s *sessionReader) Read(p []byte) (int, error) { return s.r.Read(p) }
func (s *sessionReader) Close() error               { return s.sess.Close() }
