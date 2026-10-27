// adapter.go bridges the WebShell model (Session + host Executor) to the
// core.Session contract, so a WebShell foothold gets the same Exec/upload/
// download surface as SSH and every downstream kit works against it unchanged.
package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// CapabilitySession wraps a WebShell Session plus its host Executor into a
// core.Session.
type CapabilitySession struct {
	Shell    Session
	Executor Executor
}

// Info describes the foothold without performing I/O.
func (c *CapabilitySession) Info() core.SessionInfo {
	host := ""
	if u, err := url.Parse(c.Shell.URL); err == nil {
		host = u.Hostname()
	}
	kind := "webshell"
	labels := []string{}
	if c.Shell.ShellType != "" {
		labels = append(labels, c.Shell.ShellType)
	}
	return core.SessionInfo{
		ID: c.shellID(), Kind: kind, Host: host, User: "",
		Labels: labels,
		Meta: map[string]string{
			"url": c.Shell.URL, "protocol": c.Shell.Protocol,
			"shell_type": c.Shell.ShellType, "encoding": c.Shell.Encoding,
		},
	}
}

func (c *CapabilitySession) shellID() string {
	if c.Shell.ID != 0 {
		return fmt.Sprintf("webshell-%d", c.Shell.ID)
	}
	return ""
}

// Close is a no-op: a WebShell has no connection to tear down.
func (c *CapabilitySession) Close() error { return nil }

// Exec runs a command through the WebShell executor.
func (c *CapabilitySession) Exec(ctx context.Context, cmd string, opts core.ExecOpts) (core.Output, error) {
	if c.Executor == nil {
		return core.Output{}, fmt.Errorf("WebShell Executor 未注入")
	}
	if strings.TrimSpace(cmd) == "" {
		return core.Output{}, fmt.Errorf("命令为空")
	}
	if opts.Dir != "" {
		cmd = "cd " + core.ShellQuote(opts.Dir) + " && " + cmd
	}
	res, err := c.Executor.Exec(ctx, c.Shell, cmd)
	if err != nil {
		return core.Output{}, err
	}
	out := core.Output{Command: cmd, Stdout: res.Output, ExitCode: 0, EvidenceID: res.TrafficID}
	if res.HTTPStatus >= 400 {
		out.ExitCode = 1
	}
	if opts.MaxOutput > 0 && len(out.Stdout) > opts.MaxOutput {
		out.Stdout, out.Truncated = out.Stdout[:opts.MaxOutput], true
	}
	return out, nil
}

// Upload writes bytes to the remote path via the WebShell file channel.
func (c *CapabilitySession) Upload(ctx context.Context, src io.Reader, remote string) error {
	if c.Executor == nil {
		return fmt.Errorf("WebShell Executor 未注入")
	}
	if strings.TrimSpace(remote) == "" {
		return fmt.Errorf("remote 路径必填")
	}
	data, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	_, err = c.Executor.File(ctx, c.Shell, FileOp{Action: "write", Path: remote, Content: data})
	return err
}

// Download reads a remote path through the WebShell file channel.
func (c *CapabilitySession) Download(ctx context.Context, remote string) (io.ReadCloser, error) {
	if c.Executor == nil {
		return nil, fmt.Errorf("WebShell Executor 未注入")
	}
	res, err := c.Executor.File(ctx, c.Shell, FileOp{Action: "read", Path: remote})
	if err != nil {
		return nil, err
	}
	data := []byte(res.Output)
	// Some WebShell protocols base64 file content; the executor declares it with
	// ExecResult.Encoding. Guessing is not an option: a plain-text body such as
	// "abcdefgh" is also a legal base64 string, so a sniff would silently return
	// 6 bytes of garbage instead of the file.
	if strings.EqualFold(res.Encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(res.Output))
		if err != nil {
			return nil, fmt.Errorf("对端声明 base64 但内容解码失败：%w", err)
		}
		data = decoded
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
