// ssh.go implements read-only SSH credential verification: authenticate with
// x/crypto/ssh, then run id and sudo -n true to probe the permission surface
// (login / groups / passwordless sudo). No write operation is performed.
package cred

import (
	"context"
	"fmt"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHProbeInput is one SSH credential verification request.
type SSHProbeInput struct {
	Host       string
	Port       int // 0 = 22
	Username   string
	Password   string // either this or Key
	PrivateKey string // PEM private key (optional)
	Timeout    time.Duration
}

// SSHProbeResult is the live-connection conclusion: liveness + auth + surface.
type SSHProbeResult struct {
	Alive    bool   `json:"alive"`     // TCP/SSH banner reachable
	Authed   bool   `json:"authed"`    // credential accepted
	User     string `json:"user"`      // id -un after login
	Groups   string `json:"groups"`    // id output summary
	SudoNOPW bool   `json:"sudo_nopw"` // sudo -n true succeeded (high risk)
	Banner   string `json:"banner,omitempty"`
	Detail   string `json:"detail"`
}

// VerifySSH performs live verification. Invalid credentials / unreachable
// network return an explicit Detail.
func VerifySSH(ctx context.Context, in SSHProbeInput) (*SSHProbeResult, error) {
	if strings.TrimSpace(in.Host) == "" || strings.TrimSpace(in.Username) == "" {
		return nil, fmt.Errorf("host 与 username 必填")
	}
	if in.Port <= 0 {
		in.Port = 22
	}
	timeout := in.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	addr := net.JoinHostPort(in.Host, strconv.Itoa(in.Port))

	var authMethods []ssh.AuthMethod
	if strings.TrimSpace(in.PrivateKey) != "" {
		key, err := ssh.ParsePrivateKey([]byte(in.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("私钥解析失败: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(key))
	}
	if in.Password != "" {
		authMethods = append(authMethods, ssh.Password(in.Password))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("password 与 private_key 至少提供一项")
	}

	cfg := &ssh.ClientConfig{
		User:            in.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // credential test: no host key pinning
		Timeout:         timeout,
		BannerCallback:  func(string) error { return nil },
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &SSHProbeResult{Alive: false, Detail: fmt.Sprintf("端口不通: %v", err)}, nil
	}
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		// Distinguish "reachable but auth failed" from "not an SSH service".
		detail := fmt.Sprintf("认证失败或握手异常: %v", err)
		alive := true
		if strings.Contains(err.Error(), "unable to read") || strings.Contains(err.Error(), "connection reset") {
			alive = false
			detail = "握手失败(可能不是 SSH 服务): " + err.Error()
		}
		return &SSHProbeResult{Alive: alive, Detail: detail}, nil
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	res := &SSHProbeResult{Alive: true, Authed: true, Banner: strings.TrimSpace(string(sshConn.ServerVersion()))}
	if out, err := runSSHCommand(ctx, client, "id", 5*time.Second); err == nil {
		idLine := strings.TrimSpace(out)
		res.Groups = core.Truncate(idLine, 300)
		if parts := strings.Fields(idLine); len(parts) > 0 {
			res.User = strings.TrimPrefix(parts[0], "uid=")
		}
	}
	if out, err := runSSHCommand(ctx, client, "sudo -n true 2>/dev/null && echo SUDO_OK", 5*time.Second); err == nil && strings.Contains(out, "SUDO_OK") {
		res.SudoNOPW = true
	}
	res.Detail = fmt.Sprintf("登录成功:%s@%s", in.Username, addr)
	if res.SudoNOPW {
		res.Detail += ",免密 sudo(高危)"
	}
	return res, nil
}

func runSSHCommand(ctx context.Context, client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	done := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		out, err := sess.Output(cmd)
		if err != nil {
			errCh <- err
			return
		}
		done <- string(out)
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case out := <-done:
		return out, nil
	case err := <-errCh:
		return "", err
	case <-time.After(timeout):
		return "", fmt.Errorf("命令超时: %s", cmd)
	}
}
