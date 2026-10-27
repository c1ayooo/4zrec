package core

import (
	"context"
	"io"
	"time"
)

// This file defines the post-exploitation root contract (see docs §5.1).
// A Session is an established foothold on a target (WebShell, SSH, WinRM, SMB,
// a local CLI, a C2 implant). Everything downstream — privilege escalation,
// lateral movement, persistence, cleanup, internal recon — is written against
// Session, so a new transport only has to implement three methods.

// Session is one established, ready-to-use foothold. Implementations must be
// safe for concurrent Exec calls unless Info reports otherwise.
type Session interface {
	Exec(ctx context.Context, cmd string, opts ExecOpts) (Output, error)
	Info() SessionInfo
	Close() error
}

// ExecOpts tunes one command. Zero values mean "host default".
type ExecOpts struct {
	Timeout    time.Duration     `json:"timeout,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Dir        string            `json:"dir,omitempty"`
	Stdin      []byte            `json:"stdin,omitempty"`
	Shell      string            `json:"shell,omitempty"` // sh | bash | cmd | powershell
	TTY        bool              `json:"tty,omitempty"`
	MaxOutput  int               `json:"max_output,omitempty"` // bytes; host default if 0
	Background bool              `json:"background,omitempty"`
}

// Output is the result of one command.
type Output struct {
	Command    string `json:"command"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
	Truncated  bool   `json:"truncated,omitempty"`
	// EvidenceID references the stored raw exchange when the host recorded one.
	EvidenceID string `json:"evidence_id,omitempty"`
}

// SessionInfo describes the foothold without performing I/O.
type SessionInfo struct {
	ID       string            `json:"id"`
	Kind     string            `json:"kind"` // ssh | winrm | smb | webshell | cli | c2
	Host     string            `json:"host,omitempty"`
	Port     int               `json:"port,omitempty"`
	User     string            `json:"user,omitempty"`
	OS       string            `json:"os,omitempty"` // linux | windows
	Arch     string            `json:"arch,omitempty"`
	Elevated bool              `json:"elevated,omitempty"`
	Labels   []string          `json:"labels,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// --- optional capabilities: probe with a type assertion and fall back to
// Exec + base64 when unsupported (docs §5.1) ---

// Uploader writes a stream to a remote path.
type Uploader interface {
	Upload(ctx context.Context, src io.Reader, remote string) error
}

// Downloader reads a remote path.
type Downloader interface {
	Download(ctx context.Context, remote string) (io.ReadCloser, error)
}

// Tunneler opens a network tunnel through the foothold.
type Tunneler interface {
	Tunnel(ctx context.Context, spec TunnelSpec) (Tunnel, error)
}

// TunnelSpec describes the tunnel a caller wants.
type TunnelSpec struct {
	Kind       string `json:"kind"` // local | remote | socks
	LocalAddr  string `json:"local_addr,omitempty"`
	RemoteAddr string `json:"remote_addr"`
	Network    string `json:"network,omitempty"` // tcp (default) | udp
}

// Tunnel is a live tunnel. Callers must Close it.
type Tunnel interface {
	LocalAddr() string
	Close() error
}

// SessionOpener opens a new Session from a spec. Adapters (SSH, WinRM, SMB,
// CLI, WebShell) implement it; hosts register openers and let agents pick one.
type SessionOpener interface {
	Open(ctx context.Context, spec SessionSpec) (Session, error)
}

// SessionManager is the host-facing port that owns live footholds: it opens
// sessions through the registered opener for a kind, tracks them by ID, and
// closes them. Kits (shellkit's session tools, privesc/lat/persist/cleanup)
// depend only on this port, never on a concrete transport.
type SessionManager interface {
	Open(ctx context.Context, spec SessionSpec) (SessionInfo, error)
	Get(id string) (Session, bool)
	List() []SessionInfo
	Close(id string) error
}

// SessionSpec is a transport-neutral request for a foothold. Secret is passed
// in cleartext here because the host resolves it from the Sealer at the edge;
// kits never persist it.
type SessionSpec struct {
	Kind     string            `json:"kind"` // ssh | winrm | smb | cli | webshell
	Host     string            `json:"host"`
	Port     int               `json:"port,omitempty"`
	User     string            `json:"user,omitempty"`
	Secret   string            `json:"secret,omitempty"` // password or private key
	KeyPass  string            `json:"key_pass,omitempty"`
	Domain   string            `json:"domain,omitempty"`
	Protocol string            `json:"protocol,omitempty"`
	ProxyURL string            `json:"proxy,omitempty"`
	Timeout  time.Duration     `json:"timeout,omitempty"`
	Labels   []string          `json:"labels,omitempty"`
	Options  map[string]string `json:"options,omitempty"`
}

// OutputFor builds an Output with a bounded stdout/stderr, marking Truncated.
func OutputFor(cmd, stdout, stderr string, exit int, dur time.Duration, max int) Output {
	out := Output{Command: cmd, Stdout: stdout, Stderr: stderr, ExitCode: exit, DurationMS: dur.Milliseconds()}
	if max > 0 {
		if len(out.Stdout) > max {
			out.Stdout, out.Truncated = out.Stdout[:max], true
		}
		if len(out.Stderr) > max {
			out.Stderr, out.Truncated = out.Stderr[:max], true
		}
	}
	return out
}

// ShellQuote quotes s for POSIX shells when it contains shell metacharacters.
// Adapters that build a remote command line should use this; adapters that
// stream arguments directly (execve over SSH) must not.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == '=' || r == '@' || r == ',') {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + replaceAll(s, "'", `'\''`) + "'"
}

func replaceAll(s, old, new string) string {
	if old == "" {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			out = append(out, new...)
			i += len(old)
			continue
		}
		out = append(out, s[i])
		i++
	}
	return string(out)
}
