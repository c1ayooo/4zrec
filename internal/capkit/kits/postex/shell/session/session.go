// Package session defines an already-established WebShell session and the
// host-provided executor. This module intentionally ships no default
// executor: the host must implement the actual command/file operation.
package session

import "context"

// Session is a registered, ready-to-use WebShell. Password handling (sealing,
// storage) belongs to the host.
type Session struct {
	ID           int64
	ProjectID    int64
	URL          string
	ShellType    string
	Method       string
	CmdParam     string
	PassParam    string
	Protocol     string
	ParamChannel string
	Encoding     string
	ProxyURL     string
	Password     string
}

type ExecResult struct {
	Output     string
	HTTPStatus int
	TrafficID  string
	// Encoding declares how Output carries a file body on File reads: "base64"
	// when Output is base64 of the file, anything else (including "") when it is
	// the file itself. The adapter does not guess, because a plain-text body such
	// as "abcdefgh" is also a legal base64 string and sniffing it would silently
	// return 6 bytes of garbage instead of the file.
	Encoding string
}

type FileOp struct {
	Action  string // read | list | write | upload | download | delete
	Path    string
	Content []byte
}

// Executor is the host boundary for command/file operations. Implementations
// must enforce scope, approval and evidence in the host.
type Executor interface {
	Exec(ctx context.Context, session Session, command string) (*ExecResult, error)
	File(ctx context.Context, session Session, op FileOp) (*ExecResult, error)
}
