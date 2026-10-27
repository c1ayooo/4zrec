package core

import "errors"

// Error is the stable error shape crossing the capability boundary. Hosts map
// Code to HTTP status / agent error text without parsing messages. The Code
// set is a fixed enum — never free text (see docs §5.5.3).
type Error struct {
	Code         string `json:"code"`
	Message      string `json:"message"`
	Retryable    bool   `json:"retryable,omitempty"`
	RetryAfterMS int    `json:"retry_after_ms,omitempty"`
	Hint         string `json:"hint,omitempty"`   // how the agent should fix its input
	Detail       string `json:"detail,omitempty"` // for developers, never fed to the LLM
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

const (
	CodeInvalidInput        = "bad_input"
	CodeScopeDenied         = "scope_denied"
	CodeApprovalRequired    = "approval_required"
	CodeNotFound            = "not_found"
	CodeConflict            = "conflict"
	CodeRateLimited         = "rate_limited"
	CodeUnavailable         = "unavailable"
	CodeInternal            = "internal"
	CodeNeedHuman           = "need_human"
	CodeToolMissing         = "tool_missing"
	CodeTargetUnreachable   = "target_unreachable"
	CodeTimeout             = "timeout"
	CodeUpstreamError       = "upstream_error"
	CodeEvidenceWriteFailed = "evidence_write_failed"
)

func NewError(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

func InvalidInput(msg string) *Error { return NewError(CodeInvalidInput, msg) }
func ScopeDenied(msg string) *Error  { return NewError(CodeScopeDenied, msg) }
func NotFound(msg string) *Error     { return NewError(CodeNotFound, msg) }
func Conflict(msg string) *Error     { return NewError(CodeConflict, msg) }
func Unavailable(msg string) *Error {
	return &Error{Code: CodeUnavailable, Message: msg, Retryable: true}
}
func NeedHuman(msg string) *Error {
	return &Error{Code: CodeNeedHuman, Message: msg, Retryable: false}
}
func ToolMissing(msg string) *Error {
	return &Error{Code: CodeToolMissing, Message: msg, Retryable: false}
}
func TargetUnreachable(msg string) *Error {
	return &Error{Code: CodeTargetUnreachable, Message: msg, Retryable: true}
}
func Timeout(msg string) *Error {
	return &Error{Code: CodeTimeout, Message: msg, Retryable: true}
}
func UpstreamError(msg string) *Error {
	return &Error{Code: CodeUpstreamError, Message: msg, Retryable: true}
}
func EvidenceWriteFailed(msg string) *Error {
	return &Error{Code: CodeEvidenceWriteFailed, Message: msg, Retryable: true}
}

// AsError converts any error into the stable wire shape.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return NewError(CodeInternal, err.Error())
}
