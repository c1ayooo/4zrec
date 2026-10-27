package cloud

import (
	"errors"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Reason is the normalized cloud failure, so an agent can tell "my key is
// wrong" from "my key lacks this permission" from "this region does not exist"
// without parsing vendor prose. The brief requires those to be distinguishable;
// vendor error codes differ per vendor, so each provider file maps its own
// codes into this set.
type Reason string

const (
	// ReasonInvalidCredential: the vendor rejected the AK/SK itself.
	ReasonInvalidCredential Reason = "invalid_credential"
	// ReasonPermissionDenied: the key is real but lacks the action's permission.
	ReasonPermissionDenied Reason = "permission_denied"
	// ReasonRegionInvalid: the region is unknown to the vendor or the endpoint.
	ReasonRegionInvalid Reason = "region_invalid"
	// ReasonInstanceNotRunning: the instance exists but is not in a state that
	// accepts a cloud-assistant command.
	ReasonInstanceNotRunning Reason = "instance_not_running"
	// ReasonNotFound: the named resource (instance, bucket) does not exist.
	ReasonNotFound Reason = "not_found"
	// ReasonThrottled: the vendor rate-limited the call.
	ReasonThrottled Reason = "throttled"
	// ReasonTimeout: the call did not finish in time.
	ReasonTimeout Reason = "timeout"
	// ReasonUnsupported: the vendor API has no equivalent for the request.
	ReasonUnsupported Reason = "unsupported"
	// ReasonUpstream: anything else the vendor returned.
	ReasonUpstream Reason = "upstream_error"
)

// Error is a classified vendor failure. It carries the raw vendor code for the
// developer and a masked AK for the agent; the secret never appears.
type Error struct {
	Reason   Reason
	Provider string
	Code     string // vendor error code, verbatim
	Message  string // vendor message, verbatim (already public to the caller)
	MaskedAK string // AK 前 4 + 后 4
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Code == "" {
		return string(e.Reason)
	}
	return string(e.Reason) + ": " + e.Code
}

// reasonLabels are the agent-facing phrases. The Summary is built from these,
// so a failed call still tells the agent what to do next.
var reasonLabels = map[Reason]string{
	ReasonInvalidCredential:  "凭据无效",
	ReasonPermissionDenied:   "权限不足",
	ReasonRegionInvalid:      "地域错误",
	ReasonInstanceNotRunning: "实例不在运行态",
	ReasonNotFound:           "资源不存在",
	ReasonThrottled:          "被限流",
	ReasonTimeout:            "请求超时",
	ReasonUnsupported:        "厂商不支持该能力",
	ReasonUpstream:           "云 API 调用失败",
}

// Label returns the agent-facing phrase for the reason.
func (r Reason) Label() string {
	if l, ok := reasonLabels[r]; ok {
		return l
	}
	return string(r)
}

// hints tell the agent how to fix its input (docs §5.5.3: Hint is the correction
// advice, not the diagnosis).
var hints = map[Reason]string{
	ReasonInvalidCredential:  "确认 access_key/secret_key 是否正确且未被禁用",
	ReasonPermissionDenied:   "该 AK 缺少所需权限，换用具备只读权限的凭据",
	ReasonRegionInvalid:      "region 不存在或与 endpoint 不匹配，改用该账号实际地域",
	ReasonInstanceNotRunning: "实例需处于 running 状态才能执行云助手命令",
	ReasonNotFound:           "确认实例/桶 ID 与地域是否正确",
	ReasonThrottled:          "降低调用频率后重试",
	ReasonTimeout:            "命令或列举超时，可缩减范围或延长 timeout_sec 后重试",
	ReasonUnsupported:        "该厂商 API 无对应能力，改用手工核查",
	ReasonUpstream:           "查看 detail 中的厂商错误码定位原因",
}

// capkitCodes maps a cloud reason onto the fixed capkit error enum (docs
// §5.5.3). The enum stays small; the cloud-specific distinction travels in the
// message and hint.
var capkitCodes = map[Reason]string{
	ReasonInvalidCredential:  core.CodeUpstreamError,
	ReasonPermissionDenied:   core.CodeUpstreamError,
	ReasonRegionInvalid:      core.CodeInvalidInput,
	ReasonInstanceNotRunning: core.CodeConflict,
	ReasonNotFound:           core.CodeNotFound,
	ReasonThrottled:          core.CodeRateLimited,
	ReasonTimeout:            core.CodeTimeout,
	ReasonUnsupported:        core.CodeToolMissing,
	ReasonUpstream:           core.CodeUpstreamError,
}

// AsCapkit renders the reason as a capkit error: a stable Code from the fixed
// enum, a one-line agent-readable message carrying the masked AK, a Hint that
// says how to fix the input, and the raw vendor code in Detail.
func (e *Error) AsCapkit() *core.Error {
	if e == nil {
		return nil
	}
	code := capkitCodes[e.Reason]
	if code == "" {
		code = core.CodeUpstreamError
	}
	msg := e.Reason.Label()
	if e.Provider != "" {
		msg += "（" + e.Provider
		if e.MaskedAK != "" {
			msg += " AK " + e.MaskedAK
		}
		msg += "）"
	}
	if e.Message != "" {
		msg += "：" + core.Truncate(e.Message, 120)
	}
	err := core.NewError(code, msg)
	err.Hint = hints[e.Reason]
	err.Detail = e.Provider + " " + e.Code
	switch e.Reason {
	case ReasonThrottled, ReasonTimeout, ReasonUpstream:
		err.Retryable = true
	}
	return err
}

// AsResult wraps the failure in a Result envelope.
func (e *Error) AsResult() core.Result {
	return core.FailResult(e.AsCapkit())
}

// reasonFor scans a vendor error code against a per-vendor code table, then
// falls back to a case-insensitive message match. Vendor tables list only codes
// the vendors document; the message fallback keeps an undocumented code from
// landing in reason_upstream when it clearly says "throttling".
func reasonFor(code, message string, codes map[string]Reason, fallback []matchRule) Reason {
	if r, ok := codes[code]; ok {
		return r
	}
	// Vendor codes are dots/camel-case; compare case-insensitively too.
	for k, r := range codes {
		if strings.EqualFold(k, code) {
			return r
		}
	}
	hay := strings.ToLower(code + " " + message)
	for _, rule := range fallback {
		if strings.Contains(hay, rule.contains) {
			return rule.reason
		}
	}
	return ReasonUpstream
}

// matchRule is one substring fallback for reasonFor.
type matchRule struct {
	contains string
	reason   Reason
}

// maskAK masks an access key id for display: first 4 and last 4 characters,
// middle starred. Anything short enough that masking would leak the whole key is
// replaced entirely.
func maskAK(ak string) string {
	ak = strings.TrimSpace(ak)
	if ak == "" {
		return ""
	}
	if len(ak) <= 8 {
		return strings.Repeat("*", len(ak))
	}
	return ak[:4] + "****" + ak[len(ak)-4:]
}

// asCapkitError unwraps err to a *core.Error when the failure came from
// capkit itself rather than the vendor: the host's HTTP port returns
// scope_denied / rate_limited / timeout atoms, and those must survive to the
// agent instead of being reclassified as an upstream cloud failure.
func asCapkitError(err error) *core.Error {
	var ce *core.Error
	if errors.As(err, &ce) {
		return ce
	}
	return nil
}

// describe wraps a vendor error into a classified *Error. A *Error passes
// through unchanged; everything else becomes reason_upstream.
func describe(provider, maskedAK string, err error) *Error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		if e.Provider == "" {
			e.Provider = provider
		}
		if e.MaskedAK == "" {
			e.MaskedAK = maskedAK
		}
		return e
	}
	return &Error{Reason: ReasonUpstream, Provider: provider, Message: err.Error(), MaskedAK: maskedAK}
}

// newError builds a classified error with the vendor code.
func newError(reason Reason, provider, code, message, maskedAK string) *Error {
	return &Error{Reason: reason, Provider: provider, Code: code, Message: message, MaskedAK: maskedAK}
}

// unsupported is the explicit "this vendor API has no equivalent" error, used
// instead of silently returning an empty list.
func unsupported(provider, what string) *Error {
	return &Error{Reason: ReasonUnsupported, Provider: provider, Code: "unsupported", Message: what}
}

// notFound is the explicit "the resource is not there" error.
func notFound(provider, what string) *Error {
	return &Error{Reason: ReasonNotFound, Provider: provider, Code: "not_found", Message: what}
}

// invalidInput builds a bad_input failure for a request the vendor API cannot
// express (missing region, missing bucket, ...).
func invalidInput(provider, message string) *core.Error {
	e := core.InvalidInput(message)
	if provider != "" {
		e.Detail = provider
	}
	return e
}

// requireAK is the precondition every tool shares.
func requireAK(provider, ak, sk string) *core.Error {
	if strings.TrimSpace(ak) == "" || strings.TrimSpace(sk) == "" {
		e := core.InvalidInput("access_key 与 secret_key 必填")
		e.Detail = provider
		return e
	}
	return nil
}

// fmtReason is a small helper for building messages.
func fmtReason(r Reason, format string, args ...any) string {
	return r.Label() + "：" + fmt.Sprintf(format, args...)
}
