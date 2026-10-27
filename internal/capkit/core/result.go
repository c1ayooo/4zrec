package core

import (
	"context"
	"encoding/json"
	"strings"
)

// This file implements the agent-facing output contract (see
// docs/究极渗透能力包实现方案.md §5.5). A tool never returns bare data: it
// returns a Result envelope with a fixed Status, a short Summary, a bounded
// Data payload, normalized Findings, evidence references, suggested Next
// actions and Meta. Agents decide what to do next from the envelope alone.

// Status is the six-state outcome of a tool call. Six states exist because an
// agent's reaction differs per state: blocked means change target or request
// authorization, need_human means suspend for a human, unavailable means report
// an environment problem. Collapsing these into OK=false makes agents retry
// blindly and loop against scope checks.
type Status string

const (
	StatusSuccess     Status = "success"     // completed, no risk
	StatusPartial     Status = "partial"     // partly done (e.g. some targets timed out)
	StatusFailed      Status = "failed"      // failed, possibly retryable
	StatusBlocked     Status = "blocked"     // stopped by a gate: scope / approval / ratelimit
	StatusNeedHuman   Status = "need_human"  // high-risk action awaiting human confirmation
	StatusUnavailable Status = "unavailable" // dependency missing (e.g. nuclei not installed)
)

// Valid reports whether s is one of the six defined states.
func (s Status) Valid() bool {
	switch s {
	case StatusSuccess, StatusPartial, StatusFailed, StatusBlocked, StatusNeedHuman, StatusUnavailable:
		return true
	}
	return false
}

// Terminal reports whether the status is final (no polling needed).
func (s Status) Terminal() bool { return s != StatusPartial }

// StatusForError maps a stable error code to the agent-facing status. This is
// the single place the code->status mapping lives.
func StatusForError(e *Error) Status {
	if e == nil {
		return StatusSuccess
	}
	switch e.Code {
	case CodeScopeDenied, CodeApprovalRequired, CodeRateLimited:
		return StatusBlocked
	case CodeUnavailable, CodeToolMissing:
		return StatusUnavailable
	case CodeNeedHuman:
		return StatusNeedHuman
	}
	return StatusFailed
}

// NextStep is a suggested follow-up action. It is data, not a command: the
// agent (or host policy) decides whether to run it.
type NextStep struct {
	Tool          string          `json:"tool"`
	Reason        string          `json:"reason"`
	Preconditions []string        `json:"preconditions,omitempty"`
	Risk          Risk            `json:"risk,omitempty"`
	Params        json.RawMessage `json:"params,omitempty"`
}

// Finding is a normalized vulnerability conclusion. Fingerprint is a
// normalized target+kind+param+path key used to dedupe the same issue across
// sources such as nuclei, exploitkit and yuque templates.
type Finding struct {
	Target      Target   `json:"target"`
	Kind        string   `json:"kind"` // cmdi | sqli | ssti | lfi | ssrf | upload | deser | ...
	Fingerprint string   `json:"fingerprint,omitempty"`
	Confirmed   bool     `json:"confirmed"`
	Payload     string   `json:"payload,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Source      string   `json:"source,omitempty"` // nuclei | exploitkit | yuque-template | manual
}

// Page describes list pagination. List results exceeding 100 items must
// paginate and be resumed with Cursor.
type Page struct {
	Total   int    `json:"total"`
	Cursor  string `json:"cursor,omitempty"`
	HasMore bool   `json:"has_more"`
}

// EvidenceRef points at stored evidence. Full bodies never travel in Data;
// they live in the evidence store and are referenced by ID.
type EvidenceRef struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"` // http_exchange | file | command_output | scan_log
	Size    int    `json:"size"`
	SHA256  string `json:"sha256,omitempty"`
	Preview string `json:"preview,omitempty"` // <=200 chars
}

// JobRef references a long-running job. Operations over 30s return
// StatusPartial plus a JobRef and are polled with job_status.
type JobRef struct {
	JobID       string `json:"job_id"`
	PollAfterMS int    `json:"poll_after_ms"`
}

// Meta is the fixed envelope metadata. Requests lets an agent see how much of
// its request budget it just spent; GateTrace makes "why was it slow" visible.
type Meta struct {
	Tool       string   `json:"tool"`
	Version    string   `json:"version,omitempty"`
	DurationMS int64    `json:"duration_ms"`
	Requests   int      `json:"requests,omitempty"`
	Target     string   `json:"target,omitempty"`
	GateTrace  []string `json:"gate_trace,omitempty"`
	Cached     bool     `json:"cached,omitempty"`
}

// Planner turns one Finding into candidate next actions. Hosts and agents read
// the same suggestions. Kits contribute candidates; capkit defines only the
// contract (see docs §5.3).
type Planner interface {
	Suggest(ctx context.Context, f Finding) ([]NextStep, error)
}

// MaxSummaryRunes bounds Summary so an agent can read it directly.
const MaxSummaryRunes = 200

// MaxDataBytes is the single-call Data ceiling. Oversized payloads are
// truncated with Truncated=true and the real total reported in Page.Total.
const MaxDataBytes = 8 << 10

// MaxListItems is the list length above which results must paginate.
const MaxListItems = 100

// ClampSummary trims s to MaxSummaryRunes runes, appending an ellipsis.
func ClampSummary(s string) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= MaxSummaryRunes {
		return s
	}
	return strings.TrimSpace(string(r[:MaxSummaryRunes-1])) + "…"
}

// NewResult builds an envelope with the given status and summary.
func NewResult(status Status, summary string) Result {
	return Result{
		OK:      status == StatusSuccess || status == StatusPartial,
		Status:  status,
		Summary: ClampSummary(summary),
	}
}

// SuccessResult is a completed call carrying structured data.
func SuccessResult(summary string, data any) (Result, error) {
	res := NewResult(StatusSuccess, summary)
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return Result{}, err
		}
		res.Data = b
	}
	return res, nil
}

// PartialResult is a partly-completed call carrying structured data and,
// optionally, a job reference for polling.
func PartialResult(summary string, data any) (Result, error) {
	res, err := SuccessResult(summary, data)
	if err != nil {
		return Result{}, err
	}
	res.Status = StatusPartial
	return res, nil
}

// BlockedResult is a call stopped by a gate (scope/approval/ratelimit).
func BlockedResult(err *Error) Result {
	if err == nil {
		err = NewError(CodeScopeDenied, "blocked")
	}
	return Result{OK: false, Status: StatusBlocked, Summary: ClampSummary(err.Message), Error: err}
}

// Normalize completes the envelope fields a kit owns on every return path, so
// a tool cannot satisfy the contract on its happy path and violate it on an
// error path: it fills an unset Status from Error/OK, keeps OK consistent with
// Status, stamps Meta.Tool and Meta.Version, and clamps Summary.
//
// A kit calls it once, in its Call dispatcher, rather than at each return. It
// deliberately does not invent a Summary — a generic "完成" tells an agent
// nothing, so a missing Summary has to surface as a contract failure.
func (r Result) Normalize(tool, version string) Result {
	if !r.Status.Valid() {
		switch {
		case r.Error != nil:
			r.Status = StatusForError(r.Error)
		case r.OK:
			r.Status = StatusSuccess
		default:
			r.Status = StatusFailed
		}
	}
	r.OK = r.Status == StatusSuccess || r.Status == StatusPartial
	if r.Meta.Tool == "" {
		r.Meta.Tool = tool
	}
	if r.Meta.Version == "" {
		r.Meta.Version = version
	}
	r.Summary = ClampSummary(r.Summary)
	return r
}

// ClampData enforces the 8KB Data ceiling, replacing oversized payloads with a
// valid-JSON truncation marker. The real size of the dropped payload is
// reported in Page.Total so the agent knows how much it did not receive
// (docs §5.5.4).
func (r *Result) ClampData() {
	if len(r.Data) <= MaxDataBytes {
		return
	}
	original := len(r.Data)
	preview := r.Data
	if len(preview) > 4<<10 {
		preview = preview[:4<<10]
	}
	wrapped, err := json.Marshal(map[string]any{
		"_truncated":     true,
		"original_bytes": original,
		"preview":        string(preview),
	})
	if err != nil {
		return
	}
	r.Data = wrapped
	r.Truncated = true
	if r.Page == nil {
		r.Page = &Page{}
	}
	// The real total is the original payload size; keep any list total already
	// set by the tool (a list result reports item count, not bytes).
	if r.Page.Total == 0 {
		r.Page.Total = original
	}
}
