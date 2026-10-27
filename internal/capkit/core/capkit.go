// Package capkit defines the platform-independent contracts for reusable
// security capabilities.
//
// The host owns policy: scope, approval, evidence, storage, secrets, audit and
// rate limiting are injected as ports. Capability kits only depend on this
// package, never on each other or on a host project.
package core

import (
	"context"
	"encoding/json"
)

// Capability is one self-contained capability (http, nuclei, shell, ...).
// Implementations must be safe for concurrent Call invocations.
type Capability interface {
	Manifest() Manifest
	Call(ctx context.Context, call Call) (Result, error)
}

// Call is one tool invocation routed by the runtime.
type Call struct {
	Tool    string
	Input   json.RawMessage
	Context CallContext
}

// CallContext carries the caller identity and task context. It never carries
// raw credentials; secrets are passed through the Sealer/HTTP ports.
type CallContext struct {
	TraceID   string `json:"trace_id,omitempty"`
	ProjectID int64  `json:"project_id,omitempty"`
	TaskID    string `json:"task_id,omitempty"`
	Actor     string `json:"actor,omitempty"`
	DryRun    bool   `json:"dry_run,omitempty"`
}

// Result is the structured outcome of a tool call. The envelope is the
// contract agents rely on: Status says what happened, Summary is readable in
// <=200 chars, Data is a bounded schema-constrained payload, Findings are
// normalized conclusions, Evidence holds references (never inline bodies),
// Next lists suggested follow-ups, Meta carries timing/budget trace.
//
// OK stays for wire compatibility with hosts written against earlier versions;
// it is derived from Status (success/partial => true) and never read for
// decisions on its own.
type Result struct {
	OK        bool            `json:"ok"`
	Status    Status          `json:"status,omitempty"`
	Summary   string          `json:"summary,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Findings  []Finding       `json:"findings,omitempty"`
	Evidence  []EvidenceRef   `json:"evidence,omitempty"`
	Next      []NextStep      `json:"next,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
	Page      *Page           `json:"page,omitempty"`
	Error     *Error          `json:"error,omitempty"`
	Meta      Meta            `json:"meta"`

	// Text is a legacy human-readable convenience retained for compatibility.
	Text string `json:"text,omitempty"`
	// EvidenceIDs are the evidence-store IDs of recorded Evidence entries,
	// mirrored here for hosts written against earlier versions.
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

// TextResult is a convenience for human/agent-readable output.
func TextResult(text string) Result {
	return Result{OK: true, Status: StatusSuccess, Summary: ClampSummary(text), Text: text}
}

// DataResult is a convenience for structured output.
func DataResult(v any) (Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return Result{}, err
	}
	return Result{OK: true, Status: StatusSuccess, Data: b}, nil
}

// FailResult wraps an error into a Result, mapping the error code to a Status.
func FailResult(err error) Result {
	e := AsError(err)
	return Result{
		OK:      false,
		Status:  StatusForError(e),
		Summary: ClampSummary(e.Message),
		Error:   e,
	}
}
