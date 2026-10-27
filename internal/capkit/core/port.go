package core

import (
	"context"
	"encoding/json"
	"time"
)

// ---- policy ports ----

// ScopeChecker is the authorization boundary. Implementations must fail
// closed: an unknown/unparseable target is denied.
type ScopeChecker interface {
	Check(ctx context.Context, target Target) error
}

// ApprovalRequest is presented to the host before a risky tool runs.
type ApprovalRequest struct {
	Capability string
	Tool       string
	Risk       Risk
	Targets    []Target
	Actor      string
	ProjectID  int64
}

// Approver is the human/automated approval gate. The runtime requires it for
// high-risk tools; returning an error denies the call.
type Approver interface {
	Require(ctx context.Context, req ApprovalRequest) error
}

// ---- evidence ----

// Evidence is a portable evidence record. The host decides where to store it
// (traffic store, object store, DB) and returns its stable ID.
type Evidence struct {
	Kind      string            `json:"kind"`
	Title     string            `json:"title"`
	Target    Target            `json:"target"`
	Request   []byte            `json:"request,omitempty"`
	Response  []byte            `json:"response,omitempty"`
	Data      json.RawMessage   `json:"data,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

type EvidenceSink interface {
	Record(ctx context.Context, ev Evidence) (id string, err error)
}

// ---- transport ----

type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
	Proxy   string            `json:"proxy,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`
}

type Response struct {
	Status      int                 `json:"status"`
	Headers     map[string][]string `json:"headers,omitempty"`
	Body        []byte              `json:"body,omitempty"`
	Duration    time.Duration       `json:"duration"`
	FinalURL    string              `json:"final_url,omitempty"`
	RequestText string              `json:"request_text,omitempty"`
	RespText    string              `json:"response_text,omitempty"`
}

// HTTPDoer is the only HTTP client a kit may use. The host injects a
// gate-aware implementation that enforces scope, rate limits and audit.
type HTTPDoer interface {
	Do(ctx context.Context, req Request) (*Response, error)
}

// Fetcher is the external-data fetch port: rule updates, GitHub search, threat
// intel and other non-target-scoped downloads. The host still applies proxy,
// timeout, rate limit and audit policy, but not project target scope.
type Fetcher interface {
	Fetch(ctx context.Context, req Request) (*Response, error)
}

// ---- rate limiting ----

type Limiter interface {
	Acquire(ctx context.Context, key string, spec RateLimitSpec) (release func(), err error)
}

// ---- audit ----

type AuditEvent struct {
	TraceID     string    `json:"trace_id"`
	Actor       string    `json:"actor"`
	ProjectID   int64     `json:"project_id"`
	TaskID      string    `json:"task_id,omitempty"`
	Capability  string    `json:"capability"`
	Tool        string    `json:"tool"`
	Risk        Risk      `json:"risk"`
	Targets     []Target  `json:"targets,omitempty"`
	Phase       string    `json:"phase"` // start | finish
	Status      string    `json:"status,omitempty"`
	Error       string    `json:"error,omitempty"`
	InputHash   string    `json:"input_hash,omitempty"`
	DurationMS  int64     `json:"duration_ms,omitempty"`
	EvidenceIDs []string  `json:"evidence_ids,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at,omitempty"`
}

type AuditSink interface {
	Record(ctx context.Context, ev AuditEvent)
}

// ---- settings / secrets ----

type Settings interface {
	GetString(ctx context.Context, key string) (string, bool)
	GetBool(ctx context.Context, key string) (bool, bool)
	GetInt(ctx context.Context, key string) (int64, bool)
}

// Sealer protects secrets at rest. Implementations should use AEAD and a host
// managed key; kits never see plaintext storage details.
type Sealer interface {
	Seal(plain string) (string, error)
	Open(sealed string) (string, error)
}

// ---- support ----

type Logger interface {
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

type Clock interface {
	Now() time.Time
}

type IDGenerator interface {
	New(prefix string) string
}

// ---- process execution ----

type ProcessSpec struct {
	Path      string
	Args      []string
	Env       []string
	Dir       string
	Timeout   time.Duration
	Stdin     []byte
	Targets   []Target
	RateLimit RateLimitSpec
}

type ProcessResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// ProcessRunner is the only way a kit may spawn a subprocess. The host
// injects a gate-aware implementation (scope/rate/audit/env policy).
type ProcessRunner interface {
	Run(ctx context.Context, spec ProcessSpec) (*ProcessResult, error)
}

// ---- vulnerability intel ----

// IntelItem is one advisory published by a public vulnerability-intel source.
// The kit owns the protocol; the host owns the schema and the dedup policy,
// so the only key the kit guarantees is UniqueKey (stable per source).
type IntelItem struct {
	ID          string   `json:"id,omitempty"`
	Source      string   `json:"source,omitempty"`
	UniqueKey   string   `json:"unique_key"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	Disclosure  string   `json:"disclosure,omitempty"`
	Solutions   string   `json:"solutions,omitempty"`
	SourceURL   string   `json:"source_url,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
}

// IntelQuery filters the host's intel store. Empty fields do not filter.
type IntelQuery struct {
	Text     string `json:"text,omitempty"`
	CVE      string `json:"cve,omitempty"`
	Severity string `json:"severity,omitempty"`
	Source   string `json:"source,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
}

// IntelStore is the host-owned persistence for vulnerability intel. Kits
// never open a database: they hand the host normalized items and the host
// decides how to store, dedupe and version them.
//
// Upsert is idempotent by UniqueKey. It returns the stored record id and
// whether it was newly created, so a polling kit can report real deltas
// instead of a raw insert count.
type IntelStore interface {
	Upsert(ctx context.Context, item IntelItem) (id string, created bool, err error)
	Query(ctx context.Context, q IntelQuery) ([]IntelItem, error)
	Get(ctx context.Context, id string) (*IntelItem, error)
}

// Completer is the host-provided single-shot text completion port. Kits hold
// no model credentials and import no provider SDK: the host maps a request to
// whichever profile is active and applies its own temperature and token
// budget. A nil Completer means the host has no model configured, and every
// generation tool reports "unavailable" instead of failing silently.
type Completer interface {
	Complete(ctx context.Context, system, user string, maxTokens int) (string, error)
}

// IntelSource is an advisory source the host contributes to the intel kit's
// poll loop.
//
// It exists because some sources cannot be fetched with a plain HTTP client:
// they answer every request with an anti-automation page that only a JS
// runtime can turn into a real URL. Solving that needs a JavaScript engine,
// which is the wrong dependency for this library — so the host implements the
// source with whatever it already ships, and the kit polls it alongside its
// own sources through the same store and dedup path.
//
// Implementations must return normalized items with a stable UniqueKey and a
// non-empty Source. A failure is reported per source, never as a failed poll.
type IntelSource interface {
	Name() string
	Fetch(ctx context.Context, limit int) ([]IntelItem, error)
}

// ---- artifacts / binaries ----

type ArtifactStore interface {
	Put(ctx context.Context, name string, data []byte) (path string, err error)
	Get(ctx context.Context, path string) ([]byte, error)
	Delete(ctx context.Context, path string) error
}

type BinaryStatus struct {
	Installed bool      `json:"installed"`
	Version   string    `json:"version"`
	Path      string    `json:"path"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type BinaryManager interface {
	Ensure(ctx context.Context, name, version string) (path string, status BinaryStatus, err error)
	Update(ctx context.Context, name, version string) (BinaryStatus, error)
	Status(ctx context.Context, name string) (BinaryStatus, error)
}
