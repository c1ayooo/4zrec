// Package harness provides scripted fakes for every capkit port. Contract
// tests instantiate a kit with these fakes so a tool call runs hermetically:
// no network, no subprocess, no wall clock. Each fake records what it was
// asked to do, so a test can assert on the request as well as the result.
//
// The fakes satisfy the capkit interfaces structurally; this package therefore
// imports only the root contract and never a kit.
package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// DefaultTime is the clock origin every fixture uses, so signature and
// timestamp assertions are reproducible.
var DefaultTime = time.Date(2024, 5, 26, 12, 0, 0, 0, time.UTC)

// ───────────────────────────── transport ─────────────────────────────

// Route is one scripted HTTP answer. When Match is non-empty only requests
// whose URL contains it take this route; otherwise it is the fallback.
type Route struct {
	Match   string
	Status  int
	Body    string
	Headers map[string][]string
	Err     error
}

// HTTP is a scripted core.HTTPDoer and core.Fetcher. It answers from a
// route table, falling back to the default response, and records every request
// in call order.
type HTTP struct {
	// Default answers any request no route matches.
	Default Route
	// Routes are checked in order before Default.
	Routes []Route
	// Queue answers the first len(Queue) calls in order, before Routes and
	// Default apply, and is consumed as it is used. It exists for protocol-level
	// sequences a route table cannot express — "the invocation does not exist
	// yet on the first poll, succeeds on the second" — where the answer depends
	// on how many calls came before rather than on the request itself.
	Queue []Route
	// Err fails every call regardless of routes.
	Err error

	mu       sync.Mutex
	requests []core.Request
}

// NewHTTP builds a fake transport answering every request with status/body.
func NewHTTP(status int, body string) *HTTP {
	return &HTTP{Default: Route{Status: status, Body: body}}
}

// NewHTTPJSON answers every request with a JSON body.
func NewHTTPJSON(body string) *HTTP { return NewHTTP(200, body) }

func (h *HTTP) Do(ctx context.Context, req core.Request) (*core.Response, error) {
	return h.respond(ctx, req)
}

func (h *HTTP) Fetch(ctx context.Context, req core.Request) (*core.Response, error) {
	return h.respond(ctx, req)
}

func (h *HTTP) respond(_ context.Context, req core.Request) (*core.Response, error) {
	h.mu.Lock()
	h.requests = append(h.requests, req)
	var route Route
	queued := false
	if len(h.Queue) > 0 {
		route, h.Queue = h.Queue[0], h.Queue[1:]
		queued = true
	}
	h.mu.Unlock()
	if h.Err != nil {
		return nil, h.Err
	}
	if !queued {
		route = h.Default
		for _, r := range h.Routes {
			if r.Match != "" && strings.Contains(req.URL, r.Match) {
				route = r
				break
			}
		}
	}
	if route.Err != nil {
		return nil, route.Err
	}
	status := route.Status
	if status == 0 {
		status = 200
	}
	return &core.Response{
		Status:   status,
		Body:     []byte(route.Body),
		Headers:  route.Headers,
		Duration: time.Millisecond,
		FinalURL: req.URL,
	}, nil
}

// Requests returns a copy of every request the fake received.
func (h *HTTP) Requests() []core.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]core.Request(nil), h.requests...)
}

// Calls is the number of requests the fake received.
func (h *HTTP) Calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.requests)
}

// Last returns the most recent request.
func (h *HTTP) Last() (core.Request, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.requests) == 0 {
		return core.Request{}, false
	}
	return h.requests[len(h.requests)-1], true
}

// ───────────────────────────── process ─────────────────────────────

// Process is a scripted core.ProcessRunner: every Run returns the preset
// stdout/stderr/exit code and records the spec.
type Process struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
	// Handler, when set, overrides the preset and answers per spec.
	Handler func(core.ProcessSpec) (*core.ProcessResult, error)

	mu    sync.Mutex
	calls []core.ProcessSpec
}

func (p *Process) Run(_ context.Context, spec core.ProcessSpec) (*core.ProcessResult, error) {
	p.mu.Lock()
	p.calls = append(p.calls, spec)
	handler := p.Handler
	p.mu.Unlock()
	if handler != nil {
		return handler(spec)
	}
	if p.Err != nil {
		return nil, p.Err
	}
	return &core.ProcessResult{
		ExitCode: p.ExitCode,
		Stdout:   append([]byte(nil), p.Stdout...),
		Stderr:   append([]byte(nil), p.Stderr...),
	}, nil
}

// Calls returns a copy of every process spec the fake received.
func (p *Process) Calls() []core.ProcessSpec {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]core.ProcessSpec(nil), p.calls...)
}

// Last returns the most recent process spec.
func (p *Process) Last() (core.ProcessSpec, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return core.ProcessSpec{}, false
	}
	return p.calls[len(p.calls)-1], true
}

// ───────────────────────────── clock / ids / audit ─────────────────────────────

// Clock is a manual clock. Every call to Now advances by Step, so a test that
// needs distinct timestamps gets them without sleeping.
type Clock struct {
	Now_ time.Time
	Step time.Duration

	mu sync.Mutex
	n  int
}

// NewClock builds a clock starting at t.
func NewClock(t time.Time) *Clock { return &Clock{Now_: t} }

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	t := c.Now_
	if c.Step > 0 {
		c.Now_ = c.Now_.Add(c.Step)
	}
	return t
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Now_ = c.Now_.Add(d)
}

// Set pins the clock to t.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Now_ = t
}

// IDs is a deterministic core.IDGenerator: the n-th call for a prefix returns
// "<prefix>-<n>".
type IDs struct {
	mu sync.Mutex
	n  map[string]int
}

func (g *IDs) New(prefix string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n == nil {
		g.n = map[string]int{}
	}
	g.n[prefix]++
	if prefix == "" {
		prefix = "id"
	}
	return fmt.Sprintf("%s-%d", prefix, g.n[prefix])
}

// Audit records every core.AuditEvent it receives.
type Audit struct {
	mu     sync.Mutex
	events []core.AuditEvent
}

func (a *Audit) Record(_ context.Context, ev core.AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
}

// Events returns a copy of the recorded events.
func (a *Audit) Events() []core.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]core.AuditEvent(nil), a.events...)
}

// ───────────────────────────── policy ports ─────────────────────────────

// Scope is a permissive-by-default core.ScopeChecker. Denied lists the hosts
// that must be refused; Err denies everything.
type Scope struct {
	Denied  []string
	Err     error
	Checked []core.Target
}

func (s *Scope) Check(_ context.Context, t core.Target) error {
	s.Checked = append(s.Checked, t)
	if s.Err != nil {
		return s.Err
	}
	for _, d := range s.Denied {
		if strings.Contains(t.Key(), d) {
			return core.ScopeDenied("out of scope: " + t.Key())
		}
	}
	return nil
}

// Approval is an approving-by-default core.Approver.
type Approval struct {
	Err      error
	Requests []core.ApprovalRequest
}

func (a *Approval) Require(_ context.Context, req core.ApprovalRequest) error {
	a.Requests = append(a.Requests, req)
	if a.Err != nil {
		return a.Err
	}
	return nil
}

// Limiter is a non-blocking core.Limiter that records the keys it admitted.
type Limiter struct {
	Err      error
	Acquired []string
}

func (l *Limiter) Acquire(_ context.Context, key string, _ core.RateLimitSpec) (func(), error) {
	if l.Err != nil {
		return nil, l.Err
	}
	l.Acquired = append(l.Acquired, key)
	return func() {}, nil
}

// Evidence stores every core.Evidence it is handed and returns "<Prefix><n>".
type Evidence struct {
	Prefix string
	Err    error

	mu      sync.Mutex
	records []core.Evidence
}

func (e *Evidence) Record(_ context.Context, ev core.Evidence) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Err != nil {
		return "", e.Err
	}
	e.records = append(e.records, ev)
	prefix := e.Prefix
	if prefix == "" {
		prefix = "ev"
	}
	return fmt.Sprintf("%s-%d", prefix, len(e.records)), nil
}

// Records returns a copy of the stored evidence.
func (e *Evidence) Records() []core.Evidence {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]core.Evidence(nil), e.records...)
}

// Settings is an in-memory core.Settings.
type Settings struct {
	Strings map[string]string
	Bools   map[string]bool
	Ints    map[string]int64
}

func NewSettings() *Settings {
	return &Settings{Strings: map[string]string{}, Bools: map[string]bool{}, Ints: map[string]int64{}}
}

func (s *Settings) GetString(_ context.Context, key string) (string, bool) {
	v, ok := s.Strings[key]
	return v, ok
}

func (s *Settings) GetBool(_ context.Context, key string) (bool, bool) {
	v, ok := s.Bools[key]
	return v, ok
}

func (s *Settings) GetInt(_ context.Context, key string) (int64, bool) {
	v, ok := s.Ints[key]
	return v, ok
}

// Sealer is a reversible XOR sealer for tests. It is not cryptographic and must
// never be used outside a test.
type Sealer struct{ Key byte }

func (s Sealer) Seal(plain string) (string, error)  { return s.xor(plain), nil }
func (s Sealer) Open(sealed string) (string, error) { return s.xor(sealed), nil }

func (s Sealer) xor(in string) string {
	b := []byte(in)
	key := s.Key
	if key == 0 {
		key = 0x5a
	}
	for i := range b {
		b[i] ^= key
	}
	return string(b)
}

// Logger keeps every line it is given.
type Logger struct {
	mu    sync.Mutex
	lines []string
}

func (l *Logger) Info(msg string, kv ...any)  { l.add("info", msg, kv...) }
func (l *Logger) Warn(msg string, kv ...any)  { l.add("warn", msg, kv...) }
func (l *Logger) Error(msg string, kv ...any) { l.add("error", msg, kv...) }

func (l *Logger) add(level, msg string, kv ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf("%s %s %v", level, msg, kv))
}

// Lines returns every logged line.
func (l *Logger) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// Artifacts is an in-memory core.ArtifactStore.
type Artifacts struct {
	mu    sync.Mutex
	files map[string][]byte
}

func (a *Artifacts) Put(_ context.Context, name string, data []byte) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.files == nil {
		a.files = map[string][]byte{}
	}
	path := "/fake/" + name
	a.files[path] = append([]byte(nil), data...)
	return path, nil
}

func (a *Artifacts) Get(_ context.Context, path string) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	data, ok := a.files[path]
	if !ok {
		return nil, core.NotFound("artifact not found: " + path)
	}
	return append([]byte(nil), data...), nil
}

func (a *Artifacts) Delete(_ context.Context, path string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.files, path)
	return nil
}

// Binaries is a scripted core.BinaryManager reporting every binary installed.
type Binaries struct {
	Path  string
	State core.BinaryStatus
	Err   error
}

func (b *Binaries) status() core.BinaryStatus {
	if b.State.Version == "" {
		return core.BinaryStatus{Installed: true, Version: "test-1.0", Path: b.Path, UpdatedAt: DefaultTime}
	}
	return b.State
}

func (b *Binaries) Ensure(context.Context, string, string) (string, core.BinaryStatus, error) {
	if b.Err != nil {
		return "", core.BinaryStatus{}, b.Err
	}
	return b.Path, b.status(), nil
}

func (b *Binaries) Update(context.Context, string, string) (core.BinaryStatus, error) {
	if b.Err != nil {
		return core.BinaryStatus{}, b.Err
	}
	return b.status(), nil
}

func (b *Binaries) Status(context.Context, string) (core.BinaryStatus, error) {
	if b.Err != nil {
		return core.BinaryStatus{}, b.Err
	}
	return b.status(), nil
}

// ───────────────────────────── knowledge ports ─────────────────────────────

// Intel is a scripted core.IntelStore. It keeps what it was given, so a test
// can assert the kit handed the host exactly what it claims.
type Intel struct {
	Items []core.IntelItem
	Err   error

	mu    sync.Mutex
	byKey map[string]core.IntelItem
	byID  map[string]core.IntelItem
	seq   int
}

func (i *Intel) Upsert(_ context.Context, item core.IntelItem) (string, bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.Err != nil {
		return "", false, i.Err
	}
	if i.byKey == nil {
		i.byKey = map[string]core.IntelItem{}
		i.byID = map[string]core.IntelItem{}
	}
	if existing, ok := i.byKey[item.UniqueKey]; ok {
		return existing.ID, false, nil
	}
	i.seq++
	id := fmt.Sprintf("intel-%d", i.seq)
	item.ID = id
	i.byKey[item.UniqueKey] = item
	i.byID[id] = item
	i.Items = append(i.Items, item)
	return id, true, nil
}

func (i *Intel) Query(_ context.Context, q core.IntelQuery) ([]core.IntelItem, error) {
	if i.Err != nil {
		return nil, i.Err
	}
	out := make([]core.IntelItem, 0, len(i.Items))
	for _, it := range i.Items {
		if q.Text != "" && !strings.Contains(it.Title, q.Text) {
			continue
		}
		if q.CVE != "" && !strings.EqualFold(it.CVE, q.CVE) {
			continue
		}
		out = append(out, it)
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out, nil
}

func (i *Intel) Get(_ context.Context, id string) (*core.IntelItem, error) {
	if i.Err != nil {
		return nil, i.Err
	}
	it, ok := i.byID[id]
	if !ok {
		return nil, core.NotFound("intel item not found: " + id)
	}
	return &it, nil
}

// Completer is a scripted core.Completer. Reply is returned verbatim, so a
// test can feed a canned model answer — or a malformed one.
type Completer struct {
	Reply  string
	Err    error
	Calls  int
	System []string
	User   []string
}

func (c *Completer) Complete(_ context.Context, system, user string, _ int) (string, error) {
	c.Calls++
	c.System = append(c.System, system)
	c.User = append(c.User, user)
	if c.Err != nil {
		return "", c.Err
	}
	return c.Reply, nil
}

// Fingerprints is a scripted core.FingerprintProvider.
type Fingerprints struct {
	Result []core.Fingerprint
	Err    error
}

func (f *Fingerprints) Fingerprint(context.Context, core.Target) ([]core.Fingerprint, error) {
	return f.Result, f.Err
}

// Templates is an in-memory core.TemplateCatalog.
type Templates struct {
	Refs []core.TemplateRef
	Err  error
}

func (t *Templates) Search(context.Context, core.TemplateQuery) ([]core.TemplateRef, error) {
	return t.Refs, t.Err
}

func (t *Templates) Get(_ context.Context, id string) (core.TemplateRef, bool, error) {
	if t.Err != nil {
		return core.TemplateRef{}, false, t.Err
	}
	for _, r := range t.Refs {
		if r.ID == id {
			return r, true, nil
		}
	}
	return core.TemplateRef{}, false, nil
}

// Engine is a scripted core.TemplateEngine.
type Engine struct {
	KindName string
	Result   core.Result
	Err      error
}

func (e *Engine) Kind() string {
	if e.KindName == "" {
		return "http"
	}
	return e.KindName
}

func (e *Engine) Execute(context.Context, []core.TemplateRef, core.Target, map[string]any) (core.Result, error) {
	return e.Result, e.Err
}

// ───────────────────────────── sessions ─────────────────────────────

// Session is a scripted core.Session: Exec answers with the preset output.
type Session struct {
	SessionInfo core.SessionInfo
	Stdout      string
	Stderr      string
	ExitCode    int
	Err         error

	mu    sync.Mutex
	calls []string
}

// NewSession builds a session for host:22 running as root.
func NewSession(id string) *Session {
	return &Session{
		SessionInfo: core.SessionInfo{ID: id, Kind: "ssh", Host: "10.0.0.5", Port: 22, User: "root", OS: "linux"},
		Stdout:      "uid=0(root) gid=0(root) groups=0(root)\n",
	}
}

func (s *Session) Exec(_ context.Context, cmd string, _ core.ExecOpts) (core.Output, error) {
	s.mu.Lock()
	s.calls = append(s.calls, cmd)
	s.mu.Unlock()
	if s.Err != nil {
		return core.Output{Command: cmd}, s.Err
	}
	return core.Output{Command: cmd, Stdout: s.Stdout, Stderr: s.Stderr, ExitCode: s.ExitCode}, nil
}

func (s *Session) Info() core.SessionInfo { return s.SessionInfo }

func (s *Session) Close() error { return nil }

// Calls returns every command the session was asked to run.
func (s *Session) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// Sessions is an in-memory core.SessionManager. NewSessions starts empty;
// NewSessionsWith pre-registers the given sessions.
type Sessions struct {
	mu       sync.Mutex
	sessions map[string]*Session
	order    []string
	OpenErr  error
}

func NewSessions() *Sessions {
	return &Sessions{sessions: map[string]*Session{}}
}

// NewSessionsWith builds a manager holding the given sessions.
func NewSessionsWith(list ...*Session) *Sessions {
	m := NewSessions()
	for _, s := range list {
		m.Add(s)
	}
	return m
}

// Add registers s so tools can resolve it by ID.
func (m *Sessions) Add(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[s.SessionInfo.ID]; !ok {
		m.order = append(m.order, s.SessionInfo.ID)
	}
	m.sessions[s.SessionInfo.ID] = s
}

func (m *Sessions) Open(_ context.Context, spec core.SessionSpec) (core.SessionInfo, error) {
	if m.OpenErr != nil {
		return core.SessionInfo{}, m.OpenErr
	}
	s := NewSession(m.NextID("sess"))
	s.SessionInfo.Kind = spec.Kind
	s.SessionInfo.Host = spec.Host
	s.SessionInfo.Port = spec.Port
	s.SessionInfo.User = spec.User
	m.Add(s)
	return s.SessionInfo, nil
}

// NextID is a helper for tests that need a deterministic session id.
func (m *Sessions) NextID(prefix string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("%s-%d", prefix, len(m.sessions)+1)
}

func (m *Sessions) Get(id string) (core.Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, false
	}
	return s, true
}

func (m *Sessions) List() []core.SessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]core.SessionInfo, 0, len(m.order))
	for _, id := range m.order {
		if s, ok := m.sessions[id]; ok {
			out = append(out, s.SessionInfo)
		}
	}
	return out
}

func (m *Sessions) Close(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

// ───────────────────────────── cloud signing ─────────────────────────────

// CloudSigner is a scripted cloud request signer. It records every request it
// was asked to sign and stamps a deterministic Authorization header, so a
// cloud tool can be exercised offline: the test asserts on what would have been
// sent without ever reaching a vendor API.
//
// It satisfies cloudkit's Signer interface structurally, which keeps this
// package free of kit imports.
type CloudSigner struct {
	// Signature is the value embedded in the Authorization header.
	Signature string
	// AccessKey, when set, overrides the credential echoed into the header.
	AccessKey string
	Err       error

	mu     sync.Mutex
	signed []CloudSignRequest
}

// CloudSignRequest is one recorded signing request.
type CloudSignRequest struct {
	Request   core.Request
	AccessKey string
	SecretKey string
	At        time.Time
}

// SignRequest stamps req with a fake Authorization header and records the call.
func (s *CloudSigner) SignRequest(req core.Request, accessKey, secretKey string, now time.Time) (core.Request, error) {
	s.mu.Lock()
	s.signed = append(s.signed, CloudSignRequest{Request: req, AccessKey: accessKey, SecretKey: secretKey, At: now})
	s.mu.Unlock()
	if s.Err != nil {
		return req, s.Err
	}
	ak := s.AccessKey
	if ak == "" {
		ak = accessKey
	}
	sig := s.Signature
	if sig == "" {
		sig = "FAKE-SIGNATURE"
	}
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	req.Headers["Authorization"] = "FAKESIGN Credential=" + ak + ", Signature=" + sig
	return req, nil
}

// Signed returns a copy of every signing request.
func (s *CloudSigner) Signed() []CloudSignRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]CloudSignRequest(nil), s.signed...)
}

// ───────────────────────────── assembly ─────────────────────────────

// Ports is the assembled fake port set. Fields are exposed so a test can swap
// one fake for a stricter one.
type Ports struct {
	HTTP     *HTTP
	Fetcher  *HTTP
	Scope    *Scope
	Approval *Approval
	Limiter  *Limiter
	Audit    *Audit
	Evidence *Evidence
	Settings *Settings
	Sealer   Sealer
	Logger   *Logger
	Clock    *Clock
	IDs      *IDs
	Process  *Process
	Artifact *Artifacts
	Binaries *Binaries

	Fingerprints *Fingerprints
	Templates    *Templates
	Engine       *Engine
	Sessions     *Sessions
	Intel        *Intel
	Completer    *Completer
}

// NewPorts builds a complete, permissive fake port set: an empty session list,
// no fingerprints, no templates, a transport answering every request with the
// given body, and a process runner that exits 0 with no output.
func NewPorts() *Ports {
	http := NewHTTPJSON("{}")
	return &Ports{
		HTTP: http, Fetcher: http,
		Scope: &Scope{}, Approval: &Approval{}, Limiter: &Limiter{}, Audit: &Audit{},
		Evidence: &Evidence{}, Settings: NewSettings(), Logger: &Logger{},
		Clock: NewClock(DefaultTime), IDs: &IDs{},
		Process: &Process{}, Artifact: &Artifacts{}, Binaries: &Binaries{Path: "/fake/bin"},
		Fingerprints: &Fingerprints{}, Templates: &Templates{}, Engine: &Engine{},
		Sessions: NewSessions(),
		Intel:    &Intel{}, Completer: &Completer{},
	}
}

// Deps projects the fake ports into a core.Deps for a kit constructor.
func (p *Ports) Deps() core.Deps {
	return core.Deps{
		Scope: p.Scope, Approval: p.Approval, Evidence: p.Evidence,
		HTTP: p.HTTP, Fetcher: p.Fetcher, Limiter: p.Limiter, Audit: p.Audit,
		Settings: p.Settings, Sealer: p.Sealer, Logger: p.Logger,
		Clock: p.Clock, IDs: p.IDs, Processes: p.Process,
		Artifacts: p.Artifact, Binaries: p.Binaries,
		Fingerprints: p.Fingerprints, Templates: p.Templates,
		TemplateEngines: map[string]core.TemplateEngine{"http": p.Engine, "nuclei": &Engine{KindName: "nuclei"}},
		Sessions:        p.Sessions,
		Intel:           p.Intel, Completer: p.Completer,
	}
}

// Deps builds a full core.Deps wired with permissive fakes.
func Deps() core.Deps { return NewPorts().Deps() }

// MinimalInput derives a smallest legal input for a tool from its JSON schema:
// every required property is filled with a type-appropriate sample value. It
// exists so a contract test can call every registered tool without hand-written
// fixtures per tool.
func MinimalInput(schema json.RawMessage) json.RawMessage {
	filled := map[string]any{}
	var s struct {
		Properties map[string]struct {
			Type    string          `json:"type"`
			Enum    []any           `json:"enum"`
			Default any             `json:"default"`
			Minimum *float64        `json:"minimum"`
			Items   json.RawMessage `json:"items"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(schema, &s); err != nil {
		return json.RawMessage(`{}`)
	}
	for _, name := range s.Required {
		prop, ok := s.Properties[name]
		if !ok {
			continue
		}
		filled[name] = sampleValue(name, prop.Type, prop.Enum, prop.Default, prop.Minimum, prop.Items)
	}
	out, err := json.Marshal(filled)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return out
}

func sampleValue(name, typ string, enum []any, def any, min *float64, items json.RawMessage) any {
	if def != nil {
		return def
	}
	if len(enum) > 0 {
		return enum[0]
	}
	switch typ {
	case "integer", "number":
		if min != nil {
			return int(*min)
		}
		return 1
	case "boolean":
		return false
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	default:
		return sampleString(name)
	}
}

// sampleString fills a required string by name, so targets and credentials look
// like the real thing instead of the literal "x".
func sampleString(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "url") || strings.Contains(n, "endpoint"):
		return "http://127.0.0.1:8080/"
	case strings.Contains(n, "domain"):
		return "example.com"
	case strings.Contains(n, "cidr") || strings.Contains(n, "network"):
		return "127.0.0.0/30"
	case strings.Contains(n, "ip"):
		return "127.0.0.1"
	case strings.Contains(n, "host"):
		return "127.0.0.1"
	case strings.Contains(n, "path"):
		return "/tmp/capkit-test"
	case strings.Contains(n, "provider") || strings.Contains(n, "engine"):
		return "aliyun"
	case strings.Contains(n, "username") || n == "user":
		return "root"
	case strings.Contains(n, "password") || strings.Contains(n, "secret"):
		return "S3cret-Example-Value"
	case strings.Contains(n, "key"):
		return "AKIAIOSFODNN7EXAMPLE"
	case strings.Contains(n, "session"):
		return "sess-1"
	case strings.Contains(n, "command") || strings.Contains(n, "cmd"):
		return "id"
	case strings.Contains(n, "templ"):
		return "tpl-1"
	case strings.Contains(n, "query"):
		return "domain=\"example.com\""
	case strings.Contains(n, "region"):
		return "cn-hangzhou"
	case strings.Contains(n, "name") || strings.Contains(n, "id"):
		return "test-1"
	default:
		return "test"
	}
}
