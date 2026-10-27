package harness

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// TestFakeHTTPAnswersFromRoutes pins the behaviour the contract test relies on:
// a route is selected by URL substring, the fallback answers everything else,
// and every request is recorded for later assertions.
func TestFakeHTTPAnswersFromRoutes(t *testing.T) {
	h := NewHTTP(200, "fallback")
	h.Routes = []Route{{Match: "/api/", Status: 201, Body: "routed"}}

	res, err := h.Do(context.Background(), core.Request{Method: "GET", URL: "https://t.example/api/x"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != 201 || string(res.Body) != "routed" {
		t.Fatalf("got %d %q, want 201 routed", res.Status, res.Body)
	}
	res, err = h.Fetch(context.Background(), core.Request{URL: "https://other.example/"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(res.Body) != "fallback" {
		t.Fatalf("fallback body = %q", res.Body)
	}
	if h.Calls() != 2 {
		t.Fatalf("calls = %d, want 2", h.Calls())
	}
	last, ok := h.Last()
	if !ok || last.URL != "https://other.example/" {
		t.Fatalf("last = %+v ok=%v", last, ok)
	}
}

// TestFakeHTTPQueueBeatsRoutes covers the ordered-answer mode: a peer that
// answers differently on its first poll than on its second cannot be expressed
// with a route table, so a queued answer must win over both Routes and Default —
// and then hand control back once the queue is spent.
func TestFakeHTTPQueueBeatsRoutes(t *testing.T) {
	h := NewHTTP(200, "settled")
	h.Routes = []Route{{Match: "/poll", Body: "routed"}}
	h.Queue = []Route{{Body: "not-yet"}}

	first, err := h.Do(context.Background(), core.Request{URL: "https://t.example/poll"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(first.Body) != "not-yet" {
		t.Fatalf("queued body = %q, want not-yet", first.Body)
	}
	second, err := h.Do(context.Background(), core.Request{URL: "https://t.example/poll"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(second.Body) != "routed" {
		t.Fatalf("body after the queue drained = %q, want the route answer", second.Body)
	}
	if len(h.Queue) != 0 {
		t.Fatalf("queue not drained: %+v", h.Queue)
	}
}

// TestFakeHTTPError covers the failure path a kit must turn into a Result.
func TestFakeHTTPError(t *testing.T) {
	h := NewHTTP(200, "")
	h.Err = core.Unavailable("dns down")
	if _, err := h.Do(context.Background(), core.Request{URL: "https://x/"}); err == nil {
		t.Fatal("want error")
	}
}

// TestFakeProcessReturnsPreset is the FakeProcessRunner contract: preset
// stdout/exit code come back and the spec is recorded.
func TestFakeProcessReturnsPreset(t *testing.T) {
	p := &Process{Stdout: []byte("hello\n"), ExitCode: 3}
	res, err := p.Run(context.Background(), core.ProcessSpec{Path: "/bin/echo", Args: []string{"hello"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.Stdout) != "hello\n" || res.ExitCode != 3 {
		t.Fatalf("result = %+v", res)
	}
	if len(p.Calls()) != 1 || p.Calls()[0].Path != "/bin/echo" {
		t.Fatalf("calls = %+v", p.Calls())
	}
}

// TestFakeProcessHandler overrides the preset per spec.
func TestFakeProcessHandler(t *testing.T) {
	p := &Process{Handler: func(spec core.ProcessSpec) (*core.ProcessResult, error) {
		return &core.ProcessResult{Stdout: []byte(spec.Path)}, nil
	}}
	res, _ := p.Run(context.Background(), core.ProcessSpec{Path: "/bin/x"})
	if string(res.Stdout) != "/bin/x" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

// TestFakeClockIsManual keeps tests off the wall clock, and pins that Step
// advances monotonically so two calls never report the same instant.
func TestFakeClockIsManual(t *testing.T) {
	c := NewClock(DefaultTime)
	c.Step = time.Second
	first, second := c.Now(), c.Now()
	if !first.Equal(DefaultTime) {
		t.Fatalf("first = %v, want %v", first, DefaultTime)
	}
	if !second.After(first) {
		t.Fatalf("second %v must be after first %v", second, first)
	}
	c.Set(DefaultTime)
	if got := c.Now(); !got.Equal(DefaultTime) {
		t.Fatalf("after Set: %v", got)
	}
}

// TestFakeIDsAreDeterministic keeps generated ids stable across runs.
func TestFakeIDsAreDeterministic(t *testing.T) {
	g := &IDs{}
	got := []string{g.New("job"), g.New("job"), g.New("ev")}
	want := []string{"job-1", "job-2", "ev-1"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids = %v, want %v", got, want)
		}
	}
}

// TestFakeAuditRecords pins the audit sink contract.
func TestFakeAuditRecords(t *testing.T) {
	a := &Audit{}
	a.Record(context.Background(), core.AuditEvent{Tool: "http_probe", Phase: "start"})
	if events := a.Events(); len(events) != 1 || events[0].Tool != "http_probe" {
		t.Fatalf("events = %+v", a.Events())
	}
}

// TestFakeCloudSignerStampsAndRecords is the offline cloud-signing seam: the
// signer must both record what it was asked to sign and return a request the
// tool can send, without any vendor API being reached.
func TestFakeCloudSignerStampsAndRecords(t *testing.T) {
	s := &CloudSigner{Signature: "abc123"}
	signed, err := s.SignRequest(core.Request{Method: "POST", URL: "https://ecs.aliyuncs.com/"}, "AKIDEXAMPLE", "secret", DefaultTime)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	auth := signed.Headers["Authorization"]
	if auth != "FAKESIGN Credential=AKIDEXAMPLE, Signature=abc123" {
		t.Fatalf("authorization = %q", auth)
	}
	rec := s.Signed()
	if len(rec) != 1 || rec[0].AccessKey != "AKIDEXAMPLE" || !rec[0].At.Equal(DefaultTime) {
		t.Fatalf("recorded = %+v", rec)
	}
}

// TestFakeScopeFailsClosedOnDeniedHost pins the scope fake's deny path, which
// the gate tests depend on.
func TestFakeScopeFailsClosedOnDeniedHost(t *testing.T) {
	s := &Scope{Denied: []string{"blocked.example"}}
	if err := s.Check(context.Background(), core.Target{Kind: core.TargetURL, URL: "https://blocked.example/", Host: "blocked.example"}); err == nil {
		t.Fatal("denied host must fail")
	}
	if err := s.Check(context.Background(), core.Target{Kind: core.TargetURL, URL: "https://ok.example/", Host: "ok.example"}); err != nil {
		t.Fatalf("allowed host: %v", err)
	}
}

// TestFakeSessionsResolveByID covers the SessionManager fake the post-exploitation
// kits resolve their target from.
func TestFakeSessionsResolveByID(t *testing.T) {
	m := NewSessionsWith(NewSession("sess-1"))
	s, ok := m.Get("sess-1")
	if !ok {
		t.Fatal("session not found")
	}
	out, err := s.Exec(context.Background(), "id", core.ExecOpts{})
	if err != nil || out.Stdout == "" {
		t.Fatalf("exec = %+v err=%v", out, err)
	}
	if infos := m.List(); len(infos) != 1 || infos[0].ID != "sess-1" {
		t.Fatalf("list = %+v", infos)
	}
}

// TestDepsWiresEveryPort guards against a kit silently receiving a nil port:
// the assembled Deps must satisfy every name Registry.Validate knows about.
func TestDepsWiresEveryPort(t *testing.T) {
	deps := Deps()
	for _, name := range []string{
		"scope", "approval", "evidence", "http", "fetcher", "limiter", "audit",
		"settings", "sealer", "process", "artifact", "binary", "logger", "clock",
		"ids", "fingerprints", "templates", "template_engines", "sessions",
	} {
		reg := core.NewRegistry()
		err := reg.Add(core.Spec{
			Manifest: core.Manifest{
				Name: "probe", Version: "v1", APIVersion: "v1", Requires: []string{name},
				Tools: []core.ToolSpec{{Name: "probe_tool", Description: "probe", Risk: core.RiskLow}},
			},
			New: func(core.Deps) (core.Capability, error) { return nil, nil },
		})
		if err != nil {
			t.Fatalf("add probe for %s: %v", name, err)
		}
		if err := reg.Validate(deps); err != nil {
			t.Errorf("port %s is not wired: %v", name, err)
		}
	}
}

// TestMinimalInputFillsRequiredProperties is the seam the contract test uses to
// call every registered tool without hand-written fixtures.
func TestMinimalInputFillsRequiredProperties(t *testing.T) {
	schema := json.RawMessage(`{
	  "type":"object",
	  "properties":{
	    "host":{"type":"string"},
	    "port":{"type":"integer"},
	    "engine":{"type":"string","enum":["fofa","quake"]},
	    "flag":{"type":"boolean"},
	    "tags":{"type":"array"},
	    "size":{"type":"integer","minimum":10}
	  },
	  "required":["host","port","engine","flag","tags","size"]
	}`)
	var got map[string]any
	if err := json.Unmarshal(MinimalInput(schema), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["host"] != "127.0.0.1" {
		t.Errorf("host = %v", got["host"])
	}
	if got["engine"] != "fofa" {
		t.Errorf("enum should pick its first value, got %v", got["engine"])
	}
	if _, ok := got["port"].(float64); !ok {
		t.Errorf("port = %v", got["port"])
	}
	if got["size"].(float64) != 10 {
		t.Errorf("minimum should win, got %v", got["size"])
	}
	if _, ok := got["tags"].([]any); !ok {
		t.Errorf("tags = %v", got["tags"])
	}
	if MinimalInput(json.RawMessage(`{"type":"object","properties":{}}`)) == nil {
		t.Error("empty schema must still yield an object")
	}
}
