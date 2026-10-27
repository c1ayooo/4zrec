package capkitbridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	capkit "github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
)

// The bridge exposes capkit's intel, generation and binding kits only when the
// host supplies their ports. These fakes stand in for the host's fetcher,
// intel table, model profile and artifact directory.

type fakeFetcher struct{ body string }

func (f fakeFetcher) Fetch(_ context.Context, _ capkit.Request) (*capkit.Response, error) {
	return &capkit.Response{Status: 200, Body: []byte(f.body)}, nil
}

func (f fakeFetcher) Do(ctx context.Context, req capkit.Request) (*capkit.Response, error) {
	return f.Fetch(ctx, req)
}

type fakeIntel struct{ items []capkit.IntelItem }

func (s *fakeIntel) Upsert(_ context.Context, item capkit.IntelItem) (string, bool, error) {
	s.items = append(s.items, item)
	return "1", true, nil
}

func (s *fakeIntel) Query(context.Context, capkit.IntelQuery) ([]capkit.IntelItem, error) {
	return s.items, nil
}

func (s *fakeIntel) Get(context.Context, string) (*capkit.IntelItem, error) {
	if len(s.items) == 0 {
		return nil, capkit.NotFound("empty")
	}
	it := s.items[0]
	return &it, nil
}

type fakeCompleter struct{ reply string }

func (c fakeCompleter) Complete(context.Context, string, string, int) (string, error) {
	return c.reply, nil
}

type fakeArtifacts struct{ put map[string]string }

func (a *fakeArtifacts) Put(_ context.Context, name string, data []byte) (string, error) {
	if a.put == nil {
		a.put = map[string]string{}
	}
	a.put[name] = string(data)
	return "/tmp/" + name, nil
}

func (a *fakeArtifacts) Get(context.Context, string) ([]byte, error) {
	return nil, capkit.NotFound("x")
}

func (a *fakeArtifacts) Delete(context.Context, string) error { return nil }

const kevFixture = `{"vulnerabilities":[
  {"cveID":"CVE-2024-3400","vendorProject":"Palo Alto Networks","product":"PAN-OS",
   "vulnerabilityName":"PAN-OS Command Injection","dateAdded":"2024-04-12",
   "shortDescription":"GlobalProtect command injection.","requiredAction":"Apply mitigations.","notes":""}
]}`

func newIntelBridge(t *testing.T) *Bridge {
	t.Helper()
	b, err := New(Options{
		Scope:     gates.StaticScope("127.0.0.1"),
		HTTP:      fakeFetcher{body: "{}"},
		Fetcher:   fakeFetcher{body: kevFixture},
		Intel:     &fakeIntel{},
		Completer: fakeCompleter{reply: `{"name":"Palo Alto PAN-OS","category":"firewall","patterns":[{"type":"body","value":"GlobalProtect Portal"}],"reason":"f"}`},
		Artifacts: &fakeArtifacts{},
		Context: func(context.Context) capkit.CallContext {
			return capkit.CallContext{ProjectID: 1, Actor: "test"}
		},
	})
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	return b
}

// TestIntelAndGenerationToolsAreExposed pins that a host wiring the four new
// ports actually gets the eleven new tools on its tool surface.
func TestIntelAndGenerationToolsAreExposed(t *testing.T) {
	b := newIntelBridge(t)
	have := map[string]bool{}
	for _, tool := range b.Tools() {
		have[tool.Name()] = true
	}
	for _, want := range []string{
		"vulnintel_sources", "vulnintel_poll", "vulnintel_search", "vulnintel_get",
		"poc_generate", "poc_template_draft", "poc_fingerprint_draft", "poc_publish",
		"binding_resolve", "binding_check", "binding_defaults",
	} {
		if !have[want] {
			t.Errorf("tool %q is not exposed", want)
		}
	}
}

// TestWithoutPortsTheKitsStayOut pins the fail-closed rule: a host with no
// intel store or model profile keeps its session tools and simply does not get
// the intel tools, instead of failing to build the whole bridge.
func TestWithoutPortsTheKitsStayOut(t *testing.T) {
	b, err := New(Options{
		Scope: gates.StaticScope("127.0.0.1"),
		HTTP:  fakeFetcher{body: "{}"},
	})
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	for _, tool := range b.Tools() {
		if strings.HasPrefix(tool.Name(), "vulnintel_") || strings.HasPrefix(tool.Name(), "poc_") {
			t.Errorf("tool %q must not be exposed without its ports", tool.Name())
		}
		if tool.Name() == "binding_check" {
			return // bindingkit needs no port and must still be present
		}
	}
	t.Error("binding_check is missing: bindingkit declares no port and should always register")
}

// TestBindingCheckFoldsFingerprintSpellings pins the capability the host was
// missing: the verbose product name a fingerprint reports resolves onto the
// canonical key a template library uses.
func TestBindingCheckFoldsFingerprintSpellings(t *testing.T) {
	b := newIntelBridge(t)
	in, _ := json.Marshal(map[string]any{
		"recognized": []string{"AJ-Report数据大屏系统"},
		"product":    "AJ-Report",
	})
	res, err := b.Call(context.Background(), "binding_check", in, capkit.CallContext{ProjectID: 1})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.OK {
		t.Fatalf("status = %q summary = %q", res.Status, res.Summary)
	}
	var data struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	if !data.Allowed {
		t.Fatalf("allowed = false: %q", data.Reason)
	}
}

// TestPollWritesThroughTheHostStore pins that the kit reaches the host's intel
// table through the port rather than keeping its own state.
func TestPollWritesThroughTheHostStore(t *testing.T) {
	store := &fakeIntel{}
	b, err := New(Options{
		Scope: gates.StaticScope("127.0.0.1"), HTTP: fakeFetcher{body: "{}"},
		Fetcher: fakeFetcher{body: kevFixture}, Intel: store,
	})
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	in, _ := json.Marshal(map[string]any{"sources": []string{"kev"}})
	res, err := b.Call(context.Background(), "vulnintel_poll", in, capkit.CallContext{ProjectID: 1})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.OK {
		t.Fatalf("status = %q summary = %q err = %+v", res.Status, res.Summary, res.Error)
	}
	if len(store.items) != 1 {
		t.Fatalf("host store received %d items, want 1", len(store.items))
	}
	if store.items[0].UniqueKey == "" || store.items[0].Source != "kev" {
		t.Fatalf("item is missing its identity: %+v", store.items[0])
	}
}

// TestFingerprintDraftRefusesGenericRule pins that the generation path keeps
// the "no rule that matches everything" invariant when driven from the host.
func TestFingerprintDraftRefusesGenericRule(t *testing.T) {
	b, err := New(Options{
		Scope: gates.StaticScope("127.0.0.1"), HTTP: fakeFetcher{body: "{}"},
		Completer: fakeCompleter{reply: `{"name":"Web","category":"other","patterns":[{"type":"body","value":"html"}]}`},
		Artifacts: &fakeArtifacts{},
	})
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	in, _ := json.Marshal(map[string]any{"title": "Some product RCE"})
	res, err := b.Call(context.Background(), "poc_fingerprint_draft", in, capkit.CallContext{ProjectID: 1})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if res.OK {
		t.Fatalf("a generic rule must be refused, got status %q", res.Status)
	}
}

// fakeHostSource is a host-provided advisory source (the AVD seam) that never
// touches the network.
type fakeHostSource struct {
	name  string
	items []capkit.IntelItem
	calls int
}

func (f *fakeHostSource) Name() string { return f.name }

func (f *fakeHostSource) Fetch(_ context.Context, limit int) ([]capkit.IntelItem, error) {
	f.calls++
	if limit > 0 && len(f.items) > limit {
		return f.items[:limit], nil
	}
	return f.items, nil
}

// TestHostSourceJoinsThePollLoop pins the AVD decision: a source the host
// fetches itself (because it needs a JS engine) is polled through capkit's
// loop and written through the host's store, so the host does not keep a
// second poll path for one source.
func TestHostSourceJoinsThePollLoop(t *testing.T) {
	store := &fakeIntel{}
	host := &fakeHostSource{
		name: "aliyun-avd",
		items: []capkit.IntelItem{{
			UniqueKey: "AVD-2026-104935_aliyun-avd",
			Title:     "Ivanti Connect Secure 请求头权限绕过漏洞",
			Severity:  "high",
		}},
	}
	b, err := New(Options{
		Scope:      gates.StaticScope("127.0.0.1"),
		HTTP:       fakeFetcher{body: "{}"},
		Fetcher:    fakeFetcher{body: kevFixture},
		Intel:      store,
		Completer:  fakeCompleter{reply: "{}"},
		Artifacts:  &fakeArtifacts{},
		ExtraIntel: []capkit.IntelSource{host},
		Context: func(context.Context) capkit.CallContext {
			return capkit.CallContext{ProjectID: 1, Actor: "test"}
		},
	})
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	in, _ := json.Marshal(map[string]any{"sources": []string{"aliyun-avd"}})
	res, err := b.Call(context.Background(), "vulnintel_poll", in, capkit.CallContext{ProjectID: 1, Actor: "test"})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if res.Status != capkit.StatusSuccess {
		t.Fatalf("status = %q summary=%q err=%+v", res.Status, res.Summary, res.Error)
	}
	if host.calls != 1 {
		t.Fatalf("host source called %d times, want 1", host.calls)
	}
	if len(store.items) != 1 || store.items[0].Source != "aliyun-avd" {
		t.Fatalf("store items = %+v", store.items)
	}
}
