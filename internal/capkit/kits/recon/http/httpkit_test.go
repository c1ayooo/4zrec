package http

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// errDoer is an HTTPDoer that always fails, for the failure branches.
type errDoer struct{ err error }

func (e errDoer) Do(context.Context, core.Request) (*core.Response, error) { return nil, e.err }

// memEvidence is an in-memory EvidenceSink.
type memEvidence struct {
	err     error
	records []core.Evidence
}

func (m *memEvidence) Record(_ context.Context, ev core.Evidence) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	m.records = append(m.records, ev)
	return fmt.Sprintf("ev-%d", len(m.records)), nil
}

func probeCall(t *testing.T, kit *Kit, input string) core.Result {
	t.Helper()
	res, err := kit.Call(context.Background(), core.Call{Tool: "http_probe", Input: json.RawMessage(input)})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	return res
}

func TestProbeSuccessSummary(t *testing.T) {
	doer := &fakeDoer{resp: &core.Response{
		Status: 200, Body: []byte("hello world"),
		Headers:  map[string][]string{"Server": {"nginx/1.25"}},
		Duration: 12 * time.Millisecond, FinalURL: "http://h/x",
	}}
	ev := &memEvidence{}
	kit := &Kit{HTTP: doer, Evidence: ev}
	res := probeCall(t, kit, `{"url":"http://h/x","method":"post"}`)

	if !res.OK || res.Status != core.StatusSuccess {
		t.Fatalf("result = %+v", res)
	}
	if res.Meta.Tool != "http_probe" || res.Meta.Version != kitVersion {
		t.Fatalf("meta = %+v", res.Meta)
	}
	for _, want := range []string{"对 http://h/x 发 POST 探测", "HTTP 200", "11 字节", "Server=nginx/1.25"} {
		if !strings.Contains(res.Summary, want) {
			t.Fatalf("summary %q missing %q", res.Summary, want)
		}
	}
	if len(res.EvidenceIDs) != 1 || len(ev.records) != 1 {
		t.Fatalf("evidence = %v records=%d", res.EvidenceIDs, len(ev.records))
	}
	if doer.last.Method != "POST" || doer.last.URL != "http://h/x" {
		t.Fatalf("request = %+v", doer.last)
	}
	var data map[string]any
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if int(data["body_bytes"].(float64)) != 11 {
		t.Fatalf("body_bytes = %v", data["body_bytes"])
	}
}

func TestProbeSummaryWithoutServerHeader(t *testing.T) {
	kit := &Kit{HTTP: &fakeDoer{resp: &core.Response{Status: 204, Body: nil}}}
	res := probeCall(t, kit, `{"url":"http://h/"}`)
	if !strings.Contains(res.Summary, "Server=-") {
		t.Fatalf("summary = %q", res.Summary)
	}
	if !strings.Contains(res.Summary, "GET") {
		t.Fatalf("default method missing: %q", res.Summary)
	}
}

func TestProbeInvalidInput(t *testing.T) {
	kit := &Kit{HTTP: &fakeDoer{}}
	res := probeCall(t, kit, `{not json`)
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("result = %+v", res)
	}
	if strings.TrimSpace(res.Summary) == "" {
		t.Fatal("summary is empty")
	}
}

func TestProbeNilHTTP(t *testing.T) {
	kit := &Kit{}
	res := probeCall(t, kit, `{"url":"http://h/"}`)
	if res.Status != core.StatusUnavailable || res.Error == nil || res.Error.Code != core.CodeUnavailable {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(res.Summary, "http://h/") {
		t.Fatalf("summary lacks target: %q", res.Summary)
	}
}

func TestProbeHTTPError(t *testing.T) {
	kit := &Kit{HTTP: errDoer{err: core.ScopeDenied("out of scope")}}
	res := probeCall(t, kit, `{"url":"http://h/"}`)
	if res.Status != core.StatusBlocked || res.Error == nil || res.Error.Code != core.CodeScopeDenied {
		t.Fatalf("result = %+v", res)
	}
}

func TestProbeEvidenceErrorKeepsResult(t *testing.T) {
	kit := &Kit{
		HTTP:     &fakeDoer{resp: &core.Response{Status: 200, Body: []byte("x")}},
		Evidence: &memEvidence{err: fmt.Errorf("disk full")},
	}
	res := probeCall(t, kit, `{"url":"http://h/"}`)
	if !res.OK || len(res.EvidenceIDs) != 0 {
		t.Fatalf("result = %+v", res)
	}
}

func TestProbeUnknownTool(t *testing.T) {
	kit := &Kit{HTTP: &fakeDoer{}}
	res, err := kit.Call(context.Background(), core.Call{Tool: "nope", Input: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("result = %+v", res)
	}
	if res.Meta.Tool != "nope" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
}

func TestNewCapability(t *testing.T) {
	cap, err := NewCapability(core.Deps{HTTP: &fakeDoer{}})
	if err != nil || cap == nil {
		t.Fatalf("cap=%v err=%v", cap, err)
	}
	if cap.Manifest().Name != "httpkit" {
		t.Fatalf("manifest = %+v", cap.Manifest())
	}
}

// ───────────────────────────── engine ─────────────────────────────

func TestExecuteNilHTTP(t *testing.T) {
	kit := &Kit{}
	res, err := kit.Execute(context.Background(), nil, core.Target{URL: "http://h"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusUnavailable || res.Error == nil {
		t.Fatalf("result = %+v", res)
	}
}

func TestExecuteInvalidTarget(t *testing.T) {
	kit := &Kit{HTTP: &fakeDoer{}}
	res, _ := kit.Execute(context.Background(), nil, core.Target{}, nil)
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("result = %+v", res)
	}
}

func TestExecuteTemplateErrorBranches(t *testing.T) {
	kit := &Kit{HTTP: &fakeDoer{resp: &core.Response{Status: 200, Body: []byte("ok")}}}
	refs := []core.TemplateRef{
		{ID: "bad", Artifact: []byte(`{not json`)},
		{ID: "nopath", Artifact: []byte(`{"request":{"method":"GET"}}`)},
	}
	res, err := kit.Execute(context.Background(), refs, core.Target{URL: "http://h"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Results []engineResult `json:"results"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Results) != 2 {
		t.Fatalf("results = %+v", data.Results)
	}
	if !strings.Contains(data.Results[0].Error, "parse template") {
		t.Fatalf("result0 = %+v", data.Results[0])
	}
	if !strings.Contains(data.Results[1].Error, "request.path") {
		t.Fatalf("result1 = %+v", data.Results[1])
	}
}

func TestExecuteHTTPErrorBranch(t *testing.T) {
	kit := &Kit{HTTP: errDoer{err: fmt.Errorf("dial failed")}}
	refs := []core.TemplateRef{{ID: "t", Artifact: []byte(`{"request":{"path":"/"}}`)}}
	res, _ := kit.Execute(context.Background(), refs, core.Target{URL: "http://h"}, nil)
	var data struct {
		Results []engineResult `json:"results"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(data.Results[0].Error, "dial failed") {
		t.Fatalf("result = %+v", data.Results[0])
	}
}

func TestExecuteEvidenceAndNoMatchers(t *testing.T) {
	ev := &memEvidence{}
	kit := &Kit{HTTP: &fakeDoer{resp: &core.Response{Status: 200, Body: []byte("body")}}, Evidence: ev}
	refs := []core.TemplateRef{{ID: "t", Artifact: []byte(`{"request":{"path":"/x"}}`)}}
	res, _ := kit.Execute(context.Background(), refs, core.Target{URL: "http://h"}, nil)
	var data struct {
		Results []engineResult `json:"results"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if !data.Results[0].Matched {
		t.Fatalf("no-matcher template should match on 2xx: %+v", data.Results[0])
	}
	if len(ev.records) != 1 {
		t.Fatalf("evidence records = %d", len(ev.records))
	}
}

func TestEngineBaseURL(t *testing.T) {
	cases := []struct {
		name string
		tgt  core.Target
		want string
		err  bool
	}{
		{"url", core.Target{URL: "https://host:8443/a/b?x=1"}, "https://host:8443", false},
		{"host", core.Target{Host: "h"}, "http://h", false},
		{"host443", core.Target{Host: "h", Port: 443}, "https://h", false},
		{"ipport", core.Target{IP: "10.0.0.1", Port: 8080}, "http://10.0.0.1:8080", false},
		{"badurl", core.Target{URL: "http://"}, "", true},
		{"empty", core.Target{}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engineBaseURL(tc.tgt)
			if tc.err {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q err=%v want %q", got, err, tc.want)
			}
		})
	}
}

func TestMatchOneBranches(t *testing.T) {
	res := &core.Response{
		Status: 403, Body: []byte("Forbidden: SQL syntax"),
		Headers: map[string][]string{"Server": {"nginx"}},
	}
	if ok, _ := matchOne(engineMatcher{Type: "status", Status: []int{403}}, res); !ok {
		t.Fatal("status matcher failed")
	}
	if ok, _ := matchOne(engineMatcher{Type: "word", Part: "header", Words: []string{"nginx"}}, res); !ok {
		t.Fatal("header word matcher failed")
	}
	if ok, _ := matchOne(engineMatcher{Type: "regex", Regex: []string{"SQL syntax"}}, res); !ok {
		t.Fatal("regex matcher failed")
	}
	if _, err := matchOne(engineMatcher{Type: "regex", Regex: []string{"["}}, res); err == nil {
		t.Fatal("invalid regex should error")
	}
	if _, err := matchOne(engineMatcher{Type: "dsl"}, res); err == nil {
		t.Fatal("dsl should be unsupported")
	}
	if _, err := matchOne(engineMatcher{Type: "word", Part: "cookie"}, res); err == nil {
		t.Fatal("unsupported part should error")
	}
	if _, err := matchOne(engineMatcher{Type: "nope"}, res); err == nil {
		t.Fatal("unsupported type should error")
	}
	if ok, err := matchEngineTemplate([]engineMatcher{{Type: "status", Status: []int{200}}}, res); ok || err != nil {
		t.Fatalf("AND of one false matcher = %v %v", ok, err)
	}
	if ok, _ := matchEngineTemplate(nil, res); ok {
		t.Fatal("no-matcher 403 should not match")
	}
}

func TestExtractEngineValues(t *testing.T) {
	res := &core.Response{Body: []byte("user=admin")}
	got := extractEngineValues([]engineExtract{
		{Name: "u", Regex: `user=(\w+)`},
		{Name: "missing", Regex: `nope=(\w+)`},
		{Name: "badre", Regex: `[`},
	}, res)
	if got["u"] != "admin" {
		t.Fatalf("extract = %+v", got)
	}
	if _, ok := got["missing"]; ok {
		t.Fatalf("unexpected extract: %+v", got)
	}
}

func TestTruncateBody(t *testing.T) {
	if got := truncateBody([]byte("abc"), 0); string(got) != "abc" {
		t.Fatalf("got %q", got)
	}
	got := truncateBody([]byte("0123456789"), 4)
	if !strings.HasPrefix(string(got), "0123") || !strings.Contains(string(got), "truncated") {
		t.Fatalf("got %q", got)
	}
}

func TestKind(t *testing.T) {
	if (&Kit{}).Kind() != "http" {
		t.Fatal("kind mismatch")
	}
}
