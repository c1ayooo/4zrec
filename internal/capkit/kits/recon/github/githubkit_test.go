package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/auditlog"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
)

func TestGithubKitThroughRuntime(t *testing.T) {
	reg := core.NewRegistry()
	kit := New(core.Deps{})
	if err := reg.Add(core.Spec{Manifest: kit.Manifest(), New: NewCapability}); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(runtime.Config{
		Scope: gates.StaticScope("example.com"), Approval: gates.AutoApprove(),
		Limiter: gates.NewLimiter(), Audit: auditlog.NewMemory(),
		Fetcher:  &fakeFetcher{resp: &core.Response{Status: 200, Body: []byte(sampleJSON)}},
		Settings: fakeSettings{m: map[string]string{"github.token": "ghp_test"}},
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{
		"template_id": "org-aws", "org": "acme", "domain": "example.com",
	})
	res, err := rt.Call(context.Background(), "github_secret_search", input, core.CallContext{ProjectID: 1, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	var data SearchResult
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Items) != 1 || data.Items[0].SecretType != "aws_access_key" {
		t.Fatalf("data = %+v", data)
	}
}

func TestGithubKitScopeDenied(t *testing.T) {
	reg := core.NewRegistry()
	kit := New(core.Deps{})
	if err := reg.Add(core.Spec{Manifest: kit.Manifest(), New: NewCapability}); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(runtime.Config{
		Scope: gates.StaticScope("example.com"), Approval: gates.AutoApprove(),
		Limiter: gates.NewLimiter(), Audit: auditlog.NewMemory(),
		Fetcher:  &fakeFetcher{resp: &core.Response{Status: 200, Body: []byte(sampleJSON)}},
		Settings: fakeSettings{m: map[string]string{"github.token": "ghp_test"}},
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{"template_id": "org-aws", "org": "acme", "domain": "evil.com"})
	_, err = rt.Call(context.Background(), "github_secret_search", input, core.CallContext{ProjectID: 1})
	if err == nil || !strings.Contains(err.Error(), core.CodeScopeDenied) {
		t.Fatalf("err = %v", err)
	}
}

// TestSearchReportsPagination covers §5.5.4 for the one tool whose result set is
// genuinely unbounded: the envelope must carry the true total and a cursor.
func TestSearchReportsPagination(t *testing.T) {
	fetcher := &fakeFetcher{resp: &core.Response{Status: 200, Body: []byte(
		`{"total_count":250,"incomplete_results":false,"items":[` +
			`{"path":"a.go","html_url":"https://github.com/o/r/blob/main/a.go",` +
			`"repository":{"full_name":"o/r","html_url":"https://github.com/o/r","stargazers_count":1},` +
			`"text_matches":[{"fragment":"token=x"}]}]}`)}}
	kit := New(core.Deps{
		Fetcher:  fetcher,
		Settings: fakeSettings{m: map[string]string{"github.token": "ghp_test"}},
	})
	ctx := context.Background()

	res, err := kit.Call(ctx, core.Call{
		Tool: "github_secret_search", Input: json.RawMessage(`{"query":"token","per_page":2}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q %s", res.Status, res.Summary)
	}
	if res.Page == nil || res.Page.Total != 250 || !res.Page.HasMore || res.Page.Cursor == "" {
		t.Fatalf("page = %+v", res.Page)
	}
	if !strings.Contains(fetcher.last.URL, "page=1") {
		t.Fatalf("first request = %s", fetcher.last.URL)
	}

	// The cursor resumes at the next API page.
	if _, err := kit.Call(ctx, core.Call{
		Tool:  "github_secret_search",
		Input: json.RawMessage(`{"query":"token","per_page":2,"cursor":"` + res.Page.Cursor + `"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fetcher.last.URL, "page=2") {
		t.Fatalf("resumed request = %s", fetcher.last.URL)
	}

	// A garbled cursor is rejected rather than silently restarted.
	bad, _ := kit.Call(ctx, core.Call{
		Tool: "github_secret_search", Input: json.RawMessage(`{"query":"token","cursor":"nope"}`),
	})
	if bad.Error == nil || bad.Error.Code != core.CodeInvalidInput {
		t.Fatalf("bad cursor = %+v", bad)
	}
}

func TestDorkTemplatesSummary(t *testing.T) {
	k := New(core.Deps{})
	res, err := k.Call(context.Background(), core.Call{
		Tool: "github_dork_templates", Input: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %s", res.Status)
	}
	if res.Meta.Tool != "github_dork_templates" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
	if want := fmt.Sprintf("返回 %d 条 dork 模板", len(Templates())); res.Summary != want {
		t.Fatalf("summary = %q, want %q", res.Summary, want)
	}
}

// TestSearchSummaryNoTokenLeak: the Summary names the query and the hit counts,
// and never carries the GitHub token.
func TestSearchSummaryNoTokenLeak(t *testing.T) {
	fetcher := &fakeFetcher{resp: &core.Response{Status: 200, Body: []byte(sampleJSON)}}
	k := New(core.Deps{
		Fetcher:  fetcher,
		Settings: fakeSettings{m: map[string]string{"github.token": "ghp_supersecret"}},
	})
	res, err := k.Call(context.Background(), core.Call{
		Tool: "github_secret_search", Input: json.RawMessage(`{"query":"AKIA"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %s", res.Status)
	}
	if res.Meta.Tool != "github_secret_search" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
	if want := "在 GitHub 检索 AKIA，命中 1 条疑似泄露，高置信 1 条"; res.Summary != want {
		t.Fatalf("summary = %q, want %q", res.Summary, want)
	}
	if strings.Contains(res.Summary, "ghp_") {
		t.Fatalf("summary leaked token: %q", res.Summary)
	}
}

// TestSearchUnavailableEnvelope: a missing token is an unavailable dependency,
// reported with the fixed code and a readable Summary.
func TestSearchUnavailableEnvelope(t *testing.T) {
	k := New(core.Deps{
		Fetcher:  &fakeFetcher{resp: &core.Response{Status: 200}},
		Settings: fakeSettings{},
	})
	res, err := k.Call(context.Background(), core.Call{
		Tool: "github_secret_search", Input: json.RawMessage(`{"query":"AKIA"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusUnavailable || res.Error == nil || res.Error.Code != core.CodeUnavailable {
		t.Fatalf("res = %+v", res)
	}
	if res.Meta.Tool != "github_secret_search" || strings.TrimSpace(res.Summary) == "" {
		t.Fatalf("envelope = %+v", res)
	}
}

func TestGithubUnknownToolEnvelope(t *testing.T) {
	k := New(core.Deps{})
	res, _ := k.Call(context.Background(), core.Call{Tool: "nope", Input: json.RawMessage(`{}`)})
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("res = %+v", res)
	}
	if res.Meta.Tool != "nope" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
}
