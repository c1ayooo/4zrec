package enterprise

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// genericSummary reports whether s is one of the empty phrases the contract
// forbids: a Summary must name the target, the action and the outcome.
func genericSummary(s string) bool {
	switch strings.TrimSpace(s) {
	case "", "完成", "成功", "OK", "ok", "done", "失败", "部分完成":
		return true
	}
	return false
}

func requireEnvelope(t *testing.T, tool string, res core.Result) {
	t.Helper()
	if !res.Status.Valid() {
		t.Fatalf("%s: Status %q invalid", tool, res.Status)
	}
	if res.Meta.Tool != tool {
		t.Fatalf("%s: Meta.Tool = %q", tool, res.Meta.Tool)
	}
	if res.Meta.Version != kitVersion {
		t.Fatalf("%s: Meta.Version = %q, want %q", tool, res.Meta.Version, kitVersion)
	}
	if genericSummary(res.Summary) {
		t.Fatalf("%s: Summary %q is an empty phrase", tool, res.Summary)
	}
	if n := len([]rune(res.Summary)); n > core.MaxSummaryRunes {
		t.Fatalf("%s: Summary is %d runes, over the limit", tool, n)
	}
	if len(res.Data) > 0 {
		var v any
		if err := json.Unmarshal(res.Data, &v); err != nil {
			t.Fatalf("%s: Data is not valid JSON: %v", tool, err)
		}
	}
}

// TestEnvelopeSuccessPaths covers the success envelope for all three tools. The
// root contract gate cannot reach these paths (its resolver is unconfigured),
// so they are pinned here with the in-package fakes.
func TestEnvelopeSuccessPaths(t *testing.T) {
	ctx := context.Background()
	kit := NewKit(resolver(fakeProvider{name: "fake"}))

	res, err := kit.Call(ctx, core.Call{
		Tool: "enterprise_search", Input: []byte(`{"provider":"fake","keyword":"example"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireEnvelope(t, "enterprise_search", res)
	if res.Status != core.StatusSuccess {
		t.Fatalf("search status = %q", res.Status)
	}
	if !strings.Contains(res.Summary, "fake") || !strings.Contains(res.Summary, "example") || !strings.Contains(res.Summary, "返回 1 条") {
		t.Fatalf("search summary = %q", res.Summary)
	}

	res, err = kit.Call(ctx, core.Call{
		Tool: "enterprise_detail", Input: []byte(`{"provider":"fake","ext_id":"e1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireEnvelope(t, "enterprise_detail", res)
	if res.Status != core.StatusSuccess {
		t.Fatalf("detail status = %q", res.Status)
	}
	if !strings.Contains(res.Summary, "fake") || !strings.Contains(res.Summary, "e1") || !strings.Contains(res.Summary, "关联域名") {
		t.Fatalf("detail summary = %q", res.Summary)
	}

	res, err = NewKit(nil).Call(ctx, core.Call{Tool: "enterprise_providers"})
	if err != nil {
		t.Fatal(err)
	}
	requireEnvelope(t, "enterprise_providers", res)
	if res.Status != core.StatusSuccess {
		t.Fatalf("providers status = %q", res.Status)
	}
	available := 0
	for _, p := range Registry {
		if p.Available {
			available++
		}
	}
	want := "返回 " + strconv.Itoa(len(Registry)) + " 个企业数据源，其中 " + strconv.Itoa(available) + " 个可用"
	if res.Summary != want {
		t.Fatalf("providers summary = %q, want %q", res.Summary, want)
	}
}

// TestEnvelopeDetailDomainCount pins that the detail Summary reports the real
// related-domain count from the provider payload.
func TestEnvelopeDetailDomainCount(t *testing.T) {
	p := funcProvider{name: "cap", detailFn: func(context.Context, string) (*CompanyDetail, error) {
		return &CompanyDetail{ExtID: "e9", Name: "Acme", Domains: []DomainHit{{Domain: "a.com"}, {Domain: "b.com"}}}, nil
	}}
	res, err := NewKit(resolver(p)).Call(context.Background(), core.Call{
		Tool: "enterprise_detail", Input: []byte(`{"provider":"cap","ext_id":"e9"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireEnvelope(t, "enterprise_detail", res)
	if !strings.Contains(res.Summary, "关联域名 2 个") {
		t.Fatalf("summary = %q", res.Summary)
	}
}

// TestEnvelopeFailurePath checks the failing envelope still satisfies the
// contract: a usable Status, an enum Error.Code and a non-generic Summary.
func TestEnvelopeFailurePath(t *testing.T) {
	res, err := NewKit(nil).Call(context.Background(), core.Call{
		Tool: "enterprise_search", Input: []byte(`{"provider":"aqc","keyword":"x"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusUnavailable || res.Error == nil || res.Error.Code != core.CodeUnavailable {
		t.Fatalf("status=%q err=%+v", res.Status, res.Error)
	}
	if res.Meta.Tool != "enterprise_search" {
		t.Fatalf("Meta.Tool = %q", res.Meta.Tool)
	}
	if genericSummary(res.Summary) {
		t.Fatalf("failure summary = %q", res.Summary)
	}
}
