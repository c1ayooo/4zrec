package binding

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// TestResolveFoldsVendorSpellings pins the core promise: the verbose name a
// fingerprint reports lands on the same canonical key the template library
// uses, without losing the ability to say "unknown".
func TestResolveFoldsVendorSpellings(t *testing.T) {
	cases := []struct {
		detected string
		want     string
		via      string
	}{
		{"AJ-Report数据大屏系统", "AJ-Report", "alias"},
		{"AJ-Report", "AJ-Report", "exact"},
		{"泛微OA", "泛微OA", "exact"},
		{"Weaver OA", "泛微OA", "alias"},
		{"通达OA 2017", "通达OA", "contains"},
		{"Some Unknown Product", "", "none"},
	}
	for _, c := range cases {
		got := Resolve([]string{c.detected}, DefaultBindings)
		if len(got) != 1 {
			t.Fatalf("%s: got %d resolutions", c.detected, len(got))
		}
		if got[0].Product != c.want || got[0].MatchedVia != c.via {
			t.Errorf("%q -> (%q,%q), want (%q,%q)",
				c.detected, got[0].Product, got[0].MatchedVia, c.want, c.via)
		}
	}
}

// TestResolveNeverCrossesProducts pins the anti-guess rule: a short alias must
// not drag an unrelated product into a binding.
func TestResolveNeverCrossesProducts(t *testing.T) {
	got := Resolve([]string{"OA"}, DefaultBindings)
	if len(got) != 1 {
		t.Fatalf("got %d resolutions", len(got))
	}
	if got[0].Product != "" {
		t.Fatalf("bare OA matched %q; it must stay unmatched", got[0].Product)
	}
}

func callResolve(t *testing.T, products []string) (core.Result, resolveData) {
	t.Helper()
	cap, _ := NewCapability(core.Deps{})
	in, _ := json.Marshal(map[string]any{"products": products})
	res, err := cap.Call(context.Background(), core.Call{Tool: "binding_resolve", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q err=%+v", res.Status, res.Summary, res.Error)
	}
	var data resolveData
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	return res, data
}

// TestResolveEnvelopeCarriesUnmatchedAndQueries pins the payload shape a host
// needs: what matched, what did not, and what to search templates with.
func TestResolveEnvelopeCarriesUnmatchedAndQueries(t *testing.T) {
	res, data := callResolve(t, []string{"AJ-Report数据大屏系统", "不存在的产品"})
	if res.Summary == "" {
		t.Fatal("summary must not be empty")
	}
	if len(data.Resolutions) != 2 {
		t.Fatalf("resolutions = %d, want 2", len(data.Resolutions))
	}
	if len(data.Unmatched) != 1 || data.Unmatched[0] != "不存在的产品" {
		t.Fatalf("unmatched = %v", data.Unmatched)
	}
	found := false
	for _, q := range data.QueryTerms {
		if q == "AJ-Report" {
			found = true
		}
	}
	if !found {
		t.Fatalf("query terms = %v, want AJ-Report", data.QueryTerms)
	}
}

func callCheck(t *testing.T, in map[string]any) checkData {
	t.Helper()
	cap, _ := NewCapability(core.Deps{})
	raw, _ := json.Marshal(in)
	res, err := cap.Call(context.Background(), core.Call{Tool: "binding_check", Input: raw})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q err=%+v", res.Status, res.Summary, res.Error)
	}
	var data checkData
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	if res.Summary == "" {
		t.Fatal("summary must not be empty")
	}
	return data
}

// TestCheckAllowsBoundProduct pins the gate's happy path across the spelling
// difference that used to break the substring gate.
func TestCheckAllowsBoundProduct(t *testing.T) {
	data := callCheck(t, map[string]any{
		"recognized": []string{"AJ-Report数据大屏系统"},
		"product":    "AJ-Report",
	})
	if !data.Allowed {
		t.Fatalf("allowed = false, reason %q", data.Reason)
	}
	if data.MatchedProduct != "AJ-Report" {
		t.Fatalf("matched product = %q", data.MatchedProduct)
	}
}

// TestCheckDeniesUnrelatedProduct pins that recognition alone does not open
// every template.
func TestCheckDeniesUnrelatedProduct(t *testing.T) {
	data := callCheck(t, map[string]any{
		"recognized": []string{"AJ-Report"},
		"product":    "Weblogic",
	})
	if data.Allowed {
		t.Fatalf("allowed = true for an unrelated product: %q", data.Reason)
	}
	if !strings.Contains(data.Reason, "不在已识别指纹中") {
		t.Fatalf("reason should name the mismatch: %q", data.Reason)
	}
}

// TestCheckCVEWithoutRecognitionIsDenied pins the precondition: a CVE lookup
// still needs fingerprint evidence.
func TestCheckCVEWithoutRecognitionIsDenied(t *testing.T) {
	cap, _ := NewCapability(core.Deps{})
	raw, _ := json.Marshal(map[string]any{"recognized": []string{}, "cve": "CVE-2024-53677"})
	res, err := cap.Call(context.Background(), core.Call{Tool: "binding_check", Input: raw})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
}

// TestCheckCVEMappedToProduct pins the CVE path: a known CVE is allowed when
// the binding maps it to a recognized product.
func TestCheckCVEMappedToProduct(t *testing.T) {
	bindings := []Binding{{
		Product: "Demo OA",
		Aliases: []string{"Demo-OA"},
		CVEs:    []string{"CVE-2024-0001"},
	}}
	data := callCheck(t, map[string]any{
		"recognized": []string{"Demo-OA"},
		"cve":        "CVE-2024-0001",
		"bindings":   bindings,
	})
	if !data.Allowed {
		t.Fatalf("allowed = false, reason %q", data.Reason)
	}
}

// TestValidateRejectsAliasCollisions pins that a table where one product's
// alias is another product's canonical name is rejected: resolution would
// otherwise depend on row order.
func TestValidateRejectsAliasCollisions(t *testing.T) {
	err := Validate([]Binding{
		{Product: "Foo"},
		{Product: "Bar", Aliases: []string{"foo"}},
	})
	if err == nil {
		t.Fatal("expected a collision error")
	}
}

func TestDefaultsListsBuiltinTable(t *testing.T) {
	cap, _ := NewCapability(core.Deps{})
	res, err := cap.Call(context.Background(), core.Call{Tool: "binding_defaults"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	var data struct {
		Count    int       `json:"count"`
		Bindings []Binding `json:"bindings"`
	}
	_ = json.Unmarshal(res.Data, &data)
	if data.Count != len(DefaultBindings) || len(data.Bindings) != data.Count {
		t.Fatalf("count = %d, bindings = %d", data.Count, len(data.Bindings))
	}
}
