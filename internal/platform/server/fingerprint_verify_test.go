package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/nuclei"
)

func writeVerifyTemplate(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSelectFingerprintTemplates(t *testing.T) {
	dir := t.TempDir()
	writeVerifyTemplate(t, dir, "weaver-test.yaml", `
id: weaver-test
info:
  name: Weaver OA Test Check
  severity: high
  tags: weaver,oa
  classification:
    cve-id: CVE-2024-1111
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)
	writeVerifyTemplate(t, dir, "other-test.yaml", `
id: other-test
info:
  name: Other Product Check
  severity: high
  tags: other
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)
	writeVerifyTemplate(t, dir, "weaver-dos.yaml", `
id: weaver-dos
info:
  name: Weaver OA DoS Check
  severity: high
  tags: weaver,dos
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)
	idx := nuclei.NewIndex(dir)
	techs := []string{"Weaver OA"}

	if err := validateFingerprintScanInput("", "", techs, false, 1, 0); err == nil {
		t.Fatal("missing based_on_product/cve must be rejected")
	}
	if err := validateFingerprintScanInput("Unknown", "", techs, false, 1, 0); err == nil {
		t.Fatal("unknown product must be rejected")
	}
	if err := validateFingerprintScanInput("Weaver", "", techs, true, 1, 0); err == nil {
		t.Fatal("automatic must be rejected")
	}
	if err := validateFingerprintScanInput("Weaver", "not-a-cve", techs, false, 1, 0); err == nil {
		t.Fatal("invalid CVE must be rejected")
	}

	items, err := selectFingerprintTemplates(idx, nil, "Weaver", "", techs, nuclei.Filters{}, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "weaver-test" {
		t.Fatalf("product auto-select = %+v, want weaver-test only", items)
	}

	items, err = selectFingerprintTemplates(idx, nil, "", "CVE-2024-1111", techs, nuclei.Filters{}, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "weaver-test" {
		t.Fatalf("cve auto-select = %+v, want weaver-test only", items)
	}

	if _, err := selectFingerprintTemplates(idx, []string{"other-test"}, "Weaver", "", techs, nuclei.Filters{}, nil, 20); err == nil {
		t.Fatal("explicit unrelated template must be rejected")
	}
	items, err = selectFingerprintTemplates(idx, []string{"weaver-test"}, "Weaver", "", techs, nuclei.Filters{}, nil, 20)
	if err != nil || len(items) != 1 || items[0].ID != "weaver-test" {
		t.Fatalf("explicit related template = %+v, %v", items, err)
	}

	plan := fingerprintPlanLine("Weaver", "CVE-2024-1111", techs, []string{"weaver-test"})
	for _, want := range []string{"Weaver", "CVE-2024-1111", "weaver-test"} {
		if !strings.Contains(plan, want) {
			t.Fatalf("plan missing %q: %s", want, plan)
		}
	}

	evidence := map[string][]string{
		"https://a.example": {"Weaver OA"},
		"https://b.example": {"Other Product"},
	}
	if err := validateProductOnTargets(evidence, "Weaver"); err == nil || !strings.Contains(err.Error(), "b.example") {
		t.Fatalf("mixed targets should reject the unrecognized one: %v", err)
	}
	if err := validateProductOnTargets(map[string][]string{"https://a.example": {"Weaver OA"}}, "Weaver"); err != nil {
		t.Fatalf("recognized target should pass: %v", err)
	}
}
