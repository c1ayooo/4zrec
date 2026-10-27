package core_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// registeredSpecs returns every tool spec across the full registry, so the
// contract invariants are checked against real declarations, not fixtures.
func registeredSpecs(t *testing.T) []core.ToolSpec {
	t.Helper()
	reg := core.NewRegistry()
	if err := all.RegisterFull(reg); err != nil {
		t.Fatalf("RegisterFull: %v", err)
	}
	var out []core.ToolSpec
	for _, spec := range reg.Specs() {
		for _, tool := range spec.Manifest.Tools {
			// give each tool a unique owner so duplicates surface as test failures
			out = append(out, tool)
		}
	}
	return out
}

// TestEveryToolHasValidSchemas is the §8 gate: each registered tool declares a
// non-empty, valid JSON Schema for both input and output.
func TestEveryToolHasValidSchemas(t *testing.T) {
	specs := registeredSpecs(t)
	if len(specs) == 0 {
		t.Fatal("no tools registered")
	}
	seen := map[string]bool{}
	for _, tool := range specs {
		if seen[tool.Name] {
			t.Fatalf("duplicate tool name across kits: %s", tool.Name)
		}
		seen[tool.Name] = true
		if strings.TrimSpace(tool.Description) == "" {
			t.Errorf("%s: empty description", tool.Name)
		}
		if !tool.Risk.Valid() {
			t.Errorf("%s: invalid risk %q", tool.Name, tool.Risk)
		}
		for label, raw := range map[string]json.RawMessage{
			"input_schema":  tool.InputSchema,
			"output_schema": tool.OutputSchema,
		} {
			if len(raw) == 0 {
				t.Errorf("%s: empty %s", tool.Name, label)
				continue
			}
			var v map[string]any
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Errorf("%s: %s is not valid JSON: %v", tool.Name, label, err)
				continue
			}
			if v["type"] != "object" {
				t.Errorf("%s: %s type = %v, want object", tool.Name, label, v["type"])
			}
		}
	}
}

// TestResultContractFilesExistAndParse verifies the published contract files.
func TestResultContractFilesExistAndParse(t *testing.T) {
	for _, name := range []string{"result.json", "output.json", "tool.json", "target.json"} {
		path := filepath.Join("..", "contracts", name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("%s is not valid JSON: %v", path, err)
		}
	}
}

// TestStatusForErrorMapping locks the code->status contract from §5.5.2/§5.5.3.
func TestStatusForErrorMapping(t *testing.T) {
	cases := map[string]core.Status{
		core.CodeScopeDenied:         core.StatusBlocked,
		core.CodeApprovalRequired:    core.StatusBlocked,
		core.CodeRateLimited:         core.StatusBlocked,
		core.CodeUnavailable:         core.StatusUnavailable,
		core.CodeToolMissing:         core.StatusUnavailable,
		core.CodeNeedHuman:           core.StatusNeedHuman,
		core.CodeTargetUnreachable:   core.StatusFailed,
		core.CodeTimeout:             core.StatusFailed,
		core.CodeInvalidInput:        core.StatusFailed,
		core.CodeInternal:            core.StatusFailed,
		core.CodeEvidenceWriteFailed: core.StatusFailed,
	}
	for code, want := range cases {
		if got := core.StatusForError(core.NewError(code, "x")); got != want {
			t.Errorf("StatusForError(%s) = %s, want %s", code, got, want)
		}
	}
	// scope_denied must never be retryable: the agent must not loop on it.
	if e := core.ScopeDenied("x"); e.Retryable {
		t.Error("scope_denied must not be retryable")
	}
	if e := core.NewError(core.CodeApprovalRequired, "x"); e.Retryable {
		t.Error("approval_required must not be retryable")
	}
}

// TestSummaryClamp keeps Summary within the agent-readable bound.
func TestSummaryClamp(t *testing.T) {
	long := strings.Repeat("测", 500)
	got := core.ClampSummary(long)
	if len([]rune(got)) > core.MaxSummaryRunes {
		t.Fatalf("clamped summary = %d runes", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("clamped summary should end with ellipsis: %q", got)
	}
	if core.ClampSummary("short") != "short" {
		t.Fatal("short summary must pass through unchanged")
	}
}

// TestFailResultCarriesStatus ensures error atoms map to the right status.
func TestFailResultCarriesStatus(t *testing.T) {
	res := core.FailResult(core.ScopeDenied("out of scope"))
	if res.Status != core.StatusBlocked || res.OK {
		t.Fatalf("status/ok = %s/%v", res.Status, res.OK)
	}
	if res.Summary == "" || res.Error == nil {
		t.Fatal("blocked result needs summary and error")
	}
}

// TestNormalizeStampsEveryReturnPath locks the helper kits call once in their
// dispatcher: whatever a handler returned, the envelope that leaves the kit has
// a valid Status, a consistent OK, and a Meta naming the tool.
func TestNormalizeStampsEveryReturnPath(t *testing.T) {
	cases := []struct {
		name       string
		in         core.Result
		wantStatus core.Status
		wantOK     bool
	}{
		{"zero value fails closed", core.Result{}, core.StatusFailed, false},
		{"legacy ok only", core.Result{OK: true}, core.StatusSuccess, true},
		{"error drives status", core.Result{Error: core.ScopeDenied("x")}, core.StatusBlocked, false},
		{"explicit status wins", core.Result{OK: true, Status: core.StatusPartial}, core.StatusPartial, true},
		{"stale ok is corrected", core.Result{OK: true, Error: core.Unavailable("x")}, core.StatusUnavailable, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.Normalize("http_probe", "0.1.0")
			if got.Status != tc.wantStatus || got.OK != tc.wantOK {
				t.Fatalf("status/ok = %s/%v, want %s/%v", got.Status, got.OK, tc.wantStatus, tc.wantOK)
			}
			if got.Meta.Tool != "http_probe" || got.Meta.Version != "0.1.0" {
				t.Fatalf("meta = %+v", got.Meta)
			}
		})
	}
	// A call that already named its tool keeps that name (the runtime's
	// back-fill must never overwrite a kit that got there first).
	kept := core.Result{Meta: core.Meta{Tool: "other"}}.Normalize("http_probe", "v")
	if kept.Meta.Tool != "other" {
		t.Fatalf("existing Meta.Tool was overwritten: %+v", kept.Meta)
	}
}
