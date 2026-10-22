package fingerprint

import (
	"testing"
)

// These tests cover the ActiveRules fix without a database. The bug was a
// branch condition, and the branch is "has upstream ever synced" — the part
// that runs before any SQL is the merge itself, which is pure slice logic.
//
// The DB-backed path (a custom rule arriving before the first upstream sync)
// is covered by internal/platform/server, which already runs against a real
// Postgres.

// TestMergeWithDefaultsAddsRatherThanReplaces pins the fix: one custom rule
// arriving before the first upstream sync must be added to the built-in
// snapshot. The old code compared the rule count and returned the snapshot
// alone, so the built-in 7,587 rules stopped matching the moment a human
// confirmed the first intel fingerprint.
func TestMergeWithDefaultsAddsRatherThanReplaces(t *testing.T) {
	builtin := len(DefaultRules())
	custom := []CompiledRule{{
		ID: "fp_test", Name: "某厂商产品", Expression: `title ~= "某厂商产品"`,
	}}
	out := mergeWithDefaults(custom)
	if len(out) != builtin+1 {
		t.Fatalf("merged = %d rules, want %d (built-in %d + 1 custom)",
			len(out), builtin+1, builtin)
	}
	if out[len(out)-1].ID != "fp_test" {
		t.Fatal("the custom rule should be the last entry, so it shadows any built-in with the same name")
	}
}

// TestMergeWithDefaultsDropsDuplicates pins that a custom rule replacing a
// built-in of the same name does not double-match.
func TestMergeWithDefaultsDropsDuplicates(t *testing.T) {
	dup := DefaultRules()[0]
	out := mergeWithDefaults([]CompiledRule{dup})
	if len(out) != len(DefaultRules()) {
		t.Fatalf("a duplicate built-in rule should replace, not append: got %d, want %d",
			len(out), len(DefaultRules()))
	}
}

// TestMergeWithDefaultsDoesNotMutateSharedSlice pins that the process-wide
// snapshot is never modified. It is compiled once and shared by every caller;
// an append into it would leak one caller's custom rules into everyone else's
// match set.
func TestMergeWithDefaultsDoesNotMutateSharedSlice(t *testing.T) {
	before := len(DefaultRules())
	_ = mergeWithDefaults([]CompiledRule{{ID: "x", Name: "x", Expression: `title ~= "x"`}})
	_ = mergeWithDefaults([]CompiledRule{{ID: "y", Name: "y", Expression: `title ~= "y"`}})
	if got := len(DefaultRules()); got != before {
		t.Fatalf("DefaultRules() grew from %d to %d: the shared slice was mutated", before, got)
	}
}

// TestMergeWithDefaultsEmptyStore pins the degenerate case: no rules in the
// store yields exactly the built-in snapshot, not an empty match set.
func TestMergeWithDefaultsEmptyStore(t *testing.T) {
	out := mergeWithDefaults(nil)
	if len(out) != len(DefaultRules()) {
		t.Fatalf("empty store should yield the built-in snapshot: got %d, want %d",
			len(out), len(DefaultRules()))
	}
}

// TestActiveRulesWithoutAStore pins the no-database branch: matching must never
// come back empty, because an empty rule set reports every target as
// unrecognized and quietly disables the whole fingerprint pipeline.
func TestActiveRulesWithoutAStore(t *testing.T) {
	rules := ActiveRules(nil)
	if len(rules) == 0 {
		t.Fatal("ActiveRules(nil) returned no rules")
	}
	if len(rules) != len(DefaultRules()) {
		t.Fatalf("ActiveRules(nil) = %d rules, want the built-in %d",
			len(rules), len(DefaultRules()))
	}
}
