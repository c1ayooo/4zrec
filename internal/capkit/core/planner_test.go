package core_test

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

func confirmed(kind string) core.Finding {
	return core.Finding{Kind: kind, Confirmed: true}
}

// TestDefaultPlannerOnlyAdvisesConfirmed locks the fail-closed rule: an
// unconfirmed finding yields no suggestion, so an agent never acts on a guess.
func TestDefaultPlannerOnlyAdvisesConfirmed(t *testing.T) {
	p := core.DefaultPlanner()
	steps, err := p.Suggest(context.Background(), core.Finding{Kind: "cmdi", Confirmed: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 0 {
		t.Fatalf("unconfirmed finding produced %d steps", len(steps))
	}
}

func TestDefaultPlannerCoversKnownKinds(t *testing.T) {
	p := core.DefaultPlanner()
	for _, kind := range []string{"cmdi", "sqli", "lfi", "ssrf", "upload", "deser"} {
		steps, err := p.Suggest(context.Background(), confirmed(kind))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if len(steps) == 0 {
			t.Errorf("%s: no candidate action", kind)
		}
		for _, s := range steps {
			if s.Tool == "" || s.Reason == "" {
				t.Errorf("%s: incomplete step %+v", kind, s)
			}
			if !s.Risk.Valid() {
				t.Errorf("%s: invalid risk %q", kind, s.Risk)
			}
		}
	}
	// An unknown kind is fine; it just yields nothing.
	steps, _ := p.Suggest(context.Background(), confirmed("totally-unknown"))
	if len(steps) != 0 {
		t.Fatalf("unknown kind produced %d steps", len(steps))
	}
	// A planner aware of a doc-only tool name must still resolve to a real one.
	steps, _ = p.Suggest(context.Background(), confirmed("ssrf"))
	found := false
	for _, s := range steps {
		if s.Tool == "inet_portscan" {
			found = true
		}
	}
	if !found {
		t.Error("ssrf should suggest inet_portscan (a registered tool)")
	}
}

func TestChainPlannerDedupesByToolAndPreservesPriority(t *testing.T) {
	first := core.PlannerFunc(func(context.Context, core.Finding) ([]core.NextStep, error) {
		return []core.NextStep{{Tool: "a"}, {Tool: "b"}}, nil
	})
	second := core.PlannerFunc(func(context.Context, core.Finding) ([]core.NextStep, error) {
		return []core.NextStep{{Tool: "b"}, {Tool: "c"}}, nil
	})
	chain := &core.ChainPlanner{}
	chain.Add(first)
	chain.Add(nil) // nil is ignored
	chain.Add(second)
	steps, err := chain.Suggest(context.Background(), confirmed("x"))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, s := range steps {
		got = append(got, s.Tool)
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestChainPlannerPropagatesError(t *testing.T) {
	boom := core.PlannerFunc(func(context.Context, core.Finding) ([]core.NextStep, error) {
		return nil, context.Canceled
	})
	chain := &core.ChainPlanner{}
	chain.Add(boom)
	if _, err := chain.Suggest(context.Background(), confirmed("x")); err == nil {
		t.Fatal("expected the planner error to propagate")
	}
}

func TestDedupeNext(t *testing.T) {
	got := core.DedupeNext(
		[]core.NextStep{{Tool: "a"}, {Tool: ""}, {Tool: "b"}},
		[]core.NextStep{{Tool: "b"}, {Tool: "c"}},
	)
	if len(got) != 3 {
		t.Fatalf("deduped to %d, want 3: %+v", len(got), got)
	}
	if got[0].Tool != "a" || got[1].Tool != "b" || got[2].Tool != "c" {
		t.Fatalf("order = %+v", got)
	}
}

func TestSortByRisk(t *testing.T) {
	in := []core.NextStep{
		{Tool: "low", Risk: core.RiskLow},
		{Tool: "high", Risk: core.RiskHigh},
		{Tool: "med", Risk: core.RiskMedium},
	}
	out := core.SortByRisk(in)
	if out[0].Tool != "high" || out[1].Tool != "med" || out[2].Tool != "low" {
		t.Fatalf("order = %v", []string{out[0].Tool, out[1].Tool, out[2].Tool})
	}
	// The input slice is not mutated.
	if in[0].Tool != "low" {
		t.Fatal("SortByRisk mutated its input")
	}
}
