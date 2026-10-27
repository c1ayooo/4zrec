package playbook

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/gates"
)

func TestRunScopeDenied(t *testing.T) {
	pb := &Playbook{ID: "scope", Steps: []Step{{
		Name: "s", Kind: StepKindHTTP,
		Request: StepRequest{Method: "GET", URL: "http://evil.com/"},
		Expect:  &Expectation{Status: 200},
	}}}
	res, err := Run(context.Background(), pb, RunOptions{
		Vars:  map[string]string{"host": "x"},
		Scope: gates.StaticScope("example.com"),
	})
	if err == nil {
		t.Fatal("expected scope error")
	}
	if res == nil || res.Verdict != VerdictBlocked {
		t.Fatalf("res = %+v", res)
	}
}
