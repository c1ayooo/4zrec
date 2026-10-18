package db

import (
	"testing"
)

func TestFingerprintEvidence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	const domain = "gate-test.example"
	cleanup := func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE domain = $1`, domain)
	}
	cleanup()
	defer cleanup()

	as := d.Assets()
	if _, err := as.UpsertHTTPService(UpsertHTTPServiceReq{
		URL:          "http://" + domain,
		Technologies: []string{"Demo OA", "Nginx"},
		TaskID:       424242,
	}); err != nil {
		t.Fatalf("upsert http service: %v", err)
	}

	evidence, err := as.TechnologiesForTargets([]string{
		"http://" + domain,
		"http://" + domain + ":8080",
		domain,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence["http://"+domain]) != 2 {
		t.Fatalf("exact target evidence = %v", evidence)
	}
	if len(evidence[domain]) != 2 {
		t.Fatalf("bare target evidence = %v", evidence)
	}
	if len(evidence["http://"+domain+":8080"]) != 0 {
		t.Fatalf("explicit port must not inherit host evidence: %v", evidence)
	}

	scope, err := as.TechnologiesForScope(424242, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(scope) != 2 || scope[0] != "Demo OA" || scope[1] != "Nginx" {
		t.Fatalf("scope evidence = %v", scope)
	}

	// No task/project scope must return no evidence rather than global data.
	if scope, err := as.TechnologiesForScope(0, 0); err != nil || len(scope) != 0 {
		t.Fatalf("empty scope = %v, %v", scope, err)
	}
}
