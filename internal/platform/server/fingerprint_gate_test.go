package server

import (
	"context"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/orchestration/agent"
)

func TestFingerprintGate(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
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

	if _, err := d.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL:          "http://" + domain,
		Technologies: []string{"Demo OA", "Nginx"},
		TaskID:       424242,
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{pg: d, assets: d.Assets()}}

	if _, err := s.requireTargetFingerprints([]string{"http://" + domain}); err != nil {
		t.Fatalf("recognized target should pass: %v", err)
	}
	if _, err := s.requireTargetFingerprints([]string{"http://" + domain + ":8080"}); err == nil {
		t.Fatal("explicit unrecognized port must be rejected")
	} else if !strings.Contains(err.Error(), "fingerprint_scan") {
		t.Fatalf("rejection should point at fingerprint_scan: %v", err)
	}

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 424242})
	if _, err := s.requireSearchFingerprint(ctx, 0, nil, "Demo OA", ""); err != nil {
		t.Fatalf("recognized product should pass: %v", err)
	}
	if _, err := s.requireSearchFingerprint(ctx, 0, nil, "通达OA", ""); err == nil {
		t.Fatal("unrecognized product must be rejected")
	}
	if _, err := s.requireSearchFingerprint(ctx, 0, nil, "", "CVE-2024-0001"); err != nil {
		t.Fatalf("CVE lookup with recognition evidence should pass: %v", err)
	}
	if _, err := s.requireSearchFingerprint(ctx, 0, []string{"http://" + domain}, "Demo OA", ""); err != nil {
		t.Fatalf("recognized target should pass search gate: %v", err)
	}
	if _, err := s.requireSearchFingerprint(ctx, 0, []string{"http://unknown.example"}, "Demo OA", ""); err == nil {
		t.Fatal("unrecognized target must be rejected")
	}
}
