package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/nuclei"
	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/orchestration/agent"
)

func TestFingerprintVerifyPlan(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	const (
		domain   = "verify-plan.example"
		kbHash   = "zz-test:verify-plan-kb"
		intelKey = "zz-test:verify-plan-intel"
	)
	cleanup := func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE domain = $1`, domain)
		_, _ = d.Exec(`DELETE FROM vuln_kb WHERE content_hash = $1`, kbHash)
		_, _ = d.Exec(`DELETE FROM vuln_intel WHERE unique_key = $1`, intelKey)
	}
	cleanup()
	defer cleanup()

	if _, err := d.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL:          "http://" + domain,
		Technologies: []string{"Demo OA"},
		TaskID:       424242,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertVulnKB(db.VulnKBEntry{
		ContentHash: kbHash, Title: "Demo OA RCE", Product: "Demo OA",
		VulnType: "命令执行", CVE: "CVE-2025-9999", RequestLine: "GET /x HTTP/1.1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertVulnIntel(db.VulnIntel{
		UniqueKey: intelKey, Title: "Demo OA RCE advisory", Description: "Demo OA test",
		Severity: "high", CVE: "CVE-2025-9999", Source: "test",
		SourceURL: "https://example.com/advisory", Tags: `["demo"]`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE vuln_intel SET github_poc = $1::jsonb WHERE unique_key = $2`,
		`[{"full_name":"demo/poc","url":"https://github.com/demo/poc","stars":7}]`, intelKey); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	mgr := nuclei.New(filepath.Join(root, "nuclei"), nil)
	if err := os.MkdirAll(mgr.CustomTemplatesDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	template := `
id: demo-oa-check
info:
  name: Demo OA Check
  severity: high
  tags: demo,oa
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`
	if err := os.WriteFile(filepath.Join(mgr.CustomTemplatesDir(), "demo-oa-check.yaml"), []byte(template), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		dataDir:   root,
		m:         &Manager{pg: d, assets: d.Assets()},
		nucleiMgr: mgr,
	}
	tool := s.toolFingerprintVerify()
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 424242})

	res, err := tool.Call(ctx, json.RawMessage(`{"targets":["http://`+domain+`"]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("plan should succeed: %s", res.Flatten())
	}
	text := res.Flatten()
	for _, want := range []string{"Demo OA", "CVE-2025-9999", "https://github.com/demo/poc", "demo-oa-check"} {
		if !strings.Contains(text, want) {
			t.Fatalf("plan missing %q:\n%s", want, text)
		}
	}

	res, err = tool.Call(ctx, json.RawMessage(`{"targets":["http://unknown.example"]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("unrecognized target must be rejected: %s", res.Flatten())
	}
}
