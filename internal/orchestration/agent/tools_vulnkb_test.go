package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

func TestSearchVulnKBFingerprintGate(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	const domain = "gate-agent.example"
	const intelKey = "zz-test:gate-agent"
	cleanup := func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE domain = $1`, domain)
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
	if _, err := d.UpsertVulnIntel(db.VulnIntel{
		UniqueKey: intelKey, Title: "Demo OA RCE", Description: "Demo OA test advisory",
		Severity: "high", CVE: "CVE-2025-9999", Source: "test",
		SourceURL: "https://example.com/advisory", Tags: `["demo"]`,
		Refs: `["https://example.com/ref"]`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE vuln_intel SET github_poc = $1::jsonb WHERE unique_key = $2`,
		`[{"full_name":"demo/poc","url":"https://github.com/demo/poc","stars":7}]`, intelKey); err != nil {
		t.Fatal(err)
	}

	tools := NewToolSet(nil, "")
	tools.SetAssetStore(d.Assets(), d.Companies())
	tool := tools.searchVulnKB()
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 424242})

	call := func(ctx context.Context, input string) ResultText {
		res, err := tool.Call(ctx, json.RawMessage(input), nil)
		if err != nil {
			t.Fatalf("tool error: %v", err)
		}
		return ResultText{text: res.Flatten(), isError: res.IsError}
	}

	if got := call(ctx, `{"q":"Demo OA"}`); got.isError {
		t.Fatalf("recognized product should pass: %s", got.text)
	} else if !strings.Contains(got.text, "CVE-2025-9999") || !strings.Contains(got.text, "https://github.com/demo/poc") {
		t.Fatalf("intel POC should be included: %s", got.text)
	}
	if got := call(ctx, `{"q":"通达OA"}`); !got.isError || !strings.Contains(got.text, "不在已识别指纹") {
		t.Fatalf("unrecognized product should be gated: %v %s", got.isError, got.text)
	}
	if got := call(ctx, `{"q":"Demo OA","target":"http://`+domain+`"}`); got.isError {
		t.Fatalf("recognized target should pass: %s", got.text)
	}
	if got := call(ctx, `{"q":"Demo OA","target":"http://unknown.example"}`); !got.isError {
		t.Fatalf("unrecognized target should be gated: %s", got.text)
	}
	if got := call(context.Background(), `{"q":"Demo OA"}`); !got.isError {
		t.Fatalf("no task fingerprint evidence should be gated: %s", got.text)
	}
}

type ResultText struct {
	text    string
	isError bool
}
