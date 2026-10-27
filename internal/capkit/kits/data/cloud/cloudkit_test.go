package cloud

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/harness"
)

// These tests drive the kit's own tools — the dispatch layer, the envelope each
// tool builds, and the credential rules — with the harness fakes. They are the
// half of the kit the per-vendor tests do not reach: those call a provider
// directly, these call the tool an agent actually invokes.

// kitWith builds a kit whose HTTP port is the given fake and whose evidence port
// is a recording fake.
func kitWith(t *testing.T, fake *harness.HTTP, ev *harness.Evidence) *Kit {
	t.Helper()
	return New(core.Deps{HTTP: fake, Evidence: ev, Clock: &harness.Clock{Now_: harness.DefaultTime}})
}

// callTool invokes one tool the way an agent would and returns the envelope.
func callTool(t *testing.T, k *Kit, tool string, input string) core.Result {
	t.Helper()
	res, err := k.Call(context.Background(), core.Call{Tool: tool, Input: json.RawMessage(input)})
	if err != nil {
		t.Fatalf("%s returned a transport error: %v", tool, err)
	}
	return res
}

// dataOf decodes the envelope's Data for field assertions.
func dataOf(t *testing.T, res core.Result) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("Data is not a JSON object (%q): %v", res.Data, err)
	}
	return out
}

const verifyInputTemplate = `{"provider":"aws","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","region":"us-east-1"}`

// ────────────────────────── envelope / masking ──────────────────────────

// TestKitVerifyMasksTheAK is the credential rule at the envelope level: the
// Summary an agent reads carries the masked AK, never the caller's key.
func TestKitVerifyMasksTheAK(t *testing.T) {
	fake := harness.NewHTTP(200, awsCallerIdentityXML)
	k := kitWith(t, fake, nil)

	res := callTool(t, k, "cloud_ak_verify", verifyInputTemplate)
	if res.Status != core.StatusSuccess {
		t.Fatalf("Status = %s, want success (error=%+v)", res.Status, res.Error)
	}
	if res.Meta.Tool != "cloud_ak_verify" || res.Meta.Version != kitVersion {
		t.Errorf("Meta = %+v, want tool=cloud_ak_verify version=%s", res.Meta, kitVersion)
	}
	if strings.Contains(res.Summary, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("Summary leaks the raw AK: %q", res.Summary)
	}
	masked := maskAK("AKIAIOSFODNN7EXAMPLE")
	if !strings.Contains(res.Summary, masked) {
		t.Errorf("Summary %q does not carry the masked AK %q", res.Summary, masked)
	}
	if !strings.Contains(res.Summary, "123456789012") || !strings.Contains(res.Summary, "iam_user") {
		t.Errorf("Summary %q does not state the account and identity type", res.Summary)
	}
	// The same masking applies inside Data, and the raw secret never appears.
	data := dataOf(t, res)
	if data["ak_masked"] != masked {
		t.Errorf("data.ak_masked = %v, want %v", data["ak_masked"], masked)
	}
	if strings.Contains(string(res.Data), "wJalrXUtnFEMI") {
		t.Fatalf("Data leaks the secret key")
	}
	if len(res.Next) == 0 {
		t.Error("a verified credential should suggest the read-only follow-ups")
	}
}

// TestKitVerifyFailureKeepsMaskAndReason covers the failure envelope: the agent
// is told why, in the normalized vocabulary, without the credential.
func TestKitVerifyFailureKeepsMaskAndReason(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 403, Body: `<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid</Message></Error></ErrorResponse>`}}
	k := kitWith(t, fake, nil)

	res := callTool(t, k, "cloud_ak_verify", verifyInputTemplate)
	if res.Status != core.StatusFailed {
		t.Fatalf("Status = %s, want failed", res.Status)
	}
	if res.Error == nil {
		t.Fatal("no Error on a failed verification")
	}
	// The agent-facing distinction is the reason phrase; the code is the stable
	// enum entry the host switches on.
	if !strings.Contains(res.Error.Message, ReasonInvalidCredential.Label()) {
		t.Errorf("Error.Message %q does not say the credential is invalid", res.Error.Message)
	}
	if res.Error.Code != core.CodeUpstreamError {
		t.Errorf("Error.Code = %s, want %s (invalid credential maps onto the enum, not a bug)", res.Error.Code, core.CodeUpstreamError)
	}
	// Not retryable: replaying a wrong key changes nothing, so the agent is
	// nudged to fix the input rather than to try again.
	if res.Error.Retryable {
		t.Error("an invalid credential must not be marked retryable")
	}
	if res.Error.Hint == "" {
		t.Error("no Hint telling the agent how to fix the input")
	}
	if !strings.Contains(res.Error.Detail, "InvalidClientTokenId") {
		t.Errorf("Error.Detail = %q, want the raw vendor code for the developer", res.Error.Detail)
	}
	if strings.Contains(res.Error.Message, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("Error.Message leaks the raw AK: %q", res.Error.Message)
	}
	if !strings.Contains(res.Error.Message, maskAK("AKIAIOSFODNN7EXAMPLE")) {
		t.Errorf("Error.Message %q does not identify the masked AK", res.Error.Message)
	}
	if strings.Contains(res.Error.Message, "wJalrXUtnFEMI") {
		t.Fatalf("Error.Message leaks the secret: %q", res.Error.Message)
	}
}

// TestKitScopeDenialIsNotReclassified is the gate rule: an error the host's own
// gate raised (blocked / rate limited / timeout) keeps its code instead of being
// rewritten as a vendor failure, so the agent does not retry what it must not.
func TestKitScopeDenialIsNotReclassified(t *testing.T) {
	fake := harness.NewHTTP(200, awsCallerIdentityXML)
	fake.Err = core.ScopeDenied("目标不在授权范围")
	k := kitWith(t, fake, nil)

	res := callTool(t, k, "cloud_ak_verify", verifyInputTemplate)
	if res.Status != core.StatusBlocked {
		t.Fatalf("Status = %s, want blocked", res.Status)
	}
	if res.Error == nil || res.Error.Code != core.CodeScopeDenied {
		t.Fatalf("Error = %+v, want code %s", res.Error, core.CodeScopeDenied)
	}
	if res.Error.Retryable {
		t.Error("a scope denial must not be marked retryable")
	}
}

// TestKitUnavailableWithoutDoer covers a host that registered cloudkit but
// injected no HTTP port: the tools say so rather than dialing a vendor.
func TestKitUnavailableWithoutDoer(t *testing.T) {
	k := New(core.Deps{})
	for _, tool := range []string{"cloud_ak_verify", "cloud_asset_list", "cloud_iam_list", "cloud_run_command", "cloud_storage_list"} {
		res := callTool(t, k, tool, verifyInputTemplate)
		if res.Status != core.StatusUnavailable {
			t.Errorf("%s: Status = %s, want unavailable", tool, res.Status)
		}
		if res.Error == nil || res.Error.Code != core.CodeUnavailable {
			t.Errorf("%s: Error = %+v, want code %s", tool, res.Error, core.CodeUnavailable)
		}
	}
}

// TestKitInputGuards covers the shared validation every tool runs before it
// touches a provider.
func TestKitInputGuards(t *testing.T) {
	fake := harness.NewHTTP(200, awsCallerIdentityXML)
	k := kitWith(t, fake, nil)

	cases := []struct {
		name  string
		tool  string
		input string
	}{
		{"unknown tool", "cloud_nope", verifyInputTemplate},
		{"malformed json", "cloud_ak_verify", `{"provider":`},
		{"missing provider", "cloud_ak_verify", `{"access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s"}`},
		{"unknown provider", "cloud_ak_verify", `{"provider":"gcp","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s"}`},
		{"missing key", "cloud_ak_verify", `{"provider":"aws","access_key":"","secret_key":""}`},
		{"asset list without region", "cloud_asset_list", `{"provider":"aws","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s"}`},
		{"run command without instance", "cloud_run_command", `{"provider":"aws","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s","command":"id"}`},
		{"run command without command", "cloud_run_command", `{"provider":"aws","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s","instance_id":"i-1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := fake.Calls()
			res := callTool(t, k, tc.tool, tc.input)
			if res.Error == nil {
				t.Fatalf("no Error: status=%s summary=%q", res.Status, res.Summary)
			}
			switch res.Status {
			case core.StatusFailed, core.StatusBlocked, core.StatusNeedHuman:
			default:
				t.Errorf("Status = %s, want a failure state", res.Status)
			}
			if res.Error.Code == "" {
				t.Error("Error.Code is empty; the agent cannot decide from it")
			}
			if fake.Calls() != before {
				t.Errorf("an invalid input reached the wire (%d -> %d calls)", before, fake.Calls())
			}
		})
	}
}

// ────────────────────────── cloud_asset_list ──────────────────────────

func TestKitListAssetsSummaryCounts(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: ""},
		Routes: []harness.Route{
			{Match: "ec2.us-east-1.amazonaws.com", Status: 200, Body: awsDescribeInstancesXML},
			{Match: "rds.us-east-1.amazonaws.com", Status: 200, Body: awsDescribeDBInstancesXML},
		},
	}
	k := kitWith(t, fake, nil)

	res := callTool(t, k, "cloud_asset_list", verifyInputTemplate)
	if res.Status != core.StatusSuccess {
		t.Fatalf("Status = %s (error=%+v)", res.Status, res.Error)
	}
	// The Summary must state what was asked for, what came back, and the counts.
	if !strings.Contains(res.Summary, "aws") || !strings.Contains(res.Summary, "us-east-1") {
		t.Errorf("Summary %q omits the target and region", res.Summary)
	}
	if !strings.Contains(res.Summary, "计算实例 2 台") || !strings.Contains(res.Summary, "数据库 1 个") {
		t.Errorf("Summary %q does not carry the per-kind counts", res.Summary)
	}
	if data := dataOf(t, res); data["count"].(float64) != 3 {
		t.Errorf("data.count = %v, want 3", data["count"])
	}
	if res.Page == nil || !res.Page.HasMore {
		t.Errorf("Page = %+v, want a continuation cursor", res.Page)
	}
}

// TestKitListAssetsPartialKeepsData covers the partial state: one service failed,
// the other answered, so the caller gets the data plus the warning.
func TestKitListAssetsPartialKeepsData(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: ""},
		Routes: []harness.Route{
			{Match: "ec2.us-east-1.amazonaws.com", Status: 200, Body: awsDescribeInstancesXML},
			{Match: "rds.us-east-1.amazonaws.com", Status: 403, Body: `<ErrorResponse><Error><Code>AccessDenied</Code><Message>not authorized</Message></Error></ErrorResponse>`},
		},
	}
	k := kitWith(t, fake, nil)

	res := callTool(t, k, "cloud_asset_list", verifyInputTemplate)
	if res.Status != core.StatusPartial {
		t.Fatalf("Status = %s, want partial", res.Status)
	}
	if !res.OK {
		t.Error("a partial result is still OK")
	}
	if res.Error != nil {
		t.Errorf("a partial result must not carry Error: %+v", res.Error)
	}
	if !strings.Contains(res.Summary, "RDS") {
		t.Errorf("Summary %q does not explain the partial failure", res.Summary)
	}
	if data := dataOf(t, res); data["count"].(float64) != 2 {
		t.Errorf("data.count = %v, want the 2 instances that did come back", data["count"])
	}
}

// TestKitListAssetsEmpty covers a region with nothing in it: a truthful zero, not
// a generic phrase.
func TestKitListAssetsEmpty(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 200, Body: `<?xml version="1.0"?><DescribeInstancesResponse><reservationSet/></DescribeInstancesResponse>`}}
	k := kitWith(t, fake, nil)

	res := callTool(t, k, "cloud_asset_list", verifyInputTemplate)
	if res.Status != core.StatusSuccess {
		t.Fatalf("Status = %s (error=%+v)", res.Status, res.Error)
	}
	if !strings.Contains(res.Summary, "未发现") {
		t.Errorf("Summary %q does not say the region is empty", res.Summary)
	}
	if res.Page != nil {
		t.Errorf("Page = %+v, want none when there is nothing to page", res.Page)
	}
}

// ────────────────────────── cloud_iam_list ──────────────────────────

func TestKitListIAMSummaryFlagsAdmins(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: awsListAttachedUserPoliciesXML},
		Queue: []harness.Route{
			{Body: awsListUsersXML},
			{Body: awsListPoliciesXML},
			{Body: awsListAccessKeysXML},
		},
	}
	k := kitWith(t, fake, nil)

	res := callTool(t, k, "cloud_iam_list", `{"provider":"aws","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("Status = %s (error=%+v)", res.Status, res.Error)
	}
	if !strings.Contains(res.Summary, "子用户 2 个") || !strings.Contains(res.Summary, "策略 2 条") {
		t.Errorf("Summary %q does not carry the per-category counts", res.Summary)
	}
	if !strings.Contains(res.Summary, "疑似管理员权限") {
		t.Errorf("Summary %q does not surface the admin hint", res.Summary)
	}
	// The admin finding is what justifies the high-risk follow-up, and it must be
	// declared as high risk so the host's approval gate applies.
	var found bool
	for _, next := range res.Next {
		if next.Tool == "cloud_run_command" {
			found = true
			if next.Risk != core.RiskHigh {
				t.Errorf("cloud_run_command suggested at risk %s, want high", next.Risk)
			}
		}
	}
	if !found {
		t.Errorf("no cloud_run_command follow-up for an administratively privileged user: %+v", res.Next)
	}
}

// ────────────────────────── cloud_run_command ──────────────────────────

// TestKitRunCommandLargeOutputGoesToEvidence is the evidence rule: the inline
// Data keeps a bounded prefix, the full output is recorded, and the Summary
// reports the real size so the agent knows it is not seeing everything.
func TestKitRunCommandLargeOutputGoesToEvidence(t *testing.T) {
	big := strings.Repeat("A", maxCommandOutput+512)
	invocation := `{"CommandId":"cmd-1","InstanceId":"i-0aaa1111","Status":"Success","ResponseCode":0,` +
		`"StandardOutputContent":"` + big + `","StandardErrorContent":""}`
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: invocation},
		Queue:   []harness.Route{{Body: awsSendCommandJSON}},
	}
	ev := &harness.Evidence{}
	k := kitWith(t, fake, ev)

	res := callTool(t, k, "cloud_run_command",
		`{"provider":"aws","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s","instance_id":"i-0aaa1111","command":"cat big.log"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("Status = %s (error=%+v)", res.Status, res.Error)
	}
	if !strings.Contains(res.Summary, "stdout "+itoa(maxCommandOutput+512)+" 字节") {
		t.Errorf("Summary %q does not report the true output size", res.Summary)
	}
	if !res.Truncated {
		t.Error("Truncated not set for output over the inline ceiling")
	}
	records := ev.Records()
	if len(records) != 1 {
		t.Fatalf("evidence records = %d, want 1", len(records))
	}
	if records[0].Kind != "command_output" {
		t.Errorf("evidence kind = %q", records[0].Kind)
	}
	if !strings.Contains(string(records[0].Data), big) {
		t.Error("the stored evidence does not carry the full output")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].ID != "ev-1" {
		t.Fatalf("Evidence refs = %+v, want one with id ev-1", res.Evidence)
	}
	inline := dataOf(t, res)["stdout"].(string)
	if len(inline) != maxCommandOutput {
		t.Errorf("inline stdout is %d bytes, want the %d-byte ceiling", len(inline), maxCommandOutput)
	}
	if dataOf(t, res)["evidence_id"] != "ev-1" {
		t.Errorf("data.evidence_id = %v, want ev-1", dataOf(t, res)["evidence_id"])
	}
}

// TestKitRunCommandSmallOutputStaysInline covers the common case: short output
// needs no evidence record.
func TestKitRunCommandSmallOutputStaysInline(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: awsInvocationSuccessJSON},
		Queue:   []harness.Route{{Body: awsSendCommandJSON}},
	}
	ev := &harness.Evidence{}
	k := kitWith(t, fake, ev)

	res := callTool(t, k, "cloud_run_command",
		`{"provider":"aws","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s","instance_id":"i-0aaa1111","command":"id"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("Status = %s (error=%+v)", res.Status, res.Error)
	}
	if res.Truncated {
		t.Error("short output must not be marked truncated")
	}
	if len(ev.Records()) != 0 {
		t.Errorf("short output recorded %d evidence items, want 0", len(ev.Records()))
	}
	if len(res.Evidence) != 0 {
		t.Errorf("Evidence = %+v, want none", res.Evidence)
	}
	if got := dataOf(t, res)["stdout"].(string); got != "uid=0(root)\n" {
		t.Errorf("stdout = %q", got)
	}
	// The instance is named in the Summary, so the operator can see what ran where.
	if !strings.Contains(res.Summary, "i-0aaa1111") || !strings.Contains(res.Summary, "cmd-1") {
		t.Errorf("Summary %q omits the instance or command id", res.Summary)
	}
}

// TestKitRunCommandEvidenceFailureIsNotFatal covers an evidence store that is
// down: the command result still comes back, just without a reference.
func TestKitRunCommandEvidenceFailureIsNotFatal(t *testing.T) {
	big := strings.Repeat("B", maxCommandOutput+1)
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: `{"CommandId":"cmd-1","InstanceId":"i-1","Status":"Success","ResponseCode":0,"StandardOutputContent":"` + big + `","StandardErrorContent":""}`},
		Queue:   []harness.Route{{Body: awsSendCommandJSON}},
	}
	ev := &harness.Evidence{Err: core.Unavailable("evidence store down")}
	k := kitWith(t, fake, ev)

	res := callTool(t, k, "cloud_run_command",
		`{"provider":"aws","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s","instance_id":"i-1","command":"id"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("Status = %s, want success even when evidence could not be stored", res.Status)
	}
	if len(res.Evidence) != 0 {
		t.Errorf("Evidence = %+v, want none when the store failed", res.Evidence)
	}
}

// TestKitRunCommandIsHighRisk covers the manifest contract behind the approval
// gate: the runtime only gate-checks what the manifest declares.
func TestKitRunCommandIsHighRisk(t *testing.T) {
	var spec *core.ToolSpec
	manifest := New(core.Deps{}).Manifest()
	for i := range manifest.Tools {
		if manifest.Tools[i].Name == "cloud_run_command" {
			spec = &manifest.Tools[i]
		}
	}
	if spec == nil {
		t.Fatal("cloud_run_command missing from the manifest")
	}
	if spec.Risk != core.RiskHigh {
		t.Fatalf("cloud_run_command risk = %s, want high", spec.Risk)
	}
	if spec.RateLimit.PerSecond <= 0 {
		t.Error("a command tool should carry its own rate limit")
	}
	if spec.ExtractTargets == nil {
		t.Fatal("cloud_run_command must declare ExtractTargets so the instance is scope-checked")
	}
	targets, err := spec.ExtractTargets(json.RawMessage(`{"instance_id":"i-0AAA1111"}`))
	if err != nil {
		t.Fatalf("ExtractTargets: %v", err)
	}
	if len(targets) != 1 || targets[0].Host != "i-0aaa1111" {
		t.Fatalf("targets = %+v, want the lowercased instance id", targets)
	}
	// No tool may declare a write action: the surface is read-only by design.
	for _, tool := range manifest.Tools {
		low := strings.ToLower(tool.Name)
		for _, verb := range []string{"delete", "create", "update", "attach", "detach", "stop", "start", "terminate", "modify", "put"} {
			if strings.Contains(low, verb) {
				t.Errorf("tool %q looks like a write action; the cloud surface is read-only apart from cloud_run_command", tool.Name)
			}
		}
	}
}

// ────────────────────────── cloud_storage_list ──────────────────────────

func TestKitListStorageSummary(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 200, Body: awsListBucketsXML}}
	k := kitWith(t, fake, nil)

	res := callTool(t, k, "cloud_storage_list", `{"provider":"aws","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("Status = %s (error=%+v)", res.Status, res.Error)
	}
	if !strings.Contains(res.Summary, "对象存储桶 2 个") {
		t.Errorf("Summary %q does not carry the bucket count", res.Summary)
	}
}

// TestKitListStorageObjectsSummary covers the bucket-scoped form: the Summary
// names the bucket and prefix, which is what makes the count interpretable.
func TestKitListStorageObjectsSummary(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 200, Body: awsListObjectsXML}}
	k := kitWith(t, fake, nil)

	res := callTool(t, k, "cloud_storage_list",
		`{"provider":"aws","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s","bucket":"my-bucket","prefix":"logs/"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("Status = %s (error=%+v)", res.Status, res.Error)
	}
	if !strings.Contains(res.Summary, "my-bucket") || !strings.Contains(res.Summary, "logs/") || !strings.Contains(res.Summary, "2 个对象") {
		t.Errorf("Summary %q does not name the bucket, prefix and count", res.Summary)
	}
}

// ────────────────────────── shared helpers ──────────────────────────

func TestNormalizeKindsAndInclude(t *testing.T) {
	if got := normalizeKinds(nil); len(got) != 2 || got[0] != AssetCompute {
		t.Errorf("normalizeKinds(nil) = %v, want both kinds", got)
	}
	if got := normalizeKinds([]string{" compute ", "COMPUTE", "", "database"}); len(got) != 2 {
		t.Errorf("normalizeKinds did not dedupe/case-fold: %v", got)
	}
	if got := normalizeKinds([]string{"", "  "}); len(got) != 2 || got[0] != AssetCompute {
		t.Errorf("normalizeKinds(all blank) = %v, want the defaults", got)
	}
	if got := normalizeInclude(nil); len(got) != 3 {
		t.Errorf("normalizeInclude(nil) = %v, want all three", got)
	}
	if got := normalizeInclude([]string{"Users", "users", " "}); len(got) != 1 || got[0] != "users" {
		t.Errorf("normalizeInclude did not dedupe/case-fold: %v", got)
	}
}

func TestPageOf(t *testing.T) {
	if p := pageOf(0, "", false); p != nil {
		t.Errorf("pageOf(empty) = %+v, want nil", p)
	}
	if p := pageOf(10, "", false); p == nil || p.Total != 10 {
		t.Errorf("pageOf(10) = %+v", p)
	}
	if p := pageOf(0, "off:1", true); p == nil || !p.HasMore {
		t.Errorf("pageOf(cursor) = %+v", p)
	}
}

func TestOrDashAndMustJSON(t *testing.T) {
	if got := orDash("  "); got != "-" {
		t.Errorf("orDash(blank) = %q", got)
	}
	if got := orDash("Success"); got != "Success" {
		t.Errorf("orDash = %q", got)
	}
	if got := string(mustJSON(map[string]string{"a": "b"})); got != `{"a":"b"}` {
		t.Errorf("mustJSON = %s", got)
	}
	// An unmarshalable value must not panic or produce invalid JSON.
	if got := string(mustJSON(func() {})); got != `{}` {
		t.Errorf("mustJSON(unsupported) = %s, want {}", got)
	}
}

func TestParseInputTrimsAndLowercases(t *testing.T) {
	in, err := parseInput(json.RawMessage(`{"provider":"  AWS ","access_key":" AK ","secret_key":" SK ","region":" us-east-1 "}`))
	if err != nil {
		t.Fatalf("parseInput: %v", err)
	}
	if in.Provider != "aws" {
		t.Errorf("Provider = %q, want aws", in.Provider)
	}
	creds := in.creds()
	if creds.AccessKey != "AK" || creds.SecretKey != "SK" || creds.Region != "us-east-1" {
		t.Errorf("creds not trimmed: %+v", creds)
	}
	if _, err := parseInput(json.RawMessage(`{"provider":"aws"}`)); err == nil {
		t.Error("want an error when the key pair is missing")
	}
}

func TestPageSizeAndMaxResultsClamp(t *testing.T) {
	if got := (callInput{}).pageSize(); got != defaultPageSize {
		t.Errorf("pageSize(default) = %d", got)
	}
	if got := (callInput{PageSize: core.MaxListItems + 50}).pageSize(); got != core.MaxListItems {
		t.Errorf("pageSize over the cap = %d, want %d", got, core.MaxListItems)
	}
	if got := (callInput{MaxResults: 7}).maxResults(); got != 7 {
		t.Errorf("maxResults = %d", got)
	}
	if got := (callInput{MaxResults: -1}).maxResults(); got != defaultPageSize {
		t.Errorf("maxResults(negative) = %d", got)
	}
	if got := (callInput{MaxResults: core.MaxListItems + 1}).maxResults(); got != core.MaxListItems {
		t.Errorf("maxResults over the cap = %d", got)
	}
}

// TestKitProviderMatrix covers the provider lookup and the four names in the
// manifest enum, so a provider cannot be renamed out of the schema.
func TestKitProviderMatrix(t *testing.T) {
	k := New(core.Deps{HTTP: harness.NewHTTP(200, "")})
	for _, name := range []string{ProviderAliyun, ProviderTencent, ProviderAWS, ProviderHuawei} {
		p, err := k.provider(name)
		if err != nil {
			t.Errorf("provider %q: %v", name, err)
			continue
		}
		if p.Name() != name {
			t.Errorf("provider %q reports name %q", name, p.Name())
		}
	}
	if _, err := k.provider(""); err == nil {
		t.Error("an empty provider must be rejected")
	}
	if _, err := k.provider("gcp"); err == nil {
		t.Error("an unsupported provider must be rejected")
	}
}

func TestMaskAK(t *testing.T) {
	if got := maskAK("AKIAIOSFODNN7EXAMPLE"); got != "AKIA****MPLE" {
		t.Errorf("maskAK = %q, want AKIA****MPLE", got)
	}
	// A short key is masked whole: showing 8 of 8 characters is not masking.
	if got := maskAK("short"); got != "*****" {
		t.Errorf("maskAK(short) = %q", got)
	}
	if got := maskAK(""); got != "" {
		t.Errorf("maskAK(empty) = %q", got)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestKitGateErrorsSurviveClassification is the boundary rule for all four
// providers: the host's HTTP port raises scope_denied / rate_limited /
// unavailable before any vendor sees the request, and each vendor classifier
// must pass those through instead of turning them into a cloud failure. Getting
// this wrong is not cosmetic — a scope denial dressed up as a retryable upstream
// error is an invitation to hammer a host outside the authorized range.
func TestKitGateErrorsSurviveClassification(t *testing.T) {
	cases := []struct {
		name     string
		portErr  *core.Error
		status   core.Status
		wantCode string
	}{
		{"scope denied", core.ScopeDenied("目标不在授权范围"), core.StatusBlocked, core.CodeScopeDenied},
		{"rate limited", core.NewError(core.CodeRateLimited, "请求频率超限"), core.StatusBlocked, core.CodeRateLimited},
		{"port unavailable", core.Unavailable("HTTPDoer 不可用"), core.StatusUnavailable, core.CodeUnavailable},
		{"timeout", core.Timeout("云 API 超时"), core.StatusFailed, core.CodeTimeout},
	}
	for _, tc := range cases {
		for _, provider := range []string{ProviderAliyun, ProviderTencent, ProviderAWS, ProviderHuawei} {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				fake := harness.NewHTTP(200, "")
				fake.Err = tc.portErr
				k := kitWith(t, fake, nil)

				input := `{"provider":"` + provider + `","access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"s","region":"us-east-1"}`
				res := callTool(t, k, "cloud_ak_verify", input)
				if res.Status != tc.status {
					t.Errorf("Status = %s, want %s", res.Status, tc.status)
				}
				if res.Error == nil {
					t.Fatal("no Error")
				}
				if res.Error.Code != tc.wantCode {
					t.Errorf("Error.Code = %s, want the gate's own %s", res.Error.Code, tc.wantCode)
				}
				if strings.Contains(res.Error.Message, "wJalrXUtnFEMI") {
					t.Errorf("Error.Message leaks the secret: %q", res.Error.Message)
				}
			})
		}
	}
}
