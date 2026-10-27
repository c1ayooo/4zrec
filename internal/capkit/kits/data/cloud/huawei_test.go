package cloud

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/harness"
)

// Every test below is fully offline: the SDK's HTTP client is the injected
// httpDoerClient, whose doer is a scripted harness.HTTP. No Huawei host is ever
// dialed; the assertions read what the SDK would have sent.

func huaweiTestCreds() Credentials {
	return Credentials{
		AccessKey: "HWExampleAccessKey",
		SecretKey: "ExampleSecretKeyValue",
		Region:    "cn-north-4",
	}
}

// huaweiTestCredsAK varies the AK so the SDK's process-global project-id cache
// (keyed by AK+region) cannot leak a prior test's lookup into this one.
func huaweiTestCredsAK(ak string) Credentials {
	creds := huaweiTestCreds()
	creds.AccessKey = ak
	return creds
}

func newHuaweiFakeProvider(fake *harness.HTTP) *huaweiProvider {
	return &huaweiProvider{h: newHTTPDoerClient(fake, 0)}
}

// huaweiRequestFor finds the single recorded request whose URL contains fragment.
func huaweiRequestFor(t *testing.T, fake *harness.HTTP, fragment string) core.Request {
	t.Helper()
	for _, r := range fake.Requests() {
		if strings.Contains(r.URL, fragment) {
			return r
		}
	}
	t.Fatalf("no recorded request URL contained %q; calls=%v", fragment, huaweiURLs(fake))
	return core.Request{}
}

func huaweiURLs(fake *harness.HTTP) []string {
	var out []string
	for _, r := range fake.Requests() {
		out = append(out, r.URL)
	}
	return out
}

// assertSignedViaDoer proves the request went through the injected doer and was
// signed by the SDK: the URL is a Huawei host and the Authorization header
// carries the SDK-HMAC-SHA256 scheme.
func assertHuaweiSignedViaDoer(t *testing.T, fake *harness.HTTP, hostFragment string) {
	t.Helper()
	if fake.Calls() == 0 {
		t.Fatalf("expected at least one request through the injected doer, got 0")
	}
	last, ok := fake.Last()
	if !ok {
		t.Fatal("no request recorded")
	}
	if !strings.Contains(last.URL, hostFragment) {
		t.Fatalf("request URL %q does not contain %q", last.URL, hostFragment)
	}
	if !strings.Contains(last.URL, "myhuaweicloud.com") {
		t.Fatalf("request URL %q is not a Huawei host", last.URL)
	}
	auth := last.Headers["Authorization"]
	if !strings.Contains(auth, "SDK-HMAC-SHA256") {
		t.Fatalf("Authorization header %q missing SDK-HMAC-SHA256 (SDK did not sign)", auth)
	}
}

// ────────────────────────── Verify ──────────────────────────

func TestHuaweiVerifyOffline(t *testing.T) {
	fake := harness.NewHTTPJSON(`{"account_id":"1a2b3c","principal_urn":"iam::1a2b3c:user/alice","principal_id":"3f9c"}`)
	p := newHuaweiFakeProvider(fake)

	id, err := p.Verify(context.Background(), huaweiTestCreds())
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if id.AccountID != "1a2b3c" {
		t.Errorf("AccountID = %q, want 1a2b3c", id.AccountID)
	}
	if id.ARN != "iam::1a2b3c:user/alice" {
		t.Errorf("ARN = %q", id.ARN)
	}
	if id.Type != "iam_user" {
		t.Errorf("Type = %q, want iam_user", id.Type)
	}
	if id.Alias != "3f9c" {
		t.Errorf("Alias = %q, want 3f9c", id.Alias)
	}
	// STS is a global service: one signed request, no project lookup first.
	if fake.Calls() != 1 {
		t.Fatalf("expected exactly 1 STS call, got %d", fake.Calls())
	}
	assertHuaweiSignedViaDoer(t, fake, "sts.cn-north-4.myhuaweicloud.com")
}

func TestHuaweiVerifyRootAccount(t *testing.T) {
	fake := harness.NewHTTPJSON(`{"account_id":"1a2b3c","principal_urn":"iam::1a2b3c:root","principal_id":"1a2b3c"}`)
	p := newHuaweiFakeProvider(fake)

	id, err := p.Verify(context.Background(), huaweiTestCreds())
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if id.Type != "root_account" {
		t.Errorf("Type = %q, want root_account", id.Type)
	}
}

func TestHuaweiIdentityType(t *testing.T) {
	cases := map[string]string{
		"iam::1a2b3c:root":          "root_account",
		"iam::1a2b3c:user/alice":    "iam_user",
		"iam::1a2b3c:agency/deploy": "agency",
		"iam::1a2b3c:group/devs":    "iam_group",
		"":                          "",
		"garbage":                   "",
	}
	for urn, want := range cases {
		if got := huaweiIdentityType(urn); got != want {
			t.Errorf("huaweiIdentityType(%q) = %q, want %q", urn, got, want)
		}
	}
}

// A bad credential must be rejected by the vendor (401 → invalid_credential),
// not surfaced as a generic upstream failure.
func TestHuaweiVerifyInvalidCredential(t *testing.T) {
	fake := harness.NewHTTP(401, `{"error_code":"APIGW.0301","error_msg":"authentication failed"}`)
	p := newHuaweiFakeProvider(fake)

	_, err := p.Verify(context.Background(), huaweiTestCreds())
	if err == nil {
		t.Fatal("expected an error for a rejected credential")
	}
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("want a classified *Error, got %T (%v)", err, err)
	}
	if ce.Reason != ReasonInvalidCredential {
		t.Errorf("Reason = %q, want %q", ce.Reason, ReasonInvalidCredential)
	}
	if ce.Code != "APIGW.0301" {
		t.Errorf("Code = %q, want the verbatim APIGW.0301", ce.Code)
	}
}

// ────────────────────────── ListAssets ──────────────────────────

func TestHuaweiListAssetsOffline(t *testing.T) {
	// Both services need a project id in the path, so the SDK's own IAM
	// KeystoneListProjects call is routed through the same doer first. One
	// project id in the region keeps the lookup unambiguous.
	projectsJSON := `{"projects":[{"id":"0f3a2b","name":"cn-north-4"}],"projects_enabled":true}`
	ecsJSON := `{"count":5,"servers":[` +
		`{"id":"e0f1g2","name":"web-1","status":"ACTIVE","flavor":{"id":"s6.large","name":"s6.large"},` +
		`"OS-EXT-AZ:availability_zone":"cn-north-4a",` +
		`"addresses":{"default":[{"version":"4","addr":"10.0.0.5","OS-EXT-IPS:type":"fixed"},{"version":"4","addr":"1.2.3.4","OS-EXT-IPS:type":"floating"}]}},` +
		`{"id":"h3i4j5","name":"web-2","status":"SHUTOFF","flavor":{"id":"s6.small","name":"s6.small"}}]}` +
		`}`
	rdsJSON := `{"instances":[` +
		`{"id":"r6k7l8","name":"db-1","status":"ACTIVE","type":"Ha","datastore":{"type":"MySQL","version":"8.0"},` +
		`"private_ips":["10.0.0.9"],"public_ips":[]}],"total_count":1}`

	fake := &harness.HTTP{Routes: []harness.Route{
		{Match: "iam.", Status: 200, Body: projectsJSON},
		{Match: "ecs.", Status: 200, Body: ecsJSON},
		{Match: "rds.", Status: 200, Body: rdsJSON},
	}, Default: harness.Route{Status: 500, Body: `{"error_code":"InternalError","error_msg":"unrouted"}`}}
	p := newHuaweiFakeProvider(fake)

	page, err := p.ListAssets(context.Background(), huaweiTestCredsAK("HWTestAKListAssets"), AssetRequest{
		Kinds: []string{AssetCompute, AssetDatabase}, Region: "cn-north-4", PageSize: 50,
	})
	if err != nil {
		t.Fatalf("ListAssets returned error: %v", err)
	}
	if len(page.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", page.Warnings)
	}
	if len(page.Instances) != 3 {
		t.Fatalf("got %d instances, want 3", len(page.Instances))
	}
	compute := page.Instances[0]
	if compute.ID != "e0f1g2" || compute.Name != "web-1" || compute.Status != "ACTIVE" ||
		compute.Type != "s6.large" || compute.Zone != "cn-north-4a" || compute.Kind != AssetCompute {
		t.Errorf("compute instance mapped wrong: %+v", compute)
	}
	if len(compute.PrivateIP) != 1 || compute.PrivateIP[0] != "10.0.0.5" {
		t.Errorf("compute PrivateIP = %v, want [10.0.0.5]", compute.PrivateIP)
	}
	if len(compute.PublicIP) != 1 || compute.PublicIP[0] != "1.2.3.4" {
		t.Errorf("compute PublicIP = %v, want [1.2.3.4] (floating address)", compute.PublicIP)
	}
	// A server with no addresses must yield no IP slices at all.
	if page.Instances[1].PrivateIP != nil || page.Instances[1].PublicIP != nil {
		t.Errorf("address-less server should carry no IPs: %+v", page.Instances[1])
	}
	db := page.Instances[2]
	if db.ID != "r6k7l8" || db.Name != "db-1" || db.Status != "ACTIVE" ||
		db.Type != "Ha" || db.Kind != AssetDatabase {
		t.Errorf("db instance mapped wrong: %+v", db)
	}
	if db.Engine != "MySQL 8.0" {
		t.Errorf("db Engine = %q, want %q", db.Engine, "MySQL 8.0")
	}
	if len(db.PrivateIP) != 1 || db.PrivateIP[0] != "10.0.0.9" {
		t.Errorf("db PrivateIP = %v, want [10.0.0.9]", db.PrivateIP)
	}
	if page.Total != 3 {
		t.Errorf("Total = %d, want 3", page.Total)
	}

	// The vendor reported more ECS servers than came back, so a next cursor must
	// be offered at offset 0 + 2.
	if !page.HasMore || page.Cursor != "2" {
		t.Errorf("expected HasMore with cursor 2 (offset 0 + 2), got HasMore=%v cursor=%q",
			page.HasMore, page.Cursor)
	}

	// Every request went through the injected doer, and the project lookup
	// happened once and was shared by both service calls.
	if fake.Calls() != 3 {
		t.Fatalf("expected 3 requests (1 project lookup + ECS + RDS), got %d: %v", fake.Calls(), huaweiURLs(fake))
	}
	for _, r := range fake.Requests() {
		if !strings.Contains(r.URL, "myhuaweicloud.com") {
			t.Errorf("request URL %q not a Huawei host", r.URL)
		}
		if !strings.Contains(r.Headers["Authorization"], "SDK-HMAC-SHA256") {
			t.Errorf("request %q not SDK-signed (Authorization=%q)", r.URL, r.Headers["Authorization"])
		}
	}
	// The project lookup must have gone through the same doer, and the ECS/RDS
	// paths must carry the resolved project id.
	if r := huaweiRequestFor(t, fake, "/v3/projects"); !strings.Contains(r.URL, "iam.cn-north-4.myhuaweicloud.com") {
		t.Errorf("project lookup URL %q is not the IAM endpoint", r.URL)
	}
	if r := huaweiRequestFor(t, fake, "cloudservers/detail"); !strings.Contains(r.URL, "/v1/0f3a2b/cloudservers/detail") {
		t.Errorf("ECS request URL %q missing the resolved project_id path", r.URL)
	}
	if r := huaweiRequestFor(t, fake, "/instances"); !strings.Contains(r.URL, "/v3/0f3a2b/instances") {
		t.Errorf("RDS request URL %q missing the resolved project_id path", r.URL)
	}
}

// A paging cursor must resume where the previous page stopped.
func TestHuaweiListAssetsCursorResume(t *testing.T) {
	projectsJSON := `{"projects":[{"id":"0f3a2b","name":"cn-north-4"}]}`
	ecsJSON := `{"count":1,"servers":[{"id":"e0f1g2","status":"ACTIVE"}]}`
	fake := &harness.HTTP{Routes: []harness.Route{
		{Match: "iam.", Status: 200, Body: projectsJSON},
		{Match: "ecs.", Status: 200, Body: ecsJSON},
	}}
	p := newHuaweiFakeProvider(fake)

	page, err := p.ListAssets(context.Background(), huaweiTestCredsAK("HWTestAKCursor"), AssetRequest{
		Kinds: []string{AssetCompute}, Region: "cn-north-4", PageSize: 50, Cursor: "50",
	})
	if err != nil {
		t.Fatalf("ListAssets returned error: %v", err)
	}
	if len(page.Instances) != 1 {
		t.Fatalf("got %d instances, want 1", len(page.Instances))
	}
	ecsReq := huaweiRequestFor(t, fake, "cloudservers/detail")
	if !strings.Contains(ecsReq.URL, "offset=50") {
		t.Errorf("ECS request URL %q must resume at offset=50", ecsReq.URL)
	}
}

// One kind failing must not fail the whole call: the other kind is returned and
// the failure is recorded in Warnings.
func TestHuaweiListAssetsPartialFailure(t *testing.T) {
	projectsJSON := `{"projects":[{"id":"0f3a2b","name":"cn-north-4"}]}`
	ecsJSON := `{"count":1,"servers":[{"id":"e0f1g2","status":"ACTIVE"}]}`
	fake := &harness.HTTP{Routes: []harness.Route{
		{Match: "iam.", Status: 200, Body: projectsJSON},
		{Match: "ecs.", Status: 200, Body: ecsJSON},
		{Match: "rds.", Status: 403, Body: `{"error_code":"APIGW.0302","error_msg":"no permission"}`},
	}, Default: harness.Route{Status: 500}}
	p := newHuaweiFakeProvider(fake)

	page, err := p.ListAssets(context.Background(), huaweiTestCredsAK("HWTestAKPartial"), AssetRequest{
		Kinds: []string{AssetCompute, AssetDatabase}, Region: "cn-north-4",
	})
	if err != nil {
		t.Fatalf("partial failure should not error, got %v", err)
	}
	if len(page.Instances) != 1 {
		t.Fatalf("got %d instances, want 1 (compute)", len(page.Instances))
	}
	if len(page.Warnings) != 1 || !strings.Contains(page.Warnings[0], "RDS") {
		t.Fatalf("expected an RDS warning, got %v", page.Warnings)
	}
}

// Both kinds failing is the only case that errors.
func TestHuaweiListAssetsAllFail(t *testing.T) {
	fake := &harness.HTTP{Routes: []harness.Route{
		{Match: "iam.", Status: 200, Body: `{"projects":[{"id":"0f3a2b","name":"cn-north-4"}]}`},
		{Match: "ecs.", Status: 403, Body: `{"error_code":"APIGW.0302","error_msg":"denied"}`},
		{Match: "rds.", Status: 403, Body: `{"error_code":"APIGW.0302","error_msg":"denied"}`},
	}}
	p := newHuaweiFakeProvider(fake)

	_, err := p.ListAssets(context.Background(), huaweiTestCredsAK("HWTestAKAllFail"), AssetRequest{
		Kinds: []string{AssetCompute, AssetDatabase}, Region: "cn-north-4",
	})
	if err == nil {
		t.Fatal("expected an error when both kinds fail")
	}
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("want a classified *Error, got %T", err)
	}
	if ce.Reason != ReasonPermissionDenied {
		t.Errorf("Reason = %q, want %q", ce.Reason, ReasonPermissionDenied)
	}
}

// An unknown kind is skipped with a warning, not an error.
func TestHuaweiListAssetsUnknownKind(t *testing.T) {
	projectsJSON := `{"projects":[{"id":"0f3a2b","name":"cn-north-4"}]}`
	ecsJSON := `{"count":1,"servers":[{"id":"e0f1g2","status":"ACTIVE"}]}`
	fake := &harness.HTTP{Routes: []harness.Route{
		{Match: "iam.", Status: 200, Body: projectsJSON},
		{Match: "ecs.", Status: 200, Body: ecsJSON},
	}}
	p := newHuaweiFakeProvider(fake)

	page, err := p.ListAssets(context.Background(), huaweiTestCredsAK("HWTestAKUnknownKind"), AssetRequest{
		Kinds: []string{AssetCompute, "network"}, Region: "cn-north-4",
	})
	if err != nil {
		t.Fatalf("unknown kind must not error: %v", err)
	}
	if len(page.Instances) != 1 {
		t.Errorf("compute instance should still be returned, got %d", len(page.Instances))
	}
	found := false
	for _, w := range page.Warnings {
		if strings.Contains(w, "network") {
			found = true
		}
	}
	if !found {
		t.Errorf("unknown kind should land in Warnings, got %v", page.Warnings)
	}
}

// ────────────────────────── error classification ──────────────────────────

func TestClassifyHuaweiErrorCodes(t *testing.T) {
	cases := []struct {
		code    string
		message string
		status  int
		want    Reason
	}{
		// Status is the primary discriminator: an invalid AK/SK is 401, a scoped
		// permission failure is 403, a missing resource is 404, throttling is 429.
		{"APIGW.0301", "authentication failed", 401, ReasonInvalidCredential},
		{"APIGW.0302", "the request is forbidden", 403, ReasonPermissionDenied},
		{"IAM.0005", "no permission", 403, ReasonPermissionDenied},
		{"IAM.0007", "not found", 404, ReasonNotFound},
		{"APIGW.0308", "too many requests", 429, ReasonThrottled},
		{"", "authentication failed", 401, ReasonInvalidCredential},
		{"", "forbidden", 403, ReasonPermissionDenied},
		{"", "not found", 404, ReasonNotFound},
		{"", "throttled", 429, ReasonThrottled},
		// Any 5xx is upstream_error, including 503 and 504: the code/prose table
		// only runs when the status is outside this fallback set.
		{"", "internal error", 500, ReasonUpstream},
		{"", "service unavailable", 503, ReasonUpstream},
		{"", "gateway timeout", 504, ReasonUpstream},
		// Outside the status set (notably 400), the code and prose decide.
		{"APIGW.0303", "boom", 400, ReasonRegionInvalid},
		{"APIGW.0308", "boom", 400, ReasonThrottled},
		{"Ecs.0100", "boom", 400, ReasonInstanceNotRunning},
		{"", "request was throttled", 400, ReasonThrottled},
		{"", "invalid region ap-southeast-9", 400, ReasonRegionInvalid},
		{"", "operation timed out", 400, ReasonTimeout},
	}
	for _, tc := range cases {
		got := classifyHuawei(&sdkerr.ServiceResponseError{
			StatusCode: tc.status, ErrorCode: tc.code, ErrorMessage: tc.message,
		})
		ce, ok := got.(*Error)
		if !ok {
			t.Errorf("%s/%d: classifyHuawei returned %T, want *Error", tc.code, tc.status, got)
			continue
		}
		if ce.Reason != tc.want {
			t.Errorf("%s/%d (%q): Reason = %q, want %q", tc.code, tc.status, tc.message, ce.Reason, tc.want)
		}
		if ce.Code != tc.code {
			t.Errorf("%s/%d: Code = %q, want verbatim %q", tc.code, tc.status, ce.Code, tc.code)
		}
		if ce.Provider != ProviderHuawei {
			t.Errorf("%s/%d: Provider = %q, want %q", tc.code, tc.status, ce.Provider, ProviderHuawei)
		}
	}
}

// The prose fallback must cover every reason the brief names, since Huawei's
// per-service codes are large and under-documented.
func TestClassifyHuaweiFallbackByMessage(t *testing.T) {
	cases := map[string]Reason{
		"the request is throttled":               ReasonThrottled,
		"request rate exceeds limit":             ReasonThrottled,
		"quota exceeded":                         ReasonThrottled,
		"operation timed out":                    ReasonTimeout,
		"deadline exceeded":                      ReasonTimeout,
		"invalid region ap-southeast-9":          ReasonRegionInvalid,
		"the server is not in the running state": ReasonInstanceNotRunning,
		"instance does not exist":                ReasonNotFound,
		"the ECS is not running":                 ReasonInstanceNotRunning,
	}
	for msg, want := range cases {
		got := classifyHuawei(&sdkerr.ServiceResponseError{
			StatusCode: 400, ErrorCode: "Odd.NewCode", ErrorMessage: msg,
		})
		ce, ok := got.(*Error)
		if !ok || ce.Reason != want {
			t.Errorf("message %q classified as %+v, want %q", msg, got, want)
		}
	}
}

func TestClassifyHuaweiTimeoutContext(t *testing.T) {
	got := classifyHuawei(context.DeadlineExceeded)
	ce, ok := got.(*Error)
	if !ok || ce.Reason != ReasonTimeout {
		t.Fatalf("context deadline classified as %+v, want timeout", got)
	}
}

func TestClassifyHuaweiNil(t *testing.T) {
	if got := classifyHuawei(nil); got != nil {
		t.Fatalf("classifyHuawei(nil) = %+v, want nil", got)
	}
}

// A host gate error (scope denial) must survive classification verbatim, so
// cloudkit.go's failure() keeps the host's code.
func TestHuaweiCapkitErrorPassthrough(t *testing.T) {
	denied := core.ScopeDenied("out of scope: ecs.cn-north-4.myhuaweicloud.com")
	got := classifyHuawei(denied)
	var ce *core.Error
	if !errors.As(got, &ce) {
		t.Fatalf("want *core.Error passthrough, got %T", got)
	}
	if ce.Code != core.CodeScopeDenied {
		t.Fatalf("code = %q, want %q", ce.Code, core.CodeScopeDenied)
	}
}

// ────────────────────────── boundaries ──────────────────────────

// Without an injected doer every call must report the host's unavailable error,
// not dial a vendor directly.
func TestHuaweiUnavailableWithoutDoer(t *testing.T) {
	p := &huaweiProvider{h: newHTTPDoerClient(nil, 0)}

	_, err := p.Verify(context.Background(), huaweiTestCreds())
	if err == nil {
		t.Fatal("expected unavailable error, got nil")
	}
	var ce *core.Error
	if !errors.As(err, &ce) {
		t.Fatalf("want *core.Error, got %T (%v)", err, err)
	}
	if ce.Code != core.CodeUnavailable {
		t.Fatalf("code = %q, want %q", ce.Code, core.CodeUnavailable)
	}
}

// Missing credentials must fail before any SDK call.
func TestHuaweiMissingCredential(t *testing.T) {
	fake := harness.NewHTTPJSON(`{}`)
	p := newHuaweiFakeProvider(fake)

	_, err := p.Verify(context.Background(), Credentials{})
	var ce *Error
	if !errors.As(err, &ce) || ce.Reason != ReasonInvalidCredential {
		t.Fatalf("want invalid_credential, got %v", err)
	}
	if fake.Calls() != 0 {
		t.Fatalf("no request should be sent without credentials, got %d", fake.Calls())
	}
}

// The two capabilities this SDK cannot reach must say so instead of returning an
// empty success: no fabricated call, no fake data.
func TestHuaweiUnsupportedSurfaces(t *testing.T) {
	p := newHuaweiFakeProvider(harness.NewHTTP(500, `{}`))

	if _, err := p.ListStorage(context.Background(), huaweiTestCreds(), StorageRequest{}); err == nil {
		t.Error("ListStorage must not claim success: OBS needs a separate SDK")
	} else {
		var ce *Error
		if !errors.As(err, &ce) || ce.Reason != ReasonUnsupported {
			t.Errorf("ListStorage error = %v, want unsupported", err)
		}
	}
	if _, err := p.RunCommand(context.Background(), huaweiTestCreds(), CommandRequest{
		InstanceID: "e0f1g2", Command: "id",
	}); err == nil {
		t.Error("RunCommand must not claim success: the ECS service has no command API in this SDK")
	} else {
		var ce *Error
		if !errors.As(err, &ce) || ce.Reason != ReasonUnsupported {
			t.Errorf("RunCommand error = %v, want unsupported", err)
		} else if !strings.Contains(ce.Message, "ECS") {
			t.Errorf("RunCommand message should name the missing ECS capability: %q", ce.Message)
		}
	}
}

// ListStorage must name the dependency it is missing, so the agent knows the gap
// is a module this kit does not import rather than a wrong input.
func TestHuaweiListStorageMessageNamesMissingModule(t *testing.T) {
	p := newHuaweiFakeProvider(harness.NewHTTP(500, `{}`))
	_, err := p.ListStorage(context.Background(), huaweiTestCreds(), StorageRequest{})
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("want *Error, got %T (%v)", err, err)
	}
	if !strings.Contains(ce.Message, "huaweicloud-sdk-go-obs，当前依赖未引入") {
		t.Fatalf("ListStorage message = %q, want it to name huaweicloud-sdk-go-obs and 当前依赖未引入", ce.Message)
	}
}

// ────────────────────────── ListIAM ──────────────────────────

// ListIAM walks several Huawei endpoints: users, roles (policies), permanent
// access keys, and — for the admin hint — each user's groups and those groups'
// domain-level roles. Routing on the URL keeps the fake honest about which call
// is which.
func TestHuaweiListIAMOffline(t *testing.T) {
	const usersJSON = `{"users":[` +
		`{"id":"u-1","name":"alice","domain_id":"d-1","enabled":true},` +
		`{"id":"u-2","name":"bob","domain_id":"d-1","enabled":true}]}`
	const rolesJSON = `{"roles":[` +
		`{"id":"r-1","name":"security_admin","display_name":"Security Administrator","type":"AX"},` +
		`{"id":"r-2","name":"obs_readonly","display_name":"OBS Bucket ReadOnlyAccess","type":"XA"}]}`
	const credsJSON = `{"credentials":[` +
		`{"user_id":"u-1","access":"AKIDHWEXAMPLE0001","status":"active","create_time":"2024-05-26T03:30:52Z"}]}`
	const groupsJSON = `{"groups":[{"id":"g-1","name":"admins"}]}`
	const groupRolesJSON = `{"roles":[{"id":"r-9","name":"admin","display_name":"admin","type":"AA"}]}`

	fake := &harness.HTTP{Routes: []harness.Route{
		// Most specific first: the group-roles URL also contains "/groups".
		{Match: "/v3/domains/", Status: 200, Body: groupRolesJSON},
		{Match: "/groups", Status: 200, Body: groupsJSON},
		{Match: "/v3.0/OS-CREDENTIAL", Status: 200, Body: credsJSON},
		{Match: "/v3/roles", Status: 200, Body: rolesJSON},
		{Match: "/v3/users", Status: 200, Body: usersJSON},
	}, Default: harness.Route{Status: 500, Body: `{}`}}
	p := newHuaweiFakeProvider(fake)

	page, err := p.ListIAM(context.Background(), huaweiTestCredsAK("HWTestAKListIAM"), IAMRequest{
		Include:    []string{"users", "policies", "access_keys"},
		MaxResults: 100,
	})
	if err != nil {
		t.Fatalf("ListIAM returned error: %v", err)
	}
	if len(page.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", page.Warnings)
	}

	if len(page.Users) != 2 || page.Users[0].Name != "alice" || page.Users[0].ID != "u-1" {
		t.Fatalf("users mapped wrong: %+v", page.Users)
	}
	// Each user inherits an administrative role through their group, so both must
	// carry the hint (this is the privesc signal the tool exists to surface).
	for _, u := range page.Users {
		if u.AdminHint != "admin" {
			t.Errorf("user %q AdminHint = %q, want admin", u.Name, u.AdminHint)
		}
	}

	if len(page.Policies) != 2 {
		t.Fatalf("policies mapped wrong: %+v", page.Policies)
	}
	if !page.Policies[0].Admin || page.Policies[0].Name != "Security Administrator" {
		t.Errorf("Security Administrator should be flagged admin: %+v", page.Policies[0])
	}
	if page.Policies[1].Admin {
		t.Errorf("read-only policy should not be flagged admin: %+v", page.Policies[1])
	}

	if len(page.AccessKeys) != 1 || page.AccessKeys[0].ID != "AKIDHWEXAMPLE0001" ||
		page.AccessKeys[0].Status != "active" {
		t.Fatalf("access_keys mapped wrong: %+v", page.AccessKeys)
	}

	if page.Total != 5 {
		t.Errorf("Total = %d, want 5 (2 users + 2 policies + 1 key)", page.Total)
	}

	// Every IAM request must be SDK-signed and travel through the injected doer.
	var sawUsers, sawRoles, sawCreds, sawGroups, sawGroupRoles bool
	for _, r := range fake.Requests() {
		if !strings.Contains(r.Headers["Authorization"], "SDK-HMAC-SHA256") {
			t.Errorf("IAM request %q not SDK-signed (Authorization=%q)", r.URL, r.Headers["Authorization"])
		}
		switch {
		case strings.Contains(r.URL, "/v3/domains/"):
			sawGroupRoles = true
		case strings.Contains(r.URL, "/groups"):
			sawGroups = true
		case strings.Contains(r.URL, "/v3.0/OS-CREDENTIAL"):
			sawCreds = true
		case strings.Contains(r.URL, "/v3/roles"):
			sawRoles = true
		case strings.Contains(r.URL, "/v3/users"):
			sawUsers = true
		}
	}
	for name, seen := range map[string]bool{
		"users": sawUsers, "roles": sawRoles, "credentials": sawCreds,
		"groups": sawGroups, "group roles": sawGroupRoles,
	} {
		if !seen {
			t.Errorf("no IAM %s request observed; urls=%v", name, huaweiURLs(fake))
		}
	}
}

// The admin probe is bounded by maxAdminProbe (shared with aws.go), so a large
// account cannot turn one tool call into a per-user call storm.
func TestHuaweiListIAMAdminProbeBounded(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"users":[`)
	total := maxAdminProbe + 5
	for i := 0; i < total; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"id":"u-` + strconv.Itoa(i) + `","name":"n-` + strconv.Itoa(i) +
			`","domain_id":"d-1","enabled":true}`)
	}
	sb.WriteString(`]}`)

	fake := &harness.HTTP{Routes: []harness.Route{
		{Match: "/v3/domains/", Status: 200, Body: `{"roles":[]}`},
		{Match: "/groups", Status: 200, Body: `{"groups":[]}`},
		{Match: "/v3/users", Status: 200, Body: sb.String()},
	}, Default: harness.Route{Status: 500, Body: `{}`}}
	p := newHuaweiFakeProvider(fake)

	page, err := p.ListIAM(context.Background(), huaweiTestCredsAK("HWTestAKProbeBound"), IAMRequest{
		Include: []string{"users"}, MaxResults: 100,
	})
	if err != nil {
		t.Fatalf("ListIAM returned error: %v", err)
	}
	if len(page.Users) != total {
		t.Fatalf("got %d users, want %d", len(page.Users), total)
	}
	groupCalls := 0
	for _, r := range fake.Requests() {
		if strings.Contains(r.URL, "/groups") {
			groupCalls++
		}
	}
	if groupCalls != maxAdminProbe {
		t.Fatalf("admin probe made %d group lookups, want %d", groupCalls, maxAdminProbe)
	}
}
