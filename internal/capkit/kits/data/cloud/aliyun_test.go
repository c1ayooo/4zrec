package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/alibabacloud-go/tea/dara"
	"github.com/alibabacloud-go/tea/tea"
	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/harness"
)

// Every test below is fully offline: the SDK's HTTP client is the injected
// httpDoerClient, whose doer is a scripted harness.HTTP. No vendor host is ever
// dialed; the assertions read what the SDK would have sent.

func testCreds() Credentials {
	return Credentials{
		AccessKey: "LTAI5tExampleAccessKey",
		SecretKey: "ExampleSecretKeyValue",
		Region:    "cn-hangzhou",
	}
}

// assertSignedViaDoer proves the request went through the injected doer and was
// signed by the SDK: the URL is the vendor host and the Authorization header
// carries the ACS3 Credential field.
func assertSignedViaDoer(t *testing.T, fake *harness.HTTP, hostFragment string) {
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
	if !strings.Contains(last.URL, "aliyuncs.com") {
		t.Fatalf("request URL %q does not contain aliyuncs.com", last.URL)
	}
	auth := last.Headers["Authorization"]
	if !strings.Contains(auth, "Credential=") {
		t.Fatalf("Authorization header %q missing Credential= (SDK did not sign)", auth)
	}
}

func newFakeProvider(fake *harness.HTTP) *aliyunProvider {
	return &aliyunProvider{h: newHTTPDoerClient(fake, 0)}
}

// ────────────────────────── Verify ──────────────────────────

func TestAliyunVerifyOffline(t *testing.T) {
	fake := harness.NewHTTPJSON(`{"AccountId":"123456","Arn":"acs:ram::123456:root","UserId":"216959339000123456","RequestId":"r1"}`)
	p := newFakeProvider(fake)

	id, err := p.Verify(context.Background(), testCreds())
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if id.AccountID != "123456" {
		t.Errorf("AccountID = %q, want 123456", id.AccountID)
	}
	if id.ARN != "acs:ram::123456:root" {
		t.Errorf("ARN = %q", id.ARN)
	}
	if id.Type != "root_account" {
		t.Errorf("Type = %q, want root_account", id.Type)
	}
	if id.Alias != "216959339000123456" {
		t.Errorf("Alias = %q", id.Alias)
	}
	assertSignedViaDoer(t, fake, "sts.aliyuncs.com")
}

func TestAliyunIdentityType(t *testing.T) {
	cases := map[string]string{
		"acs:ram::123456:root":                  "root_account",
		"acs:ram::123456:user/alice":            "ram_user",
		"acs:ram::123456:role/deploy":           "ram_role",
		"acs:ram::123456:assumed-role/deploy/x": "assumed_role",
		"acs:ram::123456:group/devs":            "ram_group",
	}
	for arn, want := range cases {
		if got := aliyunIdentityType(arn); got != want {
			t.Errorf("aliyunIdentityType(%q) = %q, want %q", arn, got, want)
		}
	}
}

// ────────────────────────── ListAssets ──────────────────────────

func TestAliyunListAssetsOffline(t *testing.T) {
	ecsBody := `{"Instances":{"Instance":[{"InstanceId":"i-bp1","InstanceName":"web-1","Status":"Running","InstanceType":"ecs.g6.large","ZoneId":"cn-hangzhou-b","PublicIpAddress":{"IpAddress":["1.2.3.4"]},"VpcAttributes":{"PrivateIpAddress":{"IpAddress":["10.0.0.5"]}}}]},"NextToken":"tok-2","RequestId":"r2"}`
	rdsBody := `{"Items":{"DBInstance":[{"DBInstanceId":"rm-bp1","DBInstanceDescription":"db-1","DBInstanceStatus":"Running","DBInstanceClass":"rds.mysql.c1.large","Engine":"MySQL","EngineVersion":"8.0","RegionId":"cn-hangzhou","ZoneId":"cn-hangzhou-h","ConnectionString":"rm-bp1.mysql.rds.aliyuncs.com"}]},"NextToken":"tok-3","RequestId":"r3"}`
	fake := &harness.HTTP{Routes: []harness.Route{
		{Match: "ecs.", Status: 200, Body: ecsBody},
		{Match: "rds.", Status: 200, Body: rdsBody},
	}, Default: harness.Route{Status: 500, Body: `{"Code":"Unexpected"}`}}
	p := newFakeProvider(fake)

	page, err := p.ListAssets(context.Background(), testCreds(), AssetRequest{
		Kinds: []string{AssetCompute, AssetDatabase}, Region: "cn-hangzhou", PageSize: 50,
	})
	if err != nil {
		t.Fatalf("ListAssets returned error: %v", err)
	}
	if len(page.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", page.Warnings)
	}
	if len(page.Instances) != 2 {
		t.Fatalf("got %d instances, want 2", len(page.Instances))
	}
	compute := page.Instances[0]
	if compute.ID != "i-bp1" || compute.Name != "web-1" || compute.Status != "Running" ||
		compute.Type != "ecs.g6.large" || compute.Zone != "cn-hangzhou-b" || compute.Kind != AssetCompute {
		t.Errorf("compute instance mapped wrong: %+v", compute)
	}
	if len(compute.PublicIP) != 1 || compute.PublicIP[0] != "1.2.3.4" {
		t.Errorf("compute PublicIP = %v, want [1.2.3.4]", compute.PublicIP)
	}
	if len(compute.PrivateIP) != 1 || compute.PrivateIP[0] != "10.0.0.5" {
		t.Errorf("compute PrivateIP = %v, want [10.0.0.5]", compute.PrivateIP)
	}
	db := page.Instances[1]
	if db.ID != "rm-bp1" || db.Name != "db-1" || db.Status != "Running" ||
		db.Type != "rds.mysql.c1.large" || db.Zone != "cn-hangzhou-h" || db.Kind != AssetDatabase {
		t.Errorf("db instance mapped wrong: %+v", db)
	}
	if db.Engine != "MySQL 8.0" {
		t.Errorf("db Engine = %q, want %q", db.Engine, "MySQL 8.0")
	}
	if len(db.PrivateIP) != 1 || db.PrivateIP[0] != "rm-bp1.mysql.rds.aliyuncs.com" {
		t.Errorf("db PrivateIP = %v", db.PrivateIP)
	}
	if !page.HasMore || page.Cursor == "" {
		t.Errorf("expected HasMore with a cursor, got HasMore=%v cursor=%q", page.HasMore, page.Cursor)
	}
	if page.Total != 2 {
		t.Errorf("Total = %d, want 2", page.Total)
	}

	// Both requests went through the injected doer and were signed by the SDK.
	if fake.Calls() != 2 {
		t.Fatalf("expected 2 requests, got %d", fake.Calls())
	}
	for _, r := range fake.Requests() {
		if !strings.Contains(r.URL, "aliyuncs.com") {
			t.Errorf("request URL %q not an aliyun host", r.URL)
		}
		if !strings.Contains(r.Headers["Authorization"], "Credential=") {
			t.Errorf("request %q not SDK-signed (Authorization=%q)", r.URL, r.Headers["Authorization"])
		}
	}
}

// One kind failing must not fail the whole call: the other kind is returned and
// the failure is recorded in Warnings.
func TestAliyunListAssetsPartialFailure(t *testing.T) {
	ecsBody := `{"Instances":{"Instance":[{"InstanceId":"i-bp1","Status":"Running"}]},"RequestId":"r"}`
	fake := &harness.HTTP{Routes: []harness.Route{
		{Match: "ecs.", Status: 200, Body: ecsBody},
		{Match: "rds.", Status: 403, Body: `{"Code":"Forbidden.RAM","Message":"no permission"}`},
	}, Default: harness.Route{Status: 500}}
	p := newFakeProvider(fake)

	page, err := p.ListAssets(context.Background(), testCreds(), AssetRequest{
		Kinds: []string{AssetCompute, AssetDatabase}, Region: "cn-hangzhou",
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
func TestAliyunListAssetsAllFail(t *testing.T) {
	fake := harness.NewHTTP(403, `{"Code":"Forbidden","Message":"denied"}`)
	p := newFakeProvider(fake)

	_, err := p.ListAssets(context.Background(), testCreds(), AssetRequest{
		Kinds: []string{AssetCompute, AssetDatabase}, Region: "cn-hangzhou",
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

func TestAliyunListAssetsUnknownKind(t *testing.T) {
	ecsBody := `{"Instances":{"Instance":[{"InstanceId":"i-bp1","Status":"Running"}]},"RequestId":"r"}`
	fake := &harness.HTTP{Routes: []harness.Route{{Match: "ecs.", Status: 200, Body: ecsBody}}}
	p := newFakeProvider(fake)

	page, err := p.ListAssets(context.Background(), testCreds(), AssetRequest{
		Kinds: []string{AssetCompute, "network"}, Region: "cn-hangzhou",
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

// ────────────────────────── ListIAM ──────────────────────────

func TestAliyunListIAMOffline(t *testing.T) {
	// One body serves every RAM action: each response type reads its own field.
	body := `{
		"Users":{"User":[{"UserName":"alice","UserId":"u-1","CreateDate":"2024-01-01T00:00:00Z"}]},
		"Policies":{"Policy":[{"PolicyName":"AdministratorAccess","PolicyType":"Custom","Description":"full admin","AttachmentCount":3,"DefaultVersion":"v1"}]},
		"AccessKeys":{"AccessKey":[{"AccessKeyId":"LTAI-user-1","Status":"Active","CreateDate":"2024-01-02T00:00:00Z"}]},
		"IsTruncated":false,"RequestId":"r"
	}`
	fake := harness.NewHTTPJSON(body)
	p := newFakeProvider(fake)

	page, err := p.ListIAM(context.Background(), testCreds(), IAMRequest{
		Include: []string{"users", "policies", "access_keys"},
	})
	if err != nil {
		t.Fatalf("ListIAM returned error: %v", err)
	}
	if len(page.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(page.Users))
	}
	if page.Users[0].Name != "alice" || page.Users[0].ID != "u-1" || page.Users[0].CreatedAt == "" {
		t.Errorf("user mapped wrong: %+v", page.Users[0])
	}
	if page.Users[0].AdminHint != "AdministratorAccess" {
		t.Errorf("AdminHint = %q, want AdministratorAccess", page.Users[0].AdminHint)
	}
	if len(page.Policies) != 1 || page.Policies[0].Name != "AdministratorAccess" ||
		page.Policies[0].Attachments != 3 || !page.Policies[0].Admin {
		t.Errorf("policy mapped wrong: %+v", page.Policies)
	}
	if len(page.AccessKeys) != 1 || page.AccessKeys[0].ID != "LTAI-user-1" || page.AccessKeys[0].Status != "Active" {
		t.Errorf("access key mapped wrong: %+v", page.AccessKeys)
	}
	// 3 include calls + 1 admin probe (ListPoliciesForUser) for the single user.
	if fake.Calls() != 4 {
		t.Fatalf("expected 4 RAM calls (3 list + 1 admin probe), got %d", fake.Calls())
	}
	assertSignedViaDoer(t, fake, "ram.aliyuncs.com")
}

// The admin probe is bounded: with more users than maxAdminProbe, only that many
// extra calls happen.
func TestAliyunListIAMAdminProbeBounded(t *testing.T) {
	users := make([]string, 0, maxAdminProbe+5)
	for i := 0; i < maxAdminProbe+5; i++ {
		users = append(users, `{"UserName":"u","UserId":"id"}`)
	}
	body := `{"Users":{"User":[` + strings.Join(users, ",") + `]},"IsTruncated":false,"RequestId":"r"}`
	fake := harness.NewHTTPJSON(body)
	p := newFakeProvider(fake)

	if _, err := p.ListIAM(context.Background(), testCreds(), IAMRequest{Include: []string{"users"}}); err != nil {
		t.Fatalf("ListIAM error: %v", err)
	}
	// 1 ListUsers + at most maxAdminProbe probes.
	if fake.Calls() != 1+maxAdminProbe {
		t.Fatalf("expected %d calls (1 list + %d probes), got %d", 1+maxAdminProbe, maxAdminProbe, fake.Calls())
	}
}

// ────────────────────────── ListStorage ──────────────────────────

func TestAliyunListStorageBucketsOffline(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult>
  <Owner><ID>1</ID><DisplayName>acct</DisplayName></Owner>
  <Buckets>
    <Bucket><Name>b-bucket</Name><Location>oss-cn-hangzhou</Location><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>
    <Bucket><Name>a-bucket</Name><Location>oss-cn-hangzhou</Location><CreationDate>2024-01-02T00:00:00.000Z</CreationDate></Bucket>
  </Buckets>
  <IsTruncated>false</IsTruncated>
</ListAllMyBucketsResult>`
	fake := harness.NewHTTP(200, xml)
	p := newFakeProvider(fake)

	page, err := p.ListStorage(context.Background(), testCreds(), StorageRequest{})
	if err != nil {
		t.Fatalf("ListStorage returned error: %v", err)
	}
	if len(page.Buckets) != 2 {
		t.Fatalf("got %d buckets, want 2", len(page.Buckets))
	}
	// Sorted by name.
	if page.Buckets[0].Name != "a-bucket" || page.Buckets[1].Name != "b-bucket" {
		t.Errorf("buckets not sorted: %+v", page.Buckets)
	}
	if page.Buckets[0].Region != "oss-cn-hangzhou" || page.Buckets[0].CreatedAt == "" {
		t.Errorf("bucket fields mapped wrong: %+v", page.Buckets[0])
	}
	if page.Total != 2 {
		t.Errorf("Total = %d, want 2", page.Total)
	}
	last, _ := fake.Last()
	if !strings.Contains(last.URL, "aliyuncs.com") {
		t.Errorf("OSS request URL %q not an aliyun host", last.URL)
	}
	if last.Headers["Authorization"] == "" {
		t.Errorf("OSS request was not signed (no Authorization header)")
	}
}

func TestAliyunListStorageObjectsOffline(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>my-bucket</Name>
  <Prefix>logs/</Prefix>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>logs/a.txt</Key><Size>5</Size><LastModified>2024-01-01T00:00:00.000Z</LastModified></Contents>
  <Contents><Key>logs/b.txt</Key><Size>10</Size><LastModified>2024-01-02T00:00:00.000Z</LastModified></Contents>
</ListBucketResult>`
	fake := harness.NewHTTP(200, xml)
	p := newFakeProvider(fake)

	page, err := p.ListStorage(context.Background(), testCreds(), StorageRequest{
		Bucket: "my-bucket", Prefix: "logs/",
	})
	if err != nil {
		t.Fatalf("ListStorage returned error: %v", err)
	}
	if len(page.Objects) != 2 {
		t.Fatalf("got %d objects, want 2", len(page.Objects))
	}
	if page.Objects[0].Key != "logs/a.txt" || page.Objects[0].Size != 5 || page.Objects[0].LastModified == "" {
		t.Errorf("object mapped wrong: %+v", page.Objects[0])
	}
	last, _ := fake.Last()
	// The list request must name the bucket and prefix; no object body is fetched.
	if !strings.Contains(last.URL, "my-bucket") || !strings.Contains(last.URL, "prefix=logs") {
		t.Errorf("object list URL %q missing bucket/prefix", last.URL)
	}
}

// ────────────────────────── RunCommand ──────────────────────────

func TestAliyunRunCommandOffline(t *testing.T) {
	output := base64.StdEncoding.EncodeToString([]byte("hello\n"))
	// Both ECS calls land on the same host and the RPC action travels in a
	// header, not the URL, so one body serves both: RunCommand reads
	// InvokeId/CommandId and DescribeInvocationResults reads Invocation, each
	// ignoring the other's fields.
	body := `{"InvokeId":"t-1","CommandId":"c-1",` +
		`"Invocation":{"InvocationResults":{"InvocationResult":[{"InvokeId":"t-1","InstanceId":"i-bp1","InvocationStatus":"Success","ExitCode":0,"Output":"` + output + `"}]}},` +
		`"RequestId":"r"}`
	fake := harness.NewHTTPJSON(body)
	p := newFakeProvider(fake)

	res, err := p.RunCommand(context.Background(), testCreds(), CommandRequest{
		InstanceID: "i-bp1", Command: "id", TimeoutSec: 30, Region: "cn-hangzhou",
	})
	if err != nil {
		t.Fatalf("RunCommand returned error: %v", err)
	}
	if res.CommandID != "c-1" || res.InstanceID != "i-bp1" {
		t.Errorf("result identifiers wrong: %+v", res)
	}
	if res.Status != "Success" || res.ExitCode != 0 {
		t.Errorf("status/exit mapped wrong: status=%q exit=%d", res.Status, res.ExitCode)
	}
	if res.Stdout != "hello\n" {
		t.Errorf("Stdout = %q, want %q (base64-decoded)", res.Stdout, "hello\n")
	}
	if fake.Calls() != 2 {
		t.Fatalf("expected 2 calls (RunCommand + one poll), got %d", fake.Calls())
	}

	// The RunCommand request carries the command base64-encoded, never as
	// plaintext.
	runReq := fake.Requests()[0]
	encoded := base64.StdEncoding.EncodeToString([]byte("id"))
	if !strings.Contains(runReq.URL, "CommandContent="+url.QueryEscape(encoded)) &&
		!strings.Contains(string(runReq.Body), encoded) {
		t.Errorf("RunCommand request does not carry base64 command %q; url=%q body=%q",
			encoded, runReq.URL, string(runReq.Body))
	}
	if !strings.Contains(runReq.Headers["Authorization"], "Credential=") {
		t.Errorf("RunCommand request not SDK-signed: %q", runReq.Headers["Authorization"])
	}
}

// ────────────────────────── error classification ──────────────────────────

func TestClassifyAliyunErrorCodes(t *testing.T) {
	cases := []struct {
		code string
		want Reason
	}{
		{"InvalidAccessKeyId.NotFound", ReasonInvalidCredential},
		{"InvalidAccessKeyId", ReasonInvalidCredential},
		{"SignatureDoesNotMatch", ReasonInvalidCredential},
		{"MissingAuthenticationToken", ReasonInvalidCredential},
		{"InvalidSecurityToken.Expired", ReasonInvalidCredential},
		{"Forbidden", ReasonPermissionDenied},
		{"Forbidden.RAM", ReasonPermissionDenied},
		{"AccessDenied", ReasonPermissionDenied},
		{"NoPermission", ReasonPermissionDenied},
		{"Forbidden.AccessKeyDisabled", ReasonPermissionDenied},
		{"InvalidRegionId", ReasonRegionInvalid},
		{"InvalidParameter.RegionId", ReasonRegionInvalid},
		{"InvalidRegionId.NotFound", ReasonRegionInvalid},
		{"IncorrectInstanceStatus", ReasonInstanceNotRunning},
		{"InvalidInstanceStatus", ReasonInstanceNotRunning},
		{"InvalidDBInstanceState", ReasonInstanceNotRunning},
		{"InvalidInstanceId.NotFound", ReasonNotFound},
		{"InvalidDBInstanceId.NotFound", ReasonNotFound},
		{"NoSuchBucket", ReasonNotFound},
		{"InvalidBucketName", ReasonNotFound},
		{"Throttling", ReasonThrottled},
		{"Throttling.User", ReasonThrottled},
		{"ServiceUnavailable", ReasonThrottled},
		{"RequestLimitExceeded", ReasonThrottled},
		{"OperationDenied.TooManyRequests", ReasonThrottled},
		{"RequestTimeout", ReasonTimeout},
		{"Timeout", ReasonTimeout},
	}
	for _, tc := range cases {
		got := classifyAliyun(&tea.SDKError{Code: tea.String(tc.code), Message: tea.String("boom")})
		if got == nil {
			t.Errorf("%s: classifyAliyun returned nil", tc.code)
			continue
		}
		if got.Reason != tc.want {
			t.Errorf("%s: Reason = %q, want %q", tc.code, got.Reason, tc.want)
		}
		if got.Code != tc.code {
			t.Errorf("%s: Code = %q, want verbatim %q", tc.code, got.Code, tc.code)
		}
		if got.Provider != ProviderAliyun {
			t.Errorf("%s: Provider = %q, want %q", tc.code, got.Provider, ProviderAliyun)
		}
	}
}

// OSS surfaces its own error type; the classifier must read it too.
func TestClassifyAliyunOSSError(t *testing.T) {
	got := classifyAliyun(&oss.ServiceError{Code: "NoSuchBucket", Message: "bucket gone"})
	if got == nil || got.Reason != ReasonNotFound {
		t.Fatalf("OSS NoSuchBucket classified as %+v, want not_found", got)
	}
}

// An undocumented code falls through to the prose fallback.
func TestClassifyAliyunFallbackByMessage(t *testing.T) {
	got := classifyAliyun(&tea.SDKError{Code: tea.String("Odd.NewCode"), Message: tea.String("request was throttled")})
	if got == nil || got.Reason != ReasonThrottled {
		t.Fatalf("fallback classification = %+v, want throttled", got)
	}
}

func TestClassifyAliyunTimeoutContext(t *testing.T) {
	got := classifyAliyun(context.DeadlineExceeded)
	if got == nil || got.Reason != ReasonTimeout {
		t.Fatalf("context deadline classified as %+v, want timeout", got)
	}
}

func TestClassifyAliyunNil(t *testing.T) {
	if got := classifyAliyun(nil); got != nil {
		t.Fatalf("classifyAliyun(nil) = %+v, want nil", got)
	}
}

// dara.SDKError is the other SDK error shape; it must classify the same way.
func TestClassifyAliyunDaraSDKError(t *testing.T) {
	got := classifyAliyun(&dara.SDKError{Code: tea.String("InvalidInstanceStatus"), Message: tea.String("not running")})
	if got == nil || got.Reason != ReasonInstanceNotRunning {
		t.Fatalf("dara.SDKError classified as %+v, want instance_not_running", got)
	}
}

// ────────────────────────── boundaries ──────────────────────────

// Without an injected doer every call must report the host's unavailable error,
// not dial a vendor directly.
func TestAliyunUnavailableWithoutDoer(t *testing.T) {
	p := &aliyunProvider{h: newHTTPDoerClient(nil, 0)}

	_, err := p.Verify(context.Background(), testCreds())
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

// A host gate error (scope denial) must survive classification verbatim, so
// cloudkit.go's failure() keeps the host's code.
func TestAliyunCapkitErrorPassthrough(t *testing.T) {
	denied := core.ScopeDenied("out of scope: ecs.cn-hangzhou.aliyuncs.com")
	got := aliyunError(denied)
	var ce *core.Error
	if !errors.As(got, &ce) {
		t.Fatalf("want *core.Error passthrough, got %T", got)
	}
	if ce.Code != core.CodeScopeDenied {
		t.Fatalf("code = %q, want %q", ce.Code, core.CodeScopeDenied)
	}
}

// Missing credentials must fail before any SDK call.
func TestAliyunMissingCredential(t *testing.T) {
	fake := harness.NewHTTPJSON(`{}`)
	p := newFakeProvider(fake)

	_, err := p.Verify(context.Background(), Credentials{})
	var ce *Error
	if !errors.As(err, &ce) || ce.Reason != ReasonInvalidCredential {
		t.Fatalf("want invalid_credential, got %v", err)
	}
	if fake.Calls() != 0 {
		t.Fatalf("no request should be sent without credentials, got %d", fake.Calls())
	}
}
