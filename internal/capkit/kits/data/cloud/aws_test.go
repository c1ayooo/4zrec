package cloud

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/harness"
)

// Every test below is fully offline: the SDK's HTTP client is the injected
// httpDoerClient, whose doer is a scripted harness.HTTP. No AWS host is ever
// dialed; the assertions read what the SDK would have sent.
//
// The responses are the vendors' wire formats — AWS serves XML for the query
// protocol (STS, EC2, RDS, IAM, S3) and JSON for SSM — so a test that passes
// here proves the SDK parsed the request the kit asked for.

func awsTestCreds() Credentials {
	return Credentials{
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
	}
}

func newAWSFakeProvider(fake *harness.HTTP) *awsProvider {
	return &awsProvider{h: newHTTPDoerClient(fake, 0)}
}

// awsRequestFor finds the single recorded request whose URL contains fragment.
func awsRequestFor(t *testing.T, fake *harness.HTTP, fragment string) core.Request {
	t.Helper()
	for _, r := range fake.Requests() {
		if strings.Contains(r.URL, fragment) {
			return r
		}
	}
	var urls []string
	for _, r := range fake.Requests() {
		urls = append(urls, r.URL)
	}
	t.Fatalf("no recorded request URL contained %q; calls=%v", fragment, urls)
	return core.Request{}
}

// assertAWSSignedViaDoer proves the request went through the injected doer and
// was signed by the SDK: SigV4 signs with the caller's AK, so a Credential=
// scope naming that AK can only come from the SDK's own signer.
func assertAWSSignedViaDoer(t *testing.T, fake *harness.HTTP, hostFragment string) {
	t.Helper()
	if fake.Calls() == 0 {
		t.Fatal("expected at least one request through the injected doer, got 0")
	}
	last, ok := fake.Last()
	if !ok {
		t.Fatal("no request recorded")
	}
	if !strings.Contains(last.URL, hostFragment) {
		t.Fatalf("request URL %q does not contain %q", last.URL, hostFragment)
	}
	auth := last.Headers["Authorization"]
	if !strings.Contains(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/") {
		t.Fatalf("Authorization header %q missing a SigV4 Credential scope for the caller's AK (SDK did not sign)", auth)
	}
}

// ────────────────────────── Verify ──────────────────────────

const awsCallerIdentityXML = `<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/alice</Arn>
    <UserId>AIDAEXAMPLEUSERID</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`

func TestAWSVerifyOffline(t *testing.T) {
	fake := harness.NewHTTP(200, awsCallerIdentityXML)
	p := newAWSFakeProvider(fake)

	id, err := p.Verify(context.Background(), awsTestCreds())
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if id.AccountID != "123456789012" {
		t.Errorf("AccountID = %q, want 123456789012", id.AccountID)
	}
	if id.ARN != "arn:aws:iam::123456789012:user/alice" {
		t.Errorf("ARN = %q", id.ARN)
	}
	if id.Type != "iam_user" {
		t.Errorf("Type = %q, want iam_user", id.Type)
	}
	if id.Alias != "AIDAEXAMPLEUSERID" {
		t.Errorf("Alias = %q", id.Alias)
	}
	// One signed STS call, and the caller's region reached the endpoint.
	if fake.Calls() != 1 {
		t.Fatalf("expected exactly 1 STS call, got %d", fake.Calls())
	}
	assertAWSSignedViaDoer(t, fake, "sts.us-east-1.amazonaws.com")
}

// TestAWSVerifyDefaultsRegion covers a caller that gave no region: STS is global,
// so the config falls back rather than failing.
func TestAWSVerifyDefaultsRegion(t *testing.T) {
	fake := harness.NewHTTP(200, awsCallerIdentityXML)
	p := newAWSFakeProvider(fake)

	creds := awsTestCreds()
	creds.Region = ""
	if _, err := p.Verify(context.Background(), creds); err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	assertAWSSignedViaDoer(t, fake, "sts."+defaultAWSRegion+".amazonaws.com")
}

// TestAWSVerifyHonorsEndpoint covers the endpoint override: a sovereign or
// proxy endpoint must be used verbatim instead of the SDK's own resolution.
func TestAWSVerifyHonorsEndpoint(t *testing.T) {
	fake := harness.NewHTTP(200, awsCallerIdentityXML)
	p := newAWSFakeProvider(fake)

	creds := awsTestCreds()
	creds.Endpoint = "https://sts.internal.example"
	if _, err := p.Verify(context.Background(), creds); err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	last, _ := fake.Last()
	if !strings.Contains(last.URL, "sts.internal.example") {
		t.Fatalf("endpoint override ignored: URL %q", last.URL)
	}
}

// TestAWSVerifyMissingCredential is the input guard: no ambient credential
// lookup is attempted, so an empty key pair fails before any request.
func TestAWSVerifyMissingCredential(t *testing.T) {
	fake := harness.NewHTTP(200, awsCallerIdentityXML)
	p := newAWSFakeProvider(fake)

	_, err := p.Verify(context.Background(), Credentials{Region: "us-east-1"})
	if err == nil {
		t.Fatal("want an error for a missing credential")
	}
	var ce *Error
	if !errors.As(err, &ce) || ce.Reason != ReasonInvalidCredential {
		t.Fatalf("err = %v, want reason %s", err, ReasonInvalidCredential)
	}
	if fake.Calls() != 0 {
		t.Fatalf("a missing credential must not reach the wire, got %d calls", fake.Calls())
	}
}

func TestAWSIdentityType(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::1:root":                      "root_account",
		"arn:aws:iam::1:user/alice":                "iam_user",
		"arn:aws:sts::1:assumed-role/role/session": "assumed_role",
		"arn:aws:sts::1:federated-user/bob":        "federated_user",
		"arn:aws:iam::1:role/service-role/app":     "iam_role",
		"arn:aws:iam::1:group/admins":              "group/admins",
		"":                                         "",
		"arn:aws:iam":                              "",
	}
	for arn, want := range cases {
		if got := awsIdentityType(arn); got != want {
			t.Errorf("awsIdentityType(%q) = %q, want %q", arn, got, want)
		}
	}
}

// ────────────────────────── ListAssets ──────────────────────────

const awsDescribeInstancesXML = `<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet>
    <item>
      <instancesSet>
        <item>
          <instanceId>i-0aaa1111</instanceId>
          <imageId>ami-1</imageId>
          <instanceState><code>16</code><name>running</name></instanceState>
          <privateIpAddress>10.0.0.11</privateIpAddress>
          <ipAddress>203.0.113.11</ipAddress>
          <instanceType>t3.micro</instanceType>
          <placement><availabilityZone>us-east-1a</availabilityZone></placement>
          <tagSet>
            <item><key>Name</key><value>web-1</value></item>
            <item><key>Env</key><value>prod</value></item>
          </tagSet>
        </item>
        <item>
          <instanceId>i-0bbb2222</instanceId>
          <instanceState><code>80</code><name>stopped</name></instanceState>
          <instanceType>t3.small</instanceType>
          <placement><availabilityZone>us-east-1b</availabilityZone></placement>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
  <nextToken>page-2</nextToken>
</DescribeInstancesResponse>`

const awsDescribeDBInstancesXML = `<?xml version="1.0" encoding="UTF-8"?>
<DescribeDBInstancesResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/">
  <DescribeDBInstancesResult>
    <DBInstances>
      <DBInstance>
        <DBInstanceIdentifier>db-prod-1</DBInstanceIdentifier>
        <DBInstanceClass>db.t3.medium</DBInstanceClass>
        <Engine>postgres</Engine>
        <EngineVersion>16.3</EngineVersion>
        <DBInstanceStatus>available</DBInstanceStatus>
        <AvailabilityZone>us-east-1a</AvailabilityZone>
        <Endpoint><Address>db-prod-1.example.internal</Address><Port>5432</Port></Endpoint>
      </DBInstance>
    </DBInstances>
    <Marker>marker-2</Marker>
  </DescribeDBInstancesResult>
  <ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>
</DescribeDBInstancesResponse>`

func TestAWSListAssetsOffline(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: ""},
		Routes: []harness.Route{
			{Match: "ec2.us-east-1.amazonaws.com", Status: 200, Body: awsDescribeInstancesXML},
			{Match: "rds.us-east-1.amazonaws.com", Status: 200, Body: awsDescribeDBInstancesXML},
		},
	}
	p := newAWSFakeProvider(fake)

	page, err := p.ListAssets(context.Background(), awsTestCreds(), AssetRequest{
		Kinds:    []string{AssetCompute, AssetDatabase},
		Region:   "us-east-1",
		PageSize: 50,
	})
	if err != nil {
		t.Fatalf("ListAssets returned error: %v", err)
	}
	if len(page.Instances) != 3 {
		t.Fatalf("got %d instances, want 3: %+v", len(page.Instances), page.Instances)
	}
	compute, database := 0, 0
	for _, inst := range page.Instances {
		switch inst.Kind {
		case AssetCompute:
			compute++
		case AssetDatabase:
			database++
		}
	}
	if compute != 2 || database != 1 {
		t.Fatalf("kinds wrong: compute=%d database=%d", compute, database)
	}
	web := page.Instances[0]
	if web.ID != "i-0aaa1111" || web.Name != "web-1" || web.Status != "running" || web.Type != "t3.micro" {
		t.Errorf("EC2 instance mapped wrong: %+v", web)
	}
	if web.Region != "us-east-1" || web.Zone != "us-east-1a" {
		t.Errorf("EC2 placement mapped wrong: %+v", web)
	}
	if len(web.PrivateIP) != 1 || web.PrivateIP[0] != "10.0.0.11" {
		t.Errorf("PrivateIP = %v", web.PrivateIP)
	}
	if len(web.PublicIP) != 1 || web.PublicIP[0] != "203.0.113.11" {
		t.Errorf("PublicIP = %v", web.PublicIP)
	}
	stopped := page.Instances[1]
	if stopped.Status != "stopped" || stopped.Name != "" {
		t.Errorf("untagged instance mapped wrong: %+v", stopped)
	}
	db := page.Instances[2]
	if db.ID != "db-prod-1" || db.Kind != AssetDatabase || db.Engine != "postgres 16.3" {
		t.Errorf("RDS instance mapped wrong: %+v", db)
	}
	if db.Status != "available" || db.Type != "db.t3.medium" {
		t.Errorf("RDS status/class mapped wrong: %+v", db)
	}
	// Both services handed back a continuation token, so the caller can page.
	if !page.HasMore || page.Cursor == "" {
		t.Errorf("pagination not surfaced: cursor=%q hasMore=%v", page.Cursor, page.HasMore)
	}
	if page.Total != 3 {
		t.Errorf("Total = %d, want 3", page.Total)
	}
	assertAWSSignedViaDoer(t, fake, "rds.us-east-1.amazonaws.com")
}

// TestAWSListAssetsPartialFailure covers one service failing while the other
// succeeds: the caller gets the data it can, plus a warning naming the failure.
func TestAWSListAssetsPartialFailure(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: ""},
		Routes: []harness.Route{
			{Match: "ec2.us-east-1.amazonaws.com", Status: 200, Body: awsDescribeInstancesXML},
			{Match: "rds.us-east-1.amazonaws.com", Status: 403, Body: `<ErrorResponse><Error><Code>AccessDenied</Code><Message>User is not authorized</Message></Error></ErrorResponse>`},
		},
	}
	p := newAWSFakeProvider(fake)

	page, err := p.ListAssets(context.Background(), awsTestCreds(), AssetRequest{
		Kinds: []string{AssetCompute, AssetDatabase}, Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("a partial failure must not fail the call: %v", err)
	}
	if len(page.Instances) != 2 {
		t.Fatalf("got %d compute instances, want 2", len(page.Instances))
	}
	if len(page.Warnings) != 1 || !strings.Contains(page.Warnings[0], "RDS") {
		t.Fatalf("warnings = %v, want one naming RDS", page.Warnings)
	}
	if !strings.Contains(page.Warnings[0], ReasonPermissionDenied.Label()) {
		t.Errorf("warning does not classify the 403 as %s: %q", ReasonPermissionDenied.Label(), page.Warnings[0])
	}
}

// TestAWSListAssetsAllFail covers every requested kind failing: that is a
// failure, not an empty-but-successful listing.
func TestAWSListAssetsAllFail(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 403, Body: `<ErrorResponse><Error><Code>UnauthorizedOperation</Code><Message>You are not authorized</Message></Error></ErrorResponse>`},
	}
	p := newAWSFakeProvider(fake)

	_, err := p.ListAssets(context.Background(), awsTestCreds(), AssetRequest{
		Kinds: []string{AssetCompute, AssetDatabase}, Region: "us-east-1",
	})
	if err == nil {
		t.Fatal("want an error when every kind failed")
	}
	var ce *Error
	if !errors.As(err, &ce) || ce.Reason != ReasonUpstream {
		t.Fatalf("err = %v, want reason %s", err, ReasonUpstream)
	}
}

// TestAWSListAssetsUnknownKind covers a kind this provider does not implement:
// it is reported as a warning rather than silently dropped.
func TestAWSListAssetsUnknownKind(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: ""},
		Routes:  []harness.Route{{Match: "ec2.us-east-1.amazonaws.com", Status: 200, Body: awsDescribeInstancesXML}},
	}
	p := newAWSFakeProvider(fake)

	page, err := p.ListAssets(context.Background(), awsTestCreds(), AssetRequest{
		Kinds: []string{AssetCompute, "loadbalancer"}, Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(page.Warnings) != 1 || !strings.Contains(page.Warnings[0], "loadbalancer") {
		t.Fatalf("warnings = %v, want one naming the unsupported kind", page.Warnings)
	}
}

// TestAWSListAssetsCursorIsForwarded covers the page token: it must travel as
// NextToken/Marker, not be dropped.
func TestAWSListAssetsCursorIsForwarded(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: ""},
		Routes: []harness.Route{
			{Match: "ec2.us-east-1.amazonaws.com", Status: 200, Body: awsDescribeInstancesXML},
			{Match: "rds.us-east-1.amazonaws.com", Status: 200, Body: awsDescribeDBInstancesXML},
		},
	}
	p := newAWSFakeProvider(fake)

	if _, err := p.ListAssets(context.Background(), awsTestCreds(), AssetRequest{
		Kinds: []string{AssetCompute, AssetDatabase}, Region: "us-east-1",
		PageSize: 50, Cursor: "token-abc",
	}); err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	for _, svc := range []string{"ec2", "rds"} {
		req := awsRequestFor(t, fake, svc+".us-east-1.amazonaws.com")
		body := string(req.Body)
		if !strings.Contains(body, "token-abc") {
			t.Errorf("%s request did not carry the cursor: %s", svc, body)
		}
	}
	if body := string(awsRequestFor(t, fake, "ec2.us-east-1.amazonaws.com").Body); !strings.Contains(body, "MaxResults=50") {
		t.Errorf("EC2 request did not carry MaxResults: %s", body)
	}
	// A page size EC2 cannot honour is raised to its floor of 5 rather than sent
	// verbatim and rejected.
	if _, err := p.ListAssets(context.Background(), awsTestCreds(), AssetRequest{
		Kinds: []string{AssetCompute}, Region: "us-east-1", PageSize: 1,
	}); err != nil {
		t.Fatalf("ListAssets(small page): %v", err)
	}
	if body := string(awsRequestFor(t, fake, "ec2.us-east-1.amazonaws.com").Body); !strings.Contains(body, "MaxResults=5") {
		t.Errorf("EC2 page size floor not applied: %s", body)
	}
}

// ────────────────────────── ListIAM ──────────────────────────

const awsListUsersXML = `<?xml version="1.0" encoding="UTF-8"?>
<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListUsersResult>
    <Users>
      <member>
        <UserName>admin-bob</UserName><UserId>AIDA1</UserId><Arn>arn:aws:iam::1:user/admin-bob</Arn>
        <CreateDate>2024-02-01T10:00:00Z</CreateDate>
      </member>
      <member>
        <UserName>svc-reader</UserName><UserId>AIDA2</UserId><Arn>arn:aws:iam::1:user/svc-reader</Arn>
        <CreateDate>2024-03-01T10:00:00Z</CreateDate>
      </member>
    </Users>
    <IsTruncated>true</IsTruncated>
    <Marker>users-page-2</Marker>
  </ListUsersResult>
  <ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>
</ListUsersResponse>`

const awsListPoliciesXML = `<?xml version="1.0" encoding="UTF-8"?>
<ListPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListPoliciesResult>
    <Policies>
      <member>
        <PolicyName>AdministratorAccess</PolicyName><PolicyId>ANPA1</PolicyId>
        <Description>Full admin</Description><AttachmentCount>3</AttachmentCount>
        <Arn>arn:aws:iam::aws:policy/AdministratorAccess</Arn>
      </member>
      <member>
        <PolicyName>ReadOnlyAudit</PolicyName><PolicyId>ANPA2</PolicyId>
        <AttachmentCount>0</AttachmentCount>
        <Arn>arn:aws:iam::1:policy/ReadOnlyAudit</Arn>
      </member>
    </Policies>
    <IsTruncated>false</IsTruncated>
  </ListPoliciesResult>
  <ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>
</ListPoliciesResponse>`

const awsListAccessKeysXML = `<?xml version="1.0" encoding="UTF-8"?>
<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListAccessKeysResult>
    <AccessKeyMetadata>
      <member>
        <UserName>admin-bob</UserName><AccessKeyId>AKIA1</AccessKeyId>
        <Status>Active</Status><CreateDate>2024-02-02T10:00:00Z</CreateDate>
      </member>
    </AccessKeyMetadata>
    <IsTruncated>false</IsTruncated>
  </ListAccessKeysResult>
  <ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>
</ListAccessKeysResponse>`

// awsListAttachedUserPoliciesXML is what the bounded admin probe reads.
const awsListAttachedUserPoliciesXML = `<?xml version="1.0" encoding="UTF-8"?>
<ListAttachedUserPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListAttachedUserPoliciesResult>
    <AttachedPolicies>
      <member>
        <PolicyName>AdministratorAccess</PolicyName>
        <PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn>
      </member>
    </AttachedPolicies>
    <IsTruncated>false</IsTruncated>
  </ListAttachedUserPoliciesResult>
  <ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>
</ListAttachedUserPoliciesResponse>`

func TestAWSListIAMOffline(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: awsListAttachedUserPoliciesXML},
		Routes: []harness.Route{
			{Match: "iam.amazonaws.com", Status: 200, Body: awsListUsersXML},
		},
	}
	// The three IAM reads share one host, so dispatch on the Action the SDK put
	// in the query body. The fake routes on URL substrings only, so the response
	// body is chosen by action below via a per-action doer instead.
	p := newAWSFakeProvider(fake)

	_, err := p.ListIAM(context.Background(), awsTestCreds(), IAMRequest{Include: []string{"users"}})
	if err != nil {
		t.Fatalf("ListIAM(users): %v", err)
	}
	if fake.Calls() == 0 {
		t.Fatal("no IAM request recorded")
	}
	if auth := awsRequestFor(t, fake, "iam.amazonaws.com").Headers["Authorization"]; !strings.Contains(auth, "AWS4-HMAC-SHA256") {
		t.Fatalf("IAM request not SDK-signed: %q", auth)
	}
}

// TestAWSIAMActionsDispatch reads the three include categories through one
// host: the routing key is the Action the SDK wrote into the request body.
func TestAWSIAMActionsDispatch(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 200, Body: awsListAttachedUserPoliciesXML}}
	fake.Queue = []harness.Route{
		{Body: awsListUsersXML},
		{Body: awsListPoliciesXML},
		{Body: awsListAccessKeysXML},
	}
	p := newAWSFakeProvider(fake)

	page, err := p.ListIAM(context.Background(), awsTestCreds(), IAMRequest{
		Include: []string{"users", "policies", "access_keys"},
	})
	if err != nil {
		t.Fatalf("ListIAM returned error: %v", err)
	}
	if len(page.Users) != 2 {
		t.Fatalf("users = %+v", page.Users)
	}
	if page.Users[0].Name != "admin-bob" || page.Users[0].CreatedAt == "" {
		t.Errorf("user mapped wrong: %+v", page.Users[0])
	}
	// The queued responses are spent in call order, and the admin probe follows
	// the three category reads, so admin-bob's directly attached policy marks it.
	if page.Users[0].AdminHint != "AdministratorAccess" {
		t.Errorf("admin probe did not mark admin-bob: %+v", page.Users[0])
	}
	if page.Users[1].AdminHint != "AdministratorAccess" {
		t.Errorf("admin probe skipped svc-reader (bounded probe should cover both): %+v", page.Users[1])
	}
	if len(page.Policies) != 2 {
		t.Fatalf("policies = %+v", page.Policies)
	}
	if !page.Policies[0].Admin || page.Policies[0].Attachments != 3 || page.Policies[0].Description != "Full admin" {
		t.Errorf("policy mapped wrong: %+v", page.Policies[0])
	}
	if page.Policies[1].Admin {
		t.Errorf("ReadOnlyAudit wrongly flagged administrative: %+v", page.Policies[1])
	}
	if len(page.AccessKeys) != 1 || page.AccessKeys[0].ID != "AKIA1" || page.AccessKeys[0].Status != "Active" {
		t.Fatalf("access keys = %+v", page.AccessKeys)
	}
	if !page.HasMore || page.Cursor != "users-page-2" {
		t.Errorf("user pagination not surfaced: cursor=%q hasMore=%v", page.Cursor, page.HasMore)
	}
	if page.Total != 5 {
		t.Errorf("Total = %d, want 5", page.Total)
	}
}

// TestAWSListIAMUnsupportedInclude covers a category this provider does not
// implement: a warning, not a silent omission.
func TestAWSListIAMUnsupportedInclude(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 200, Body: awsListUsersXML}}
	p := newAWSFakeProvider(fake)

	page, err := p.ListIAM(context.Background(), awsTestCreds(), IAMRequest{Include: []string{"users", "groups"}})
	if err != nil {
		t.Fatalf("ListIAM: %v", err)
	}
	if len(page.Warnings) != 1 || !strings.Contains(page.Warnings[0], "groups") {
		t.Fatalf("warnings = %v, want one naming groups", page.Warnings)
	}
}

// TestAWSListIAMAllFail covers every category failing.
func TestAWSListIAMAllFail(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 403, Body: `<ErrorResponse><Error><Code>AccessDenied</Code><Message>not authorized</Message></Error></ErrorResponse>`}}
	p := newAWSFakeProvider(fake)

	_, err := p.ListIAM(context.Background(), awsTestCreds(), IAMRequest{Include: []string{"users"}})
	if err == nil {
		t.Fatal("want an error when every category failed")
	}
	var ce *Error
	if !errors.As(err, &ce) || ce.Reason != ReasonUpstream {
		t.Fatalf("err = %v, want reason %s", err, ReasonUpstream)
	}
}

// ────────────────────────── ListStorage ──────────────────────────

const awsListBucketsXML = `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult>
  <Owner><ID>owner-1</ID><DisplayName>acct</DisplayName></Owner>
  <Buckets>
    <Bucket><Name>b-logs</Name><CreationDate>2024-01-02T00:00:00.000Z</CreationDate></Bucket>
    <Bucket><Name>a-assets</Name><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`

const awsListObjectsXML = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>my-bucket</Name>
  <Prefix>logs/</Prefix>
  <KeyCount>2</KeyCount>
  <MaxKeys>2</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>cont-2</NextContinuationToken>
  <Contents><Key>logs/a.txt</Key><Size>5</Size><LastModified>2024-01-01T00:00:00.000Z</LastModified></Contents>
  <Contents><Key>logs/b.txt</Key><Size>10</Size><LastModified>2024-01-02T00:00:00.000Z</LastModified></Contents>
</ListBucketResult>`

func TestAWSListStorageBucketsOffline(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 200, Body: awsListBucketsXML}}
	p := newAWSFakeProvider(fake)

	page, err := p.ListStorage(context.Background(), awsTestCreds(), StorageRequest{})
	if err != nil {
		t.Fatalf("ListStorage returned error: %v", err)
	}
	if len(page.Buckets) != 2 {
		t.Fatalf("got %d buckets, want 2", len(page.Buckets))
	}
	if page.Buckets[0].Name != "a-assets" || page.Buckets[1].Name != "b-logs" {
		t.Errorf("buckets not sorted by name: %+v", page.Buckets)
	}
	if page.Buckets[0].CreatedAt == "" {
		t.Errorf("bucket creation date not mapped: %+v", page.Buckets[0])
	}
	if page.Total != 2 {
		t.Errorf("Total = %d, want 2", page.Total)
	}
	assertAWSSignedViaDoer(t, fake, "s3.us-east-1.amazonaws.com")
}

func TestAWSListStorageObjectsOffline(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 200, Body: awsListObjectsXML}}
	p := newAWSFakeProvider(fake)

	page, err := p.ListStorage(context.Background(), awsTestCreds(), StorageRequest{
		Bucket: "my-bucket", Prefix: "logs/", MaxResults: 2,
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
	if !page.HasMore || page.Cursor != "cont-2" {
		t.Errorf("object pagination not surfaced: cursor=%q hasMore=%v", page.Cursor, page.HasMore)
	}
	// The list request names the bucket and prefix in the URL path/query; no
	// object body is fetched for a metadata listing.
	req := awsRequestFor(t, fake, "my-bucket")
	if !strings.Contains(req.URL, "my-bucket") {
		t.Errorf("object list URL %q missing the bucket", req.URL)
	}
	if !strings.Contains(req.URL, "prefix=logs") || !strings.Contains(req.URL, "list-type=2") {
		t.Errorf("object list URL %q missing prefix/list-type", req.URL)
	}
}

func TestAWSListStorageError(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 404, Body: `<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`}}
	p := newAWSFakeProvider(fake)

	_, err := p.ListStorage(context.Background(), awsTestCreds(), StorageRequest{Bucket: "nope"})
	if err == nil {
		t.Fatal("want an error for a missing bucket")
	}
	var ce *Error
	if !errors.As(err, &ce) || ce.Reason != ReasonNotFound {
		t.Fatalf("err = %v, want reason %s", err, ReasonNotFound)
	}
}

// ────────────────────────── RunCommand ──────────────────────────

const awsSendCommandJSON = `{"Command":{"CommandId":"cmd-1","Status":"Pending","StatusDetails":"Pending","DocumentName":"AWS-RunShellScript","InstanceIds":["i-0aaa1111"]}}`

const awsInvocationSuccessJSON = `{"CommandId":"cmd-1","InstanceId":"i-0aaa1111","Status":"Success","StatusDetails":"Success","ResponseCode":0,"StandardOutputContent":"uid=0(root)\n","StandardErrorContent":""}`

func TestAWSRunCommandOffline(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: awsInvocationSuccessJSON},
		Queue:   []harness.Route{{Body: awsSendCommandJSON}},
	}
	p := newAWSFakeProvider(fake)

	res, err := p.RunCommand(context.Background(), awsTestCreds(), CommandRequest{
		InstanceID: "i-0aaa1111", Command: "id", TimeoutSec: 30,
	})
	if err != nil {
		t.Fatalf("RunCommand returned error: %v", err)
	}
	if res.CommandID != "cmd-1" || res.InstanceID != "i-0aaa1111" {
		t.Errorf("identifiers wrong: %+v", res)
	}
	if res.Status != "Success" || res.ExitCode != 0 {
		t.Errorf("status/exit mapped wrong: status=%q exit=%d", res.Status, res.ExitCode)
	}
	if res.Stdout != "uid=0(root)\n" {
		t.Errorf("Stdout = %q", res.Stdout)
	}
	if fake.Calls() != 2 {
		t.Fatalf("expected 2 calls (SendCommand + one poll), got %d", fake.Calls())
	}
	// The command travels in the SendCommand body, and the call is SDK-signed.
	sent := fake.Requests()[0]
	if !strings.Contains(string(sent.Body), "id") || !strings.Contains(string(sent.Body), "AWS-RunShellScript") {
		t.Errorf("SendCommand body does not carry the command/document: %s", string(sent.Body))
	}
	if auth := sent.Headers["Authorization"]; !strings.Contains(auth, "AWS4-HMAC-SHA256") {
		t.Errorf("SendCommand not SDK-signed: %q", auth)
	}
	if !strings.Contains(sent.URL, "ssm.us-east-1.amazonaws.com") {
		t.Errorf("SendCommand URL %q is not the SSM endpoint", sent.URL)
	}
}

// TestAWSRunCommandPollsUntilRegistered covers the SSM race the SDK surfaces as
// InvocationDoesNotExist: the first poll must not be treated as a hard failure.
func TestAWSRunCommandPollsUntilRegistered(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: awsInvocationSuccessJSON},
		Queue: []harness.Route{
			{Body: awsSendCommandJSON},
			{Status: 400, Body: `{"__type":"InvocationDoesNotExist","message":"invocation does not exist"}`},
		},
	}
	p := newAWSFakeProvider(fake)

	res, err := p.RunCommand(context.Background(), awsTestCreds(), CommandRequest{
		InstanceID: "i-0aaa1111", Command: "id",
	})
	if err != nil {
		t.Fatalf("RunCommand returned error: %v", err)
	}
	if res.Status != "Success" || res.Stdout != "uid=0(root)\n" {
		t.Fatalf("poll did not recover: %+v", res)
	}
	if fake.Calls() != 3 {
		t.Fatalf("expected 3 calls (send + 2 polls), got %d", fake.Calls())
	}
}

// TestAWSRunCommandClassifiesFailure covers a terminal Failed invocation: the
// exit code and the error text come back rather than an error being returned,
// because the command ran and its failure is the result.
func TestAWSRunCommandClassifiesFailure(t *testing.T) {
	fake := &harness.HTTP{
		Default: harness.Route{Status: 200, Body: `{"CommandId":"cmd-2","InstanceId":"i-1","Status":"Failed","StatusDetails":"Failed","ResponseCode":1,"StandardOutputContent":"","StandardErrorContent":"command not found"}`},
		Queue:   []harness.Route{{Body: `{"Command":{"CommandId":"cmd-2","Status":"Pending","StatusDetails":"Pending"}}`}},
	}
	p := newAWSFakeProvider(fake)

	res, err := p.RunCommand(context.Background(), awsTestCreds(), CommandRequest{InstanceID: "i-1", Command: "nosuchcmd"})
	if err != nil {
		t.Fatalf("RunCommand returned error: %v", err)
	}
	if res.Status != "Failed" || res.ExitCode != 1 {
		t.Errorf("terminal failure not mapped: %+v", res)
	}
	if res.Stderr != "command not found" {
		t.Errorf("Stderr = %q", res.Stderr)
	}
}

// TestAWSRunCommandSendFails covers SendCommand itself failing: that is an
// error, and the SSM code decides the reason.
func TestAWSRunCommandSendFails(t *testing.T) {
	fake := &harness.HTTP{Default: harness.Route{Status: 400, Body: `{"__type":"InvalidInstanceId","message":"The instance ID is not valid"}`}}
	p := newAWSFakeProvider(fake)

	_, err := p.RunCommand(context.Background(), awsTestCreds(), CommandRequest{InstanceID: "bogus", Command: "id"})
	if err == nil {
		t.Fatal("want an error when SendCommand fails")
	}
	var ce *Error
	if !errors.As(err, &ce) || ce.Reason != ReasonNotFound {
		t.Fatalf("err = %v, want reason %s", err, ReasonNotFound)
	}
}

func TestAWSTerminalCommandStatus(t *testing.T) {
	for _, tc := range []struct {
		status ssmtypes.CommandInvocationStatus
		want   bool
	}{
		{ssmtypes.CommandInvocationStatusSuccess, true},
		{ssmtypes.CommandInvocationStatusCancelled, true},
		{ssmtypes.CommandInvocationStatusTimedOut, true},
		{ssmtypes.CommandInvocationStatusFailed, true},
		{ssmtypes.CommandInvocationStatusPending, false},
		{ssmtypes.CommandInvocationStatusInProgress, false},
		{ssmtypes.CommandInvocationStatusDelayed, false},
	} {
		if got := terminalCommandStatus(tc.status); got != tc.want {
			t.Errorf("terminalCommandStatus(%s) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

// ────────────────────────── error classification ──────────────────────────

func TestClassifyAWSReasons(t *testing.T) {
	cases := []struct {
		code string
		want Reason
	}{
		{"InvalidClientTokenId", ReasonInvalidCredential},
		{"SignatureDoesNotMatch", ReasonInvalidCredential},
		{"ExpiredToken", ReasonInvalidCredential},
		{"AccessDenied", ReasonPermissionDenied},
		{"UnauthorizedOperation", ReasonPermissionDenied},
		{"InvalidRegion", ReasonRegionInvalid},
		{"InvalidParameterValue", ReasonRegionInvalid},
		{"InvalidInstanceID", ReasonNotFound},
		{"NoSuchBucket", ReasonNotFound},
		{"InvalidDBInstanceState", ReasonInstanceNotRunning},
		{"UnsupportedOperation", ReasonInstanceNotRunning},
		{"Throttling", ReasonThrottled},
		{"RequestLimitExceeded", ReasonThrottled},
		{"RequestTimeout", ReasonTimeout},
		{"InternalError", ReasonUpstream},
		{"SomethingUndocumented", ReasonUpstream},
	}
	for _, tc := range cases {
		got := classifyAWS(&smithy.GenericAPIError{Code: tc.code, Message: "m"})
		if got.Reason != tc.want {
			t.Errorf("classifyAWS(%s).Reason = %s, want %s", tc.code, got.Reason, tc.want)
		}
		if got.Provider != ProviderAWS || got.Code != tc.code {
			t.Errorf("classifyAWS(%s) lost provider/code: %+v", tc.code, got)
		}
	}
}

// TestClassifyAWSFallbackByMessage covers undocumented variants that only the
// message identifies.
func TestClassifyAWSFallbackByMessage(t *testing.T) {
	cases := []struct {
		message string
		want    Reason
	}{
		{"The request signature we calculated does not match", ReasonInvalidCredential},
		{"User is not authorized to perform this action", ReasonPermissionDenied},
		{"The instance is not in a valid state for this operation", ReasonInstanceNotRunning},
		{"Rate exceeded", ReasonThrottled},
		{"context deadline exceeded", ReasonTimeout},
		{"The bucket could not be found", ReasonNotFound},
	}
	for _, tc := range cases {
		got := classifyAWS(errors.New(tc.message))
		if got.Reason != tc.want {
			t.Errorf("classifyAWS(%q).Reason = %s, want %s", tc.message, got.Reason, tc.want)
		}
	}
}

// TestClassifyAWSContext covers a caller deadline: it is a timeout, and a
// cancelled context is reported the same way so the agent is told to stop.
func TestClassifyAWSContext(t *testing.T) {
	if got := classifyAWS(context.DeadlineExceeded); got.Reason != ReasonTimeout {
		t.Errorf("deadline = %s, want %s", got.Reason, ReasonTimeout)
	}
	if got := classifyAWS(context.Canceled); got.Reason != ReasonTimeout {
		t.Errorf("cancel = %s, want %s", got.Reason, ReasonTimeout)
	}
}

func TestClassifyAWSNil(t *testing.T) {
	if got := classifyAWS(nil); got != nil {
		t.Errorf("classifyAWS(nil) = %+v, want nil", got)
	}
}

// TestAWSFormatsNoSecretInError is the credential rule: an SDK error message
// must never carry the caller's secret, and the AK is masked in what the tool
// reports.
func TestAWSFormatsNoSecretInError(t *testing.T) {
	creds := awsTestCreds()
	fake := &harness.HTTP{Default: harness.Route{Status: 403, Body: `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match</Message></Error></ErrorResponse>`}}
	p := newAWSFakeProvider(fake)

	_, err := p.Verify(context.Background(), creds)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), creds.SecretKey) {
		t.Fatalf("error leaks the secret: %v", err)
	}
	// The signed request must not carry the secret in a header or the URL.
	for _, r := range fake.Requests() {
		if strings.Contains(r.URL, creds.SecretKey) {
			t.Fatalf("request URL leaks the secret: %s", r.URL)
		}
		for k, v := range r.Headers {
			if strings.Contains(v, creds.SecretKey) {
				t.Fatalf("request header %s leaks the secret", k)
			}
		}
	}
}

// ────────────────────────── shared helpers ──────────────────────────

func TestAWSTagValue(t *testing.T) {
	tags := []ec2types.Tag{{Key: stringPtr("Name"), Value: stringPtr("web")}, {Key: stringPtr("Env"), Value: stringPtr("prod")}}
	if got := tagValue(tags, "Name"); got != "web" {
		t.Errorf("tagValue(Name) = %q", got)
	}
	if got := tagValue(tags, "Missing"); got != "" {
		t.Errorf("tagValue(Missing) = %q, want empty", got)
	}
}

func TestAWSAdminish(t *testing.T) {
	for _, name := range []string{"AdministratorAccess", "arn:aws:iam::aws:policy/AdministratorAccess", "role/admin", "aws:fullaccess", "team:admin"} {
		if !adminish(name) {
			t.Errorf("adminish(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"ReadOnlyAudit", "AmazonS3ReadOnlyAccess", "PowerUserAccess"} {
		if adminish(name) {
			t.Errorf("adminish(%q) = true, want false", name)
		}
	}
}

func TestAWSClampMax(t *testing.T) {
	if got := clampMax(0); got != defaultPageSize {
		t.Errorf("clampMax(0) = %d, want %d", got, defaultPageSize)
	}
	if got := clampMax(-3); got != defaultPageSize {
		t.Errorf("clampMax(-3) = %d, want %d", got, defaultPageSize)
	}
	if got := clampMax(25); got != 25 {
		t.Errorf("clampMax(25) = %d", got)
	}
	if got := clampMax(core.MaxListItems + 1); got != core.MaxListItems {
		t.Errorf("clampMax over the cap = %d, want %d", got, core.MaxListItems)
	}
}

func TestAWSNonEmptyAndTimeString(t *testing.T) {
	if got := nonEmpty("  "); got != nil {
		t.Errorf("nonEmpty(blank) = %v, want nil", got)
	}
	if got := nonEmpty("10.0.0.1"); len(got) != 1 || got[0] != "10.0.0.1" {
		t.Errorf("nonEmpty = %v", got)
	}
	if got := timeString(nil); got != "" {
		t.Errorf("timeString(nil) = %q, want empty", got)
	}
	var zero time.Time
	if got := timeString(&zero); got != "" {
		t.Errorf("timeString(zero) = %q, want empty", got)
	}
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := timeString(&ts); got != "2024-01-02T03:04:05Z" {
		t.Errorf("timeString = %q, want 2024-01-02T03:04:05Z", got)
	}
}

// stringPtr is for building the SDK's pointer-typed tag fields.
func stringPtr(s string) *string { return &s }
