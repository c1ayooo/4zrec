package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/harness"
	tcerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
)

// These tests are fully offline. They drive the provider through a fake
// core.HTTPDoer, so the assertions prove two things at once: the tencentcloud
// SDK signed the request (it had to, to produce the Authorization header) and
// every request went out through the injected port (the fake is the only
// transport).

const stsCallerIdentityJSON = `{"Response":{"AccountId":"1234567890","Arn":"qcs::cam::uin/1234567890:root","UserId":"1234567890","PrincipalId":"1234567890","Type":"Account","RequestId":"req-sts"}}`

const cvmInstancesJSON = `{"Response":{"TotalCount":1,"InstanceSet":[{"InstanceId":"ins-abc123","InstanceName":"web-1","InstanceState":"RUNNING","InstanceType":"S5.MEDIUM4","Placement":{"Zone":"ap-guangzhou-3"},"PrivateIpAddresses":["10.0.0.5"],"PublicIpAddresses":["1.2.3.4"]}],"RequestId":"req-cvm"}}`

const cdbInstancesJSON = `{"Response":{"TotalCount":1,"Items":[{"InstanceId":"cdb-xyz789","InstanceName":"db-1","Status":1,"InstanceType":2,"EngineVersion":"5.7","Zone":"ap-guangzhou-2","Vip":"10.0.0.9"}],"RequestId":"req-cdb"}}`

const cosServiceXML = `<ListAllMyBucketsResult><Owner><ID>1234567890</ID></Owner><Buckets><Bucket><Name>b-1250000000</Name><Location>ap-guangzhou</Location><CreationDate>2023-01-02T03:04:05Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>`

const cosBucketXML = `<ListBucketResult><Name>b-1250000000</Name><Prefix></Prefix><Marker></Marker><NextMarker>next-key</NextMarker><MaxKeys>1000</MaxKeys><IsTruncated>true</IsTruncated><Contents><Key>a.txt</Key><Size>42</Size><LastModified>2023-01-02T03:04:05Z</LastModified></Contents></ListBucketResult>`

const camListUsersJSON = `{"Response":{"Data":[{"Uin":10001,"Name":"alice","CreateTime":"2023-01-01 00:00:00"}],"RequestId":"req-users"}}`

const camListPoliciesJSON = `{"Response":{"TotalNum":1,"List":[{"PolicyId":163,"PolicyName":"QcloudFinanceReadOnlyAccess","Description":"finance","Attachments":2}],"RequestId":"req-policy"}}`

const camListAccessKeysJSON = `{"Response":{"AccessKeys":[{"AccessKeyId":"AKIDexample","Status":"Active","CreateTime":"2023-01-01 00:00:00"}],"RequestId":"req-keys"}}`

const camAttachedPoliciesJSON = `{"Response":{"TotalNum":1,"List":[{"PolicyId":219,"PolicyName":"AdministratorAccess"}],"RequestId":"req-attached"}}`

// newTencentHarnessProvider wires a provider whose only transport is the fake.
func newTencentHarnessProvider(t *testing.T, fake *harness.HTTP) *tencentProvider {
	t.Helper()
	p, ok := newTencentProvider(newHTTPDoerClient(fake, 0)).(*tencentProvider)
	if !ok {
		t.Fatalf("newTencentProvider 返回了非 *tencentProvider")
	}
	return p
}

func requireTC3(t *testing.T, fake *harness.HTTP) {
	t.Helper()
	if fake.Calls() == 0 {
		t.Fatalf("注入的 HTTPDoer 未收到任何请求")
	}
	last, _ := fake.Last()
	auth := last.Headers["Authorization"]
	if !strings.HasPrefix(auth, "TC3-HMAC-SHA256") {
		t.Fatalf("Authorization 头应以 TC3-HMAC-SHA256 开头（说明签名由 SDK 完成并经由注入 Doer 发出），实际为 %q", auth)
	}
}

// ────────────────────────── offline injection tests ──────────────────────────

func TestTencentVerifyViaInjectedDoer(t *testing.T) {
	fake := harness.NewHTTP(200, stsCallerIdentityJSON)
	p := newTencentHarnessProvider(t, fake)

	id, err := p.Verify(context.Background(), Credentials{
		AccessKey: "AKIDxxxxxxxxxxxxxxxx",
		SecretKey: "secretxxxxxxxxxxxxxx",
		Region:    "ap-guangzhou",
	})
	if err != nil {
		t.Fatalf("Verify 返回错误: %v", err)
	}
	if id.AccountID != "1234567890" {
		t.Fatalf("AccountID = %q，期望 1234567890", id.AccountID)
	}
	if id.ARN != "qcs::cam::uin/1234567890:root" {
		t.Fatalf("ARN = %q", id.ARN)
	}
	if id.Type != "root_account" {
		t.Fatalf("Type = %q，期望 root_account", id.Type)
	}
	if id.Alias != "1234567890" {
		t.Fatalf("Alias = %q，期望 1234567890", id.Alias)
	}
	requireTC3(t, fake)
}

func TestTencentListAssetsViaInjectedDoer(t *testing.T) {
	fake := harness.NewHTTP(200, `{"Response":{}}`)
	fake.Routes = []harness.Route{
		{Match: tencentEndpointCVM, Status: 200, Body: cvmInstancesJSON},
		{Match: tencentEndpointCDB, Status: 200, Body: cdbInstancesJSON},
	}
	p := newTencentHarnessProvider(t, fake)

	page, err := p.ListAssets(context.Background(), Credentials{
		AccessKey: "AKIDxxxxxxxxxxxxxxxx",
		SecretKey: "secretxxxxxxxxxxxxxx",
		Region:    "ap-guangzhou",
	}, AssetRequest{
		Kinds:    []string{AssetCompute, AssetDatabase},
		Region:   "ap-guangzhou",
		PageSize: 100,
		Cursor:   "20",
	})
	if err != nil {
		t.Fatalf("ListAssets 返回错误: %v", err)
	}
	if len(page.Warnings) != 0 {
		t.Fatalf("不应有 warning: %v", page.Warnings)
	}

	var gotCompute, gotDatabase *Instance
	for i := range page.Instances {
		switch page.Instances[i].Kind {
		case AssetCompute:
			gotCompute = &page.Instances[i]
		case AssetDatabase:
			gotDatabase = &page.Instances[i]
		}
	}
	if gotCompute == nil {
		t.Fatalf("缺少 compute 实例: %+v", page.Instances)
	}
	if gotCompute.ID != "ins-abc123" || gotCompute.Name != "web-1" || gotCompute.Status != "RUNNING" ||
		gotCompute.Type != "S5.MEDIUM4" || gotCompute.Zone != "ap-guangzhou-3" {
		t.Fatalf("compute 映射错误: %+v", *gotCompute)
	}
	if len(gotCompute.PrivateIP) != 1 || gotCompute.PrivateIP[0] != "10.0.0.5" {
		t.Fatalf("compute 内网 IP 映射错误: %v", gotCompute.PrivateIP)
	}
	if len(gotCompute.PublicIP) != 1 || gotCompute.PublicIP[0] != "1.2.3.4" {
		t.Fatalf("compute 公网 IP 映射错误: %v", gotCompute.PublicIP)
	}

	if gotDatabase == nil {
		t.Fatalf("缺少 database 实例: %+v", page.Instances)
	}
	if gotDatabase.ID != "cdb-xyz789" || gotDatabase.Name != "db-1" || gotDatabase.Status != "1" ||
		gotDatabase.Type != "2" || gotDatabase.Engine != "5.7" || gotDatabase.Zone != "ap-guangzhou-2" {
		t.Fatalf("database 映射错误: %+v", *gotDatabase)
	}
	if len(gotDatabase.PrivateIP) != 1 || gotDatabase.PrivateIP[0] != "10.0.0.9" {
		t.Fatalf("database Vip 映射错误: %v", gotDatabase.PrivateIP)
	}

	if fake.Calls() != 2 {
		t.Fatalf("期望 2 次请求（CVM+CDB），实际 %d", fake.Calls())
	}
	for _, req := range fake.Requests() {
		if !strings.HasPrefix(req.Headers["Authorization"], "TC3-HMAC-SHA256") {
			t.Fatalf("请求 %s 缺少 TC3 签名头: %q", req.URL, req.Headers["Authorization"])
		}
	}

	// Cursor "20" must be parsed into the CVM/CDB Offset.
	var offsetSeen bool
	for _, req := range fake.Requests() {
		if !strings.Contains(req.URL, tencentEndpointCVM) {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(req.Body, &body); err != nil {
			t.Fatalf("CVM 请求体不是 JSON: %v (%s)", err, req.Body)
		}
		if off, ok := body["Offset"].(float64); ok && off == 20 {
			offsetSeen = true
		}
	}
	if !offsetSeen {
		t.Fatalf("cursor \"20\" 未解析为 Offset=20")
	}
}

func TestTencentListStorageBucketsViaInjectedDoer(t *testing.T) {
	fake := harness.NewHTTP(200, cosServiceXML)
	p := newTencentHarnessProvider(t, fake)

	page, err := p.ListStorage(context.Background(), Credentials{
		AccessKey: "AKIDxxxxxxxxxxxxxxxx",
		SecretKey: "secretxxxxxxxxxxxxxx",
		Region:    "ap-guangzhou",
	}, StorageRequest{MaxResults: 100})
	if err != nil {
		t.Fatalf("ListStorage 返回错误: %v", err)
	}
	if len(page.Buckets) != 1 {
		t.Fatalf("期望 1 个桶，实际 %d", len(page.Buckets))
	}
	b := page.Buckets[0]
	if b.Name != "b-1250000000" || b.Region != "ap-guangzhou" || b.CreatedAt != "2023-01-02T03:04:05Z" {
		t.Fatalf("桶映射错误: %+v", b)
	}
	if fake.Calls() == 0 {
		t.Fatalf("注入的 HTTPDoer 未收到请求")
	}
	last, _ := fake.Last()
	auth := last.Headers["Authorization"]
	// COS uses its own q-sign-algorithm scheme; the header proves the COS SDK
	// signed and the request travelled through the injected doer.
	if !strings.HasPrefix(auth, "q-sign-algorithm=") {
		t.Fatalf("COS Authorization 头应带 q-sign-algorithm，实际 %q", auth)
	}
	if !strings.Contains(last.URL, "cos.ap-guangzhou.myqcloud.com") {
		t.Fatalf("COS 服务请求 URL 非预期: %s", last.URL)
	}
}

func TestTencentListStorageObjectsViaInjectedDoer(t *testing.T) {
	fake := harness.NewHTTP(200, cosBucketXML)
	p := newTencentHarnessProvider(t, fake)

	page, err := p.ListStorage(context.Background(), Credentials{
		AccessKey: "AKIDxxxxxxxxxxxxxxxx",
		SecretKey: "secretxxxxxxxxxxxxxx",
		Region:    "ap-guangzhou",
	}, StorageRequest{Bucket: "b-1250000000", Prefix: "a/", MaxResults: 100})
	if err != nil {
		t.Fatalf("ListStorage 返回错误: %v", err)
	}
	if len(page.Objects) != 1 {
		t.Fatalf("期望 1 个对象，实际 %d", len(page.Objects))
	}
	o := page.Objects[0]
	if o.Key != "a.txt" || o.Size != 42 || o.LastModified != "2023-01-02T03:04:05Z" {
		t.Fatalf("对象映射错误: %+v", o)
	}
	if page.Cursor != "next-key" || !page.HasMore {
		t.Fatalf("分页映射错误: cursor=%q hasMore=%v", page.Cursor, page.HasMore)
	}
	last, _ := fake.Last()
	if !strings.Contains(last.URL, "b-1250000000.cos.ap-guangzhou.myqcloud.com") {
		t.Fatalf("COS 桶请求 URL 非预期: %s", last.URL)
	}
	if !strings.Contains(last.URL, "prefix=") {
		t.Fatalf("COS 列表请求未带 prefix: %s", last.URL)
	}
}

// ────────────────────────── action-routed tests ──────────────────────────

// actionDoer answers by X-TC-Action so one fake can script a multi-call flow
// (CAM's four endpoints, TAT's RunCommand + DescribeInvocationTasks).
type actionDoer struct {
	mu      sync.Mutex
	bodies  map[string]string
	replies []core.Request
}

func (d *actionDoer) Do(_ context.Context, req core.Request) (*core.Response, error) {
	d.mu.Lock()
	d.replies = append(d.replies, req)
	d.mu.Unlock()
	body, ok := d.bodies[headerValue(req, "X-TC-Action")]
	if !ok {
		body = `{"Response":{}}`
	}
	return &core.Response{Status: 200, Body: []byte(body), FinalURL: req.URL}, nil
}

// headerValue reads a header case-insensitively: net/http canonicalizes
// "X-TC-Action" to "X-Tc-Action", so an exact-key lookup would miss it.
func headerValue(req core.Request, name string) string {
	for k, v := range req.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func (d *actionDoer) calls() []core.Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]core.Request(nil), d.replies...)
}

func TestTencentListIAMViaInjectedDoer(t *testing.T) {
	doer := &actionDoer{bodies: map[string]string{
		"ListUsers":                camListUsersJSON,
		"ListPolicies":             camListPoliciesJSON,
		"ListAccessKeys":           camListAccessKeysJSON,
		"ListAttachedUserPolicies": camAttachedPoliciesJSON,
	}}
	p, _ := newTencentProvider(newHTTPDoerClient(doer, 0)).(*tencentProvider)

	page, err := p.ListIAM(context.Background(), Credentials{
		AccessKey: "AKIDxxxxxxxxxxxxxxxx",
		SecretKey: "secretxxxxxxxxxxxxxx",
	}, IAMRequest{Include: []string{"users", "policies", "access_keys"}, MaxResults: 100})
	if err != nil {
		t.Fatalf("ListIAM 返回错误: %v", err)
	}
	if len(page.Users) != 1 || page.Users[0].Name != "alice" || page.Users[0].ID != "10001" {
		t.Fatalf("users 映射错误: %+v", page.Users)
	}
	if page.Users[0].AdminHint != "AdministratorAccess" {
		t.Fatalf("AdminHint = %q，期望 AdministratorAccess", page.Users[0].AdminHint)
	}
	if len(page.Policies) != 1 || page.Policies[0].Name != "QcloudFinanceReadOnlyAccess" || page.Policies[0].Admin {
		t.Fatalf("policies 映射错误: %+v", page.Policies)
	}
	if len(page.AccessKeys) != 1 || page.AccessKeys[0].ID != "AKIDexample" || page.AccessKeys[0].Status != "Active" {
		t.Fatalf("access_keys 映射错误: %+v", page.AccessKeys)
	}

	// Every CAM call must be signed and travel through the injected doer.
	actions := map[string]bool{}
	for _, req := range doer.calls() {
		if !strings.HasPrefix(req.Headers["Authorization"], "TC3-HMAC-SHA256") {
			t.Fatalf("CAM 请求缺少 TC3 签名头: %q", req.Headers["Authorization"])
		}
		actions[headerValue(req, "X-TC-Action")] = true
	}
	for _, want := range []string{"ListUsers", "ListPolicies", "ListAccessKeys", "ListAttachedUserPolicies"} {
		if !actions[want] {
			t.Fatalf("未观察到 CAM action %s（实际 %v）", want, actions)
		}
	}
}

func TestTencentRunCommandViaInjectedDoer(t *testing.T) {
	output := base64.StdEncoding.EncodeToString([]byte("hello world\n"))
	doer := &actionDoer{bodies: map[string]string{
		"RunCommand":              `{"Response":{"InvocationId":"inv-1","CommandId":"cmd-1","RequestId":"req-run"}}`,
		"DescribeInvocationTasks": `{"Response":{"TotalCount":1,"InvocationTaskSet":[{"InstanceId":"ins-abc123","TaskStatus":"SUCCESS","TaskResult":{"ExitCode":0,"Output":"` + output + `"}}],"RequestId":"req-tasks"}}`,
	}}
	p, _ := newTencentProvider(newHTTPDoerClient(doer, 0)).(*tencentProvider)

	res, err := p.RunCommand(context.Background(), Credentials{
		AccessKey: "AKIDxxxxxxxxxxxxxxxx",
		SecretKey: "secretxxxxxxxxxxxxxx",
	}, CommandRequest{InstanceID: "ins-abc123", Command: "echo hello world", TimeoutSec: 30})
	if err != nil {
		t.Fatalf("RunCommand 返回错误: %v", err)
	}
	if res.CommandID != "cmd-1" {
		t.Fatalf("CommandID = %q", res.CommandID)
	}
	if res.Status != "success" {
		t.Fatalf("Status = %q，期望 success（原样小写）", res.Status)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d", res.ExitCode)
	}
	if res.Stdout != "hello world\n" {
		t.Fatalf("Stdout = %q，期望 base64 解码后的命令输出", res.Stdout)
	}

	var sawRunCommand bool
	for _, req := range doer.calls() {
		if headerValue(req, "X-TC-Action") != "RunCommand" {
			continue
		}
		sawRunCommand = true
		if !strings.Contains(req.URL, tencentEndpointTAT) {
			t.Fatalf("RunCommand 未指向 TAT endpoint: %s", req.URL)
		}
		var params map[string]any
		if err := json.Unmarshal(req.Body, &params); err != nil {
			t.Fatalf("RunCommand 请求体不是 JSON: %v (%s)", err, req.Body)
		}
		if ct, _ := params["CommandType"].(string); ct != "SHELL" {
			t.Fatalf("CommandType = %v，期望 SHELL", params["CommandType"])
		}
		if _, ok := params["Content"]; !ok {
			t.Fatalf("RunCommand 请求缺少 Content: %s", req.Body)
		}
		if !strings.HasPrefix(req.Headers["Authorization"], "TC3-HMAC-SHA256") {
			t.Fatalf("RunCommand 请求缺少 TC3 签名头")
		}
	}
	if !sawRunCommand {
		t.Fatalf("未观察到 RunCommand 请求")
	}
}

// ────────────────────────── error classification table ──────────────────────────

func TestClassifyTencentReasons(t *testing.T) {
	cases := map[string]Reason{
		"AuthFailure.SignatureFailure":              ReasonInvalidCredential,
		"AuthFailure.SecretIdNotFound":              ReasonInvalidCredential,
		"AuthFailure.InvalidSecretId":               ReasonInvalidCredential,
		"AuthFailure.TokenFailure":                  ReasonInvalidCredential,
		"AuthFailure.MFAFailure":                    ReasonInvalidCredential,
		"InvalidCredential":                         ReasonInvalidCredential,
		"UnauthorizedOperation":                     ReasonPermissionDenied,
		"UnauthorizedOperation.PermissionDenied":    ReasonPermissionDenied,
		"AccessDenied":                              ReasonPermissionDenied,
		"AuthFailure.UnauthorizedOperation":         ReasonPermissionDenied,
		"InvalidRegion":                             ReasonRegionInvalid,
		"InvalidRegion.NotFound":                    ReasonRegionInvalid,
		"InvalidParameterValue.Region":              ReasonRegionInvalid,
		"InvalidInstanceState":                      ReasonInstanceNotRunning,
		"UnsupportedOperation.InstanceNotRunning":   ReasonInstanceNotRunning,
		"OperationDenied.InstanceStatus":            ReasonInstanceNotRunning,
		"InvalidInstanceId.NotFound":                ReasonNotFound,
		"ResourceNotFound":                          ReasonNotFound,
		"NoSuchBucket":                              ReasonNotFound,
		"InvalidParameterValue.InstanceIdMalformed": ReasonNotFound,
		"RequestLimitExceeded":                      ReasonThrottled,
		"LimitExceeded":                             ReasonThrottled,
		"FailedOperation.TooManyRequests":           ReasonThrottled,
		"RequestTimeout":                            ReasonTimeout,
		"InternalError.Timeout":                     ReasonTimeout,
		"ClientNetworkError":                        ReasonTimeout,
	}
	for code, want := range cases {
		err := tcerr.NewTencentCloudSDKError(code, "boom", "req-1")
		got := classifyTencent(err)
		var ce *Error
		if !errors.As(got, &ce) {
			t.Fatalf("%s: classifyTencent 未返回 *Error，得到 %T (%v)", code, got, got)
		}
		if ce.Reason != want {
			t.Fatalf("%s: Reason = %s，期望 %s", code, ce.Reason, want)
		}
		if ce.Provider != ProviderTencent {
			t.Fatalf("%s: Provider = %q", code, ce.Provider)
		}
		if ce.Code != code {
			t.Fatalf("%s: Code = %q，期望原始 code", code, ce.Code)
		}
	}
}

func TestClassifyTencentUnknownCodeFallsBack(t *testing.T) {
	err := tcerr.NewTencentCloudSDKError("Some.New.Code", "operation is throttled, retry later", "req-1")
	got := classifyTencent(err)
	var ce *Error
	if !errors.As(got, &ce) {
		t.Fatalf("未返回 *Error: %T", got)
	}
	if ce.Reason != ReasonThrottled {
		t.Fatalf("fallback Reason = %s，期望 throttled", ce.Reason)
	}
}

func TestClassifyTencentPassesCapkitErrorThrough(t *testing.T) {
	blocked := core.ScopeDenied("out of scope")
	got := classifyTencent(blocked)
	if got != error(blocked) {
		t.Fatalf("宿主门禁错误被覆盖：得到 %#v，期望原样返回 %#v", got, blocked)
	}
	if classifyTencent(nil) != nil {
		t.Fatalf("nil 应返回 nil")
	}
}

// ────────────────────────── boundaries ──────────────────────────

func TestTencentListAssetsUnknownKindWarns(t *testing.T) {
	fake := harness.NewHTTP(200, `{"Response":{}}`)
	fake.Routes = []harness.Route{{Match: tencentEndpointCVM, Status: 200, Body: cvmInstancesJSON}}
	p := newTencentHarnessProvider(t, fake)

	page, err := p.ListAssets(context.Background(), Credentials{
		AccessKey: "AKIDxxxxxxxxxxxxxxxx",
		SecretKey: "secretxxxxxxxxxxxxxx",
		Region:    "ap-guangzhou",
	}, AssetRequest{Kinds: []string{AssetCompute, "network"}, Region: "ap-guangzhou"})
	if err != nil {
		t.Fatalf("部分失败不应整体报错: %v", err)
	}
	if len(page.Instances) != 1 {
		t.Fatalf("compute 应照常返回，实际 %d 个实例", len(page.Instances))
	}
	found := false
	for _, w := range page.Warnings {
		if strings.Contains(w, "network") {
			found = true
		}
	}
	if !found {
		t.Fatalf("未知 kind 应出现在 Warnings 中: %v", page.Warnings)
	}
}

func TestTencentListAssetsAllFailReturnsError(t *testing.T) {
	fake := harness.NewHTTP(200, `{"Response":{}}`)
	fake.Err = tcerr.NewTencentCloudSDKError("AuthFailure.SignatureFailure", "bad signature", "req-1")
	p := newTencentHarnessProvider(t, fake)

	_, err := p.ListAssets(context.Background(), Credentials{
		AccessKey: "AKIDxxxxxxxxxxxxxxxx",
		SecretKey: "secretxxxxxxxxxxxxxx",
		Region:    "ap-guangzhou",
	}, AssetRequest{Kinds: []string{AssetCompute}, Region: "ap-guangzhou"})
	if err == nil {
		t.Fatalf("全部失败应返回错误")
	}
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("期望 *Error，得到 %T", err)
	}
	// The aggregate error (mirroring aws.go) is upstream_error, but the warning
	// it carries must preserve the classified reason for the underlying failure.
	if ce.Reason != ReasonUpstream {
		t.Fatalf("Reason = %s，期望 upstream_error", ce.Reason)
	}
	if !strings.Contains(ce.Message, ReasonInvalidCredential.Label()) {
		t.Fatalf("聚合错误未携带底层分类（凭据无效）: %q", ce.Message)
	}
}

func TestTencentNilDoerIsUnavailable(t *testing.T) {
	p, _ := newTencentProvider(newHTTPDoerClient(nil, 0)).(*tencentProvider)
	if _, err := p.Verify(context.Background(), Credentials{AccessKey: "a", SecretKey: "b"}); err == nil {
		t.Fatalf("nil doer 应返回 unavailable")
	} else {
		var ce *core.Error
		if !errors.As(err, &ce) || ce.Code != core.CodeUnavailable {
			t.Fatalf("期望 unavailable，得到 %#v", err)
		}
	}
	if _, err := p.ListStorage(context.Background(), Credentials{AccessKey: "a", SecretKey: "b"}, StorageRequest{}); err == nil {
		t.Fatalf("nil doer 应返回 unavailable")
	} else {
		var ce *core.Error
		if !errors.As(err, &ce) || ce.Code != core.CodeUnavailable {
			t.Fatalf("ListStorage 期望 unavailable，得到 %#v", err)
		}
	}
}

func TestTencentIdentityType(t *testing.T) {
	cases := []struct {
		arn    string
		userID string
		want   string
	}{
		{"qcs::cam::uin/1234567890:root", "1234567890", "root_account"},
		{"qcs::cam::uin/1234567890:uinfo/10001", "10001", "sub_account"},
		{"qcs::cam::uin/1234567890:role/ops", "roleId:session", "assumed_role"},
	}
	for _, c := range cases {
		if got := tencentIdentityType(c.arn, c.userID); got != c.want {
			t.Fatalf("tencentIdentityType(%q,%q) = %q，期望 %q", c.arn, c.userID, got, c.want)
		}
	}
}
