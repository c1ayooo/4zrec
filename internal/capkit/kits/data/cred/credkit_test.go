package cred

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// stubFetcher routes requests to an httptest upstream, preserving method,
// headers and body so signature math can be asserted.
type stubFetcher struct{ srv *httptest.Server }

func (f stubFetcher) Fetch(ctx context.Context, req core.Request) (*core.Response, error) {
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &core.Response{Status: resp.StatusCode, Headers: resp.Header, Body: data}, nil
}

// newTestKit stands up an httptest upstream and points one provider at it.
func newTestKit(t *testing.T, provider string, handler http.Handler) *Kit {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(stubFetcher{srv: srv}).withEndpoint(provider, srv.URL)
}

// withEndpoint is a test-only fluent setter.
func (k *Kit) withEndpoint(provider, url string) *Kit {
	if k.Endpoints == nil {
		k.Endpoints = map[string]string{}
	}
	k.Endpoints[provider] = url
	return k
}

// TestAliyunValidSignature 阿里云路径:成功体平铺 Code 为空 → valid + account。
// 断言 ACS3 签名头与 x-acs-* 头齐全(签名断了就是假有效)。
func TestAliyunValidSignature(t *testing.T) {
	var gotAuth, gotAction, gotVersion, gotDate, gotNonce string
	k := newTestKit(t, ProviderAliyun, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAction = r.Header.Get("x-acs-action")
		gotVersion = r.Header.Get("x-acs-version")
		gotDate = r.Header.Get("x-acs-date")
		gotNonce = r.Header.Get("x-acs-signature-nonce")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"AccountId":"1234567890","Arn":"acs:ram::1234567890:role/test"}`)
	}))

	res, err := k.Verify(context.Background(), ProviderAliyun, "LTAI-test", "secret")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid || res.Status != StatusValid {
		t.Fatalf("expected valid, got %+v", res)
	}
	if res.AccountID != "1234567890" || res.Arn == "" {
		t.Errorf("account/arn not parsed: %+v", res)
	}
	if !strings.HasPrefix(gotAuth, "ACS3-HMAC-SHA256 Credential=LTAI-test") {
		t.Errorf("ACS3 Authorization header malformed: %q", gotAuth)
	}
	if gotAction != "GetCallerIdentity" || gotVersion != "2015-04-01" || gotDate == "" || gotNonce == "" {
		t.Errorf("x-acs-* headers incomplete: action=%q version=%q date=%q nonce=%q",
			gotAction, gotVersion, gotDate, gotNonce)
	}
}

// TestAliyunRejectedKey 厂商明确拒绝 → invalid(不是 unverifiable)。
func TestAliyunRejectedKey(t *testing.T) {
	k := newTestKit(t, ProviderAliyun, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Code":"InvalidAccessKeyId.NotFound","Message":"not found"}`)
	}))

	res, err := k.Verify(context.Background(), ProviderAliyun, "LTAI-bad", "secret")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid || res.Status != StatusInvalid {
		t.Fatalf("expected invalid, got %+v", res)
	}
	if res.Code != "InvalidAccessKeyId.NotFound" {
		t.Errorf("vendor code not surfaced: %+v", res)
	}
}

// TestAliyunPolicyBlockedIsRestricted 身份通过但策略拒绝 → restricted。
// 这是与 invalid 的关键区分:密钥真实存在。
func TestAliyunPolicyBlockedIsRestricted(t *testing.T) {
	k := newTestKit(t, ProviderAliyun, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Code":"AccessDenied","Message":"denied"}`)
	}))

	res, err := k.Verify(context.Background(), ProviderAliyun, "LTAI-real", "secret")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid || res.Status != StatusRestricted {
		t.Fatalf("expected restricted, got %+v", res)
	}
}

// TestAWSValidXML AWS 路径:XML 成功体 → valid + account/arn。
func TestAWSValidXML(t *testing.T) {
	k := newTestKit(t, ProviderAWS, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<GetCallerIdentityResponse><GetCallerIdentityResult>`+
			`<Arn>arn:aws:iam::1234:user/test</Arn><Account>1234</Account><UserId>AIDATEST</UserId>`+
			`</GetCallerIdentityResult></GetCallerIdentityResponse>`)
	}))

	res, err := k.Verify(context.Background(), ProviderAWS, "AKIA-test", "secret")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid || res.AccountID != "1234" || res.Arn == "" {
		t.Fatalf("expected valid aws identity, got %+v", res)
	}
}

// TestAWSRejectedKey AWS 403 错误码 → invalid。
func TestAWSRejectedKey(t *testing.T) {
	k := newTestKit(t, ProviderAWS, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<ErrorResponse><Error><Code>InvalidClientTokenId</Code>`+
			`<Message>The security token included in the request is invalid.</Message></Error></ErrorResponse>`)
	}))

	res, err := k.Verify(context.Background(), ProviderAWS, "AKIA-bad", "secret")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid || res.Status != StatusInvalid {
		t.Fatalf("expected invalid, got %+v", res)
	}
}

// TestTencentValid TC3 路径:Response.Error 为 nil → valid。
func TestTencentValid(t *testing.T) {
	var gotAuth string
	k := newTestKit(t, ProviderTencent, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Response":{"AccountId":"5566","Arn":"qcs::sts::5566:uin/5566:role/test"}}`)
	}))

	res, err := k.Verify(context.Background(), ProviderTencent, "AKID-test", "secret")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid || res.AccountID != "5566" {
		t.Fatalf("expected valid, got %+v", res)
	}
	if !strings.HasPrefix(gotAuth, "TC3-HMAC-SHA256 Credential=AKID-test") {
		t.Errorf("TC3 Authorization header malformed: %q", gotAuth)
	}
}

// TestHuaweiForbiddenIsRestricted 华为 403 → restricted(签名通过、策略拒绝)。
func TestHuaweiForbiddenIsRestricted(t *testing.T) {
	k := newTestKit(t, ProviderHuawei, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error_code":"IAM.0033","error_msg":"no permission"}`)
	}))

	res, err := k.Verify(context.Background(), ProviderHuawei, "ak", "sk")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid || res.Status != StatusRestricted {
		t.Fatalf("expected restricted, got %+v", res)
	}
}

// TestHuaweiUnauthorizedIsInvalid 华为 401 → invalid(签名校验直接失败)。
func TestHuaweiUnauthorizedIsInvalid(t *testing.T) {
	k := newTestKit(t, ProviderHuawei, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error_code":"APIGW.0301","error_msg":"signature invalid"}`)
	}))

	res, err := k.Verify(context.Background(), ProviderHuawei, "ak", "sk")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid || res.Status != StatusInvalid {
		t.Fatalf("expected invalid, got %+v", res)
	}
}

// TestVolcValid 火山路径:ResponseMetadata.Error 为 nil → valid。
func TestVolcValid(t *testing.T) {
	k := newTestKit(t, ProviderVolc, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ResponseMetadata":{},"Result":{"Details":[{"UserName":"a"},{"UserName":"b"}]}}`)
	}))

	res, err := k.Verify(context.Background(), ProviderVolc, "AK-test", "secret")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid || res.Status != StatusValid {
		t.Fatalf("expected valid, got %+v", res)
	}
}

// TestUnknownProvider 未支持厂商 → 显式错误,不静默走默认端点。
func TestUnknownProvider(t *testing.T) {
	k := New(stubFetcher{})
	if _, err := k.Verify(context.Background(), "gcp", "ak", "sk"); err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}

// TestNilFetcher 没注入 Fetcher → 显式错误(不静默发请求)。
func TestNilFetcher(t *testing.T) {
	k := New(nil)
	if _, err := k.Verify(context.Background(), ProviderAWS, "ak", "sk"); err == nil {
		t.Fatal("expected error when fetcher is nil")
	}
}

// TestCapabilityCallCloud Kit.Call 路由:cloud 工具走通。
func TestCapabilityCallCloud(t *testing.T) {
	k := newTestKit(t, ProviderAliyun, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"AccountId":"acc-1","Arn":"arn:test"}`)
	}))

	input, _ := json.Marshal(map[string]string{
		"provider": ProviderAliyun, "access_key": "ak", "secret_key": "sk",
	})
	res, err := k.Call(context.Background(), core.Call{Tool: "credential_verify_cloud", Input: input})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected ok result, got %+v", res.Error)
	}
	var out VerifyResult
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !out.Valid || out.AccountID != "acc-1" {
		t.Errorf("unexpected result: %+v", out)
	}
}

// TestCapabilityUnknownTool 未知工具名 → fail result。
func TestCapabilityUnknownTool(t *testing.T) {
	k := New(stubFetcher{})
	res, err := k.Call(context.Background(), core.Call{Tool: "nope", Input: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.OK {
		t.Fatal("expected failure for unknown tool")
	}
}

// TestExtractTargetsDBSSH db/ssh 工具声明的 target 提取:host:port 归一化。
func TestExtractTargetsDBSSH(t *testing.T) {
	m := New(stubFetcher{}).Manifest()
	for _, tool := range m.Tools {
		if tool.Name != "credential_verify_db" && tool.Name != "credential_verify_ssh" {
			continue
		}
		if tool.ExtractTargets == nil {
			t.Fatalf("%s must declare ExtractTargets (scope gate needs it)", tool.Name)
		}
		targets, err := tool.ExtractTargets(json.RawMessage(`{"host":"10.0.0.5","port":5432}`))
		if err != nil {
			t.Fatalf("%s ExtractTargets: %v", tool.Name, err)
		}
		if len(targets) != 1 || targets[0].Host != "10.0.0.5" || targets[0].Port != 5432 {
			t.Errorf("%s targets not normalized: %+v", tool.Name, targets)
		}
	}
}

// TestManifestDeclaresCloudReadOnly cloud 工具不产目标(外部 STS 端点,非项目资产)。
func TestManifestDeclaresCloudReadOnly(t *testing.T) {
	m := New(stubFetcher{}).Manifest()
	for _, tool := range m.Tools {
		if tool.Name == "credential_verify_cloud" {
			if tool.ExtractTargets == nil {
				t.Fatal("cloud tool must declare (empty) ExtractTargets")
			}
			targets, err := tool.ExtractTargets(json.RawMessage(`{"provider":"aws"}`))
			if err != nil || len(targets) != 0 {
				t.Errorf("cloud tool should extract no targets, got %+v (%v)", targets, err)
			}
		}
	}
}

// TestLooksLikePlaceholder 占位符防线:文档示例值不得入池。
func TestLooksLikePlaceholder(t *testing.T) {
	for _, bad := range []string{"", "YOUR_ACCESS_KEY", "AKIAEXAMPLE", "changeme", "xxxx", "<redacted>"} {
		if !LooksLikePlaceholder(bad) {
			t.Errorf("%q should be flagged as placeholder", bad)
		}
	}
	for _, ok := range []string{"LTAI5tQx", "AKIA3J7XQZP2LMNPQRST", "a1b2c3d4e5f6g7h8"} {
		if LooksLikePlaceholder(ok) {
			t.Errorf("%q should not be flagged", ok)
		}
	}
}

// TestMaskKey 脱敏回显不泄露完整密钥。
func TestMaskKey(t *testing.T) {
	got := MaskKey("LTAI5tQxAbCdEfGhIjKlMn")
	if len(got) > 12 || strings.Contains(got, "AbCdEf") {
		t.Errorf("mask leaked key material: %q", got)
	}
	if MaskKey("short") != "****" {
		t.Error("short key should be fully masked")
	}
}

// TestValidProvider 厂商枚举。
func TestValidProvider(t *testing.T) {
	for _, p := range Providers {
		if !ValidProvider(p) {
			t.Errorf("%q should be valid", p)
		}
	}
	if ValidProvider("gcp") {
		t.Error("gcp is not a supported provider")
	}
}

// TestDefaultDBPort 默认端口映射。
func TestDefaultDBPort(t *testing.T) {
	cases := map[string]int{
		"postgres": 5432, "PostgreSQL": 5432, "redis": 6379, "mysql": 3306, "unknown": 0,
	}
	for typ, want := range cases {
		if got := DefaultDBPort(typ); got != want {
			t.Errorf("DefaultDBPort(%q)=%d, want %d", typ, got, want)
		}
	}
}

// TestVerifyDBUnsupported 不支持的数据库类型 → 显式错误而非假成功。
func TestVerifyDBUnsupported(t *testing.T) {
	_, err := VerifyDB(context.Background(), DBProbeInput{Type: "mysql", Host: "127.0.0.1"})
	if err == nil {
		t.Fatal("expected explicit error for unsupported db type")
	}
}

// TestVerifySSHMissingInput SSH 缺 host/username → 参数错误。
func TestVerifySSHMissingInput(t *testing.T) {
	if _, err := VerifySSH(context.Background(), SSHProbeInput{Host: ""}); err == nil {
		t.Fatal("expected error for empty host")
	}
}

// TestCallCloudSummary: valid path names the provider and the masked AK, and
// the raw key never appears in the Summary.
func TestCallCloudSummary(t *testing.T) {
	k := newTestKit(t, ProviderAliyun, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"AccountId":"acc-1","Arn":"arn:test"}`)
	}))
	input, _ := json.Marshal(map[string]string{
		"provider": ProviderAliyun, "access_key": "LTAI5tQxAbCdEfGhIjKlMn", "secret_key": "sk",
	})
	res, err := k.Call(context.Background(), core.Call{Tool: "credential_verify_cloud", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess || !res.OK {
		t.Fatalf("status = %s", res.Status)
	}
	if res.Meta.Tool != "credential_verify_cloud" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
	want := "验证 aliyun AK LTAI…KlMn 有效，账号 acc-1"
	if res.Summary != want {
		t.Fatalf("summary = %q, want %q", res.Summary, want)
	}
	if strings.Contains(res.Summary, "AbCdEf") {
		t.Fatalf("summary leaked key material: %q", res.Summary)
	}
}

// TestCallCloudInvalidSummary: a rejected key reports "无效：<code>" with the
// masked AK, never the raw one.
func TestCallCloudInvalidSummary(t *testing.T) {
	k := newTestKit(t, ProviderAliyun, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Code":"InvalidAccessKeyId.NotFound","Message":"not found"}`)
	}))
	input, _ := json.Marshal(map[string]string{
		"provider": ProviderAliyun, "access_key": "LTAIbadkey12345678", "secret_key": "sk",
	})
	res, err := k.Call(context.Background(), core.Call{Tool: "credential_verify_cloud", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "无效") || !strings.Contains(res.Summary, "InvalidAccessKeyId.NotFound") {
		t.Fatalf("summary = %q", res.Summary)
	}
	if res.Meta.Tool != "credential_verify_cloud" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
}

// TestCallDBConnectionFailureSummary: dialing a closed localhost port is an
// offline failure branch; the target and reason must both be in the Summary.
func TestCallDBConnectionFailureSummary(t *testing.T) {
	k := New(stubFetcher{})
	input, _ := json.Marshal(map[string]any{"type": "redis", "host": "127.0.0.1", "port": 1})
	res, err := k.Call(context.Background(), core.Call{Tool: "credential_verify_db", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "127.0.0.1:1") || !strings.Contains(res.Summary, "连接失败") {
		t.Fatalf("summary = %q", res.Summary)
	}
	if res.Meta.Tool != "credential_verify_db" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
}

// TestCallSSHConnectionFailureSummary: closed localhost port, offline.
func TestCallSSHConnectionFailureSummary(t *testing.T) {
	k := New(stubFetcher{})
	input, _ := json.Marshal(map[string]any{
		"host": "127.0.0.1", "port": 1, "username": "root", "password": "pw",
	})
	res, err := k.Call(context.Background(), core.Call{Tool: "credential_verify_ssh", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "root@127.0.0.1:1") || !strings.Contains(res.Summary, "连接失败") {
		t.Fatalf("summary = %q", res.Summary)
	}
	if res.Meta.Tool != "credential_verify_ssh" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
}

// TestCallSSHMissingAuthEnvelope: a failure path still carries a Summary naming
// the reason and a Meta.Tool.
func TestCallSSHMissingAuthEnvelope(t *testing.T) {
	k := New(stubFetcher{})
	input, _ := json.Marshal(map[string]any{"host": "127.0.0.1", "username": "root"})
	res, err := k.Call(context.Background(), core.Call{Tool: "credential_verify_ssh", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusFailed || res.Error == nil {
		t.Fatalf("res = %+v", res)
	}
	if !strings.Contains(res.Summary, "password") || res.Meta.Tool != "credential_verify_ssh" {
		t.Fatalf("envelope = %+v", res)
	}
}

// TestCallDBUnsupportedEnvelope: an unsupported engine fails with a real reason.
func TestCallDBUnsupportedEnvelope(t *testing.T) {
	k := New(stubFetcher{})
	input, _ := json.Marshal(map[string]any{"type": "mysql", "host": "127.0.0.1"})
	res, err := k.Call(context.Background(), core.Call{Tool: "credential_verify_db", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusFailed || res.Error == nil {
		t.Fatalf("res = %+v", res)
	}
	if !strings.Contains(res.Summary, "暂未支持") || res.Meta.Tool != "credential_verify_db" {
		t.Fatalf("envelope = %+v", res)
	}
}

// TestCallCloudUnsupportedProvider: unsupported provider fails with the reason.
func TestCallCloudUnsupportedProvider(t *testing.T) {
	k := New(stubFetcher{})
	input, _ := json.Marshal(map[string]string{"provider": "gcp", "access_key": "ak", "secret_key": "sk"})
	res, err := k.Call(context.Background(), core.Call{Tool: "credential_verify_cloud", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusFailed || res.Error == nil {
		t.Fatalf("res = %+v", res)
	}
	if !strings.Contains(res.Summary, "不支持的云厂商") || res.Meta.Tool != "credential_verify_cloud" {
		t.Fatalf("envelope = %+v", res)
	}
}
