// Package credkit holds the credential-use primitives for authorized security
// testing: verifying that a discovered credential actually works. It is the
// "use the credential" layer, not the "find the vulnerability" layer.
//
// Three probes:
//   - cloud AK/SK minimal-read verification (ali/tencent/aws/huawei/volc STS)
//   - database live-auth verification (postgres/redis, raw protocols)
//   - SSH live-auth verification (x/crypto/ssh, read-only id + sudo -n probe)
//
// All probes are read-only: they authenticate and read identity/permission
// surface, never performing any write or privileged mutation. A host wires the
// cloud probe with a Fetcher so scope/rate/audit policy still applies; db/ssh
// probes are direct TCP/SSH and rely on the host's target authorization gate.
package cred

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Cloud providers supported by AK/SK verification.
const (
	ProviderAliyun  = "aliyun"
	ProviderTencent = "tencent"
	ProviderAWS     = "aws"
	ProviderHuawei  = "huawei"
	ProviderVolc    = "volc"
)

// Verification status semantics (four tiers, aligned with miniapp/llm verifiers).
const (
	StatusValid        = "valid"
	StatusInvalid      = "invalid"      // key explicitly rejected by vendor
	StatusRestricted   = "restricted"   // key exists but policy-blocked (key is real)
	StatusUnverifiable = "unverifiable" // network/service reason, no conclusion
)

// Providers is shared by frontends and backends.
var Providers = []string{ProviderAliyun, ProviderTencent, ProviderAWS, ProviderHuawei, ProviderVolc}

func ValidProvider(p string) bool {
	for _, v := range Providers {
		if v == p {
			return true
		}
	}
	return false
}

// VerifyResult is the conclusion of one STS verification.
type VerifyResult struct {
	Valid     bool   `json:"valid"`
	Status    string `json:"status"`
	AccountID string `json:"account_id,omitempty"`
	Arn       string `json:"arn,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
}

// CloudEndpoints returns the default vendor STS/IAM endpoints.
func CloudEndpoints() map[string]string {
	return map[string]string{
		ProviderAliyun:  "https://sts.aliyuncs.com",
		ProviderTencent: "https://sts.tencentcloudapi.com",
		ProviderAWS:     "https://sts.amazonaws.com",
		ProviderHuawei:  "https://iam.myhuaweicloud.com",
		ProviderVolc:    "https://iam.volcengineapi.com",
	}
}

// Verify does a minimal-read check of one AK/SK pair via the provider STS
// GetCallerIdentity-style endpoint. The kit's Fetcher is used, so the host still
// applies proxy/timeout/rate/audit policy. Endpoints can be overridden per
// provider (e.g. a sovereign-cloud STS host) via Kit.Endpoints.
func (k *Kit) Verify(ctx context.Context, provider, accessKeyID, secretKey string) (VerifyResult, error) {
	if k.Fetcher == nil {
		return VerifyResult{}, fmt.Errorf("fetcher 未注入")
	}
	if !ValidProvider(provider) {
		return VerifyResult{}, fmt.Errorf("不支持的云厂商: %s(可选 aliyun/tencent/aws/huawei/volc)", provider)
	}
	eps := CloudEndpoints()[provider]
	if v := k.Endpoints[provider]; strings.TrimSpace(v) != "" {
		eps = strings.TrimSpace(v)
	}
	switch provider {
	case ProviderAliyun:
		return verifyAliyunAt(ctx, k.Fetcher, eps, accessKeyID, secretKey)
	case ProviderTencent:
		return verifyTencentAt(ctx, k.Fetcher, eps, accessKeyID, secretKey)
	case ProviderAWS:
		return verifyAWSAt(ctx, k.Fetcher, eps, accessKeyID, secretKey)
	case ProviderHuawei:
		return verifyHuaweiAt(ctx, k.Fetcher, eps, accessKeyID, secretKey)
	case ProviderVolc:
		return verifyVolcAt(ctx, k.Fetcher, eps, accessKeyID, secretKey)
	}
	return VerifyResult{}, fmt.Errorf("不支持的云厂商: %s", provider)
}

// ────────────────────────── 阿里云（ACS3 签名）──────────────────────────

func verifyAliyunAt(ctx context.Context, f core.Fetcher, base, ak, sk string) (VerifyResult, error) {
	nonce, err := randomHex(16)
	if err != nil {
		return VerifyResult{}, err
	}
	acsDate := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	headers := map[string]string{
		"host":                  strings.TrimPrefix(base, "https://"),
		"x-acs-action":          "GetCallerIdentity",
		"x-acs-version":         "2015-04-01",
		"x-acs-date":            acsDate,
		"x-acs-signature-nonce": nonce,
	}
	signature, signedHeaders := acs3Sign(sk, headers, "")

	req := core.Request{
		Method:  http.MethodPost,
		URL:     base + "/",
		Headers: map[string]string{"Accept": "application/json"},
	}
	for k, v := range headers {
		if k != "host" {
			req.Headers[k] = v
		}
	}
	req.Headers["Authorization"] = fmt.Sprintf("ACS3-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s",
		ak, signedHeaders, signature)

	var payload struct {
		AccountId string `json:"AccountId"`
		Arn       string `json:"Arn"`
		Code      string `json:"Code"`
		Message   string `json:"Message"`
	}
	ok, err := fetchJSON(ctx, f, req, &payload)
	if err != nil {
		return VerifyResult{}, err
	}
	if ok && payload.Code == "" {
		return VerifyResult{Valid: true, Status: StatusValid, AccountID: payload.AccountId, Arn: payload.Arn}, nil
	}
	res := VerifyResult{Valid: false, Code: payload.Code, Message: payload.Message}
	res.Status = classifyStatus(payload.Code,
		map[string]bool{
			"InvalidAccessKeyId.NotFound": true,
			"SignatureDoesNotMatch":       true,
			"MissingAuthenticationToken":  true,
			"InvalidAccessKeyId":          true,
		},
		map[string]bool{
			"AccessDenied": true, "Forbidden": true, "Forbidden.RAM": true, "SubDenied": true, "NoPermission": true,
		})
	return res, nil
}

func acs3Sign(secretKey string, headers map[string]string, body string) (signature, signedHeaders string) {
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	signedHeaders = strings.Join(names, ";")

	var ch strings.Builder
	for _, name := range names {
		ch.WriteString(name)
		ch.WriteString(":")
		ch.WriteString(strings.TrimSpace(headers[name]))
		ch.WriteString("\n")
	}
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/",
		"",
		ch.String(),
		signedHeaders,
		sha256Hex(body),
	}, "\n")
	stringToSign := "ACS3-HMAC-SHA256\n" + sha256Hex(canonicalRequest)
	return hex.EncodeToString(hmacSHA256([]byte(secretKey), []byte(stringToSign))), signedHeaders
}

// ────────────────────────── 腾讯云（TC3-HMAC-SHA256）──────────────────────────

func verifyTencentAt(ctx context.Context, f core.Fetcher, base, ak, sk string) (VerifyResult, error) {
	const service = "sts"
	const body = "{}"
	now := time.Now().UTC()
	timestamp := now.Unix()
	date := now.Format("2006-01-02")

	canonicalHeaders := "content-type:application/json; charset=utf-8\n" +
		"host:sts.tencentcloudapi.com\n" +
		"x-tc-action:getcalleridentity\n"
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/",
		"",
		canonicalHeaders,
		"content-type;host;x-tc-action",
		sha256Hex(body),
	}, "\n")
	scope := date + "/" + service + "/tc3_request"
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256",
		fmt.Sprintf("%d", timestamp),
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")
	kDate := hmacSHA256([]byte("TC3"+sk), []byte(date))
	kService := hmacSHA256(kDate, []byte(service))
	kSigning := hmacSHA256(kService, []byte("tc3_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req := core.Request{
		Method: http.MethodPost,
		URL:    base + "/",
		Headers: map[string]string{
			"Content-Type":   "application/json; charset=utf-8",
			"X-TC-Action":    "GetCallerIdentity",
			"X-TC-Version":   "2018-08-13",
			"X-TC-Timestamp": fmt.Sprintf("%d", timestamp),
			"Authorization": fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host;x-tc-action, Signature=%s",
				ak, scope, signature),
		},
		Body: []byte(body),
	}

	var payload struct {
		Response struct {
			AccountID string `json:"AccountId"`
			UserId    string `json:"UserId"`
			Arn       string `json:"Arn"`
			Error     *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	ok, err := fetchJSON(ctx, f, req, &payload)
	if err != nil {
		return VerifyResult{}, err
	}
	if ok && payload.Response.Error == nil {
		return VerifyResult{Valid: true, Status: StatusValid, AccountID: payload.Response.AccountID, Arn: payload.Response.Arn}, nil
	}
	code, message := "", ""
	if payload.Response.Error != nil {
		code = payload.Response.Error.Code
		message = payload.Response.Error.Message
	}
	res := VerifyResult{Valid: false, Code: code, Message: message}
	res.Status = classifyStatus(code,
		map[string]bool{
			"AuthFailure.SignatureFailure": true,
			"AuthFailure.SecretIdNotFound": true,
			"AuthFailure.InvalidSecretId":  true,
			"AuthFailure.TokenFailure":     true,
		},
		map[string]bool{
			"UnauthorizedOperation": true, "AccessDenied": true,
		})
	return res, nil
}

// ────────────────────────── AWS（SigV4）──────────────────────────

type awsCallerIdentityXML struct {
	Arn     string `xml:"GetCallerIdentityResult>Arn"`
	Account string `xml:"GetCallerIdentityResult>Account"`
	UserId  string `xml:"GetCallerIdentityResult>UserId"`
}

type awsErrorXML struct {
	Code    string `xml:"Error>Code"`
	Message string `xml:"Error>Message"`
}

func verifyAWSAt(ctx context.Context, f core.Fetcher, base, ak, sk string) (VerifyResult, error) {
	const region, service = "us-east-1", "sts"
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	query := canonicalQuery(map[string]string{"Action": "GetCallerIdentity", "Version": "2011-06-15"})
	canonicalHeaders := "host:sts.amazonaws.com\nx-amz-date:" + amzDate + "\n"
	canonicalRequest := strings.Join([]string{
		http.MethodGet,
		"/",
		query,
		canonicalHeaders,
		"host;x-amz-date",
		sha256Hex(""),
	}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")
	kDate := hmacSHA256([]byte("AWS4"+sk), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req := core.Request{
		Method: http.MethodGet,
		URL:    base + "/?" + query,
		Headers: map[string]string{
			"X-Amz-Date": amzDate,
			"Authorization": fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=host;x-amz-date, Signature=%s",
				ak, scope, signature),
		},
	}
	resp, err := f.Fetch(ctx, req)
	if err != nil {
		return VerifyResult{}, err
	}
	data := resp.Body
	var identity awsCallerIdentityXML
	var awsErr awsErrorXML
	if err := xml.Unmarshal(data, &identity); err != nil {
		// non-fatal: error body still parseable below
		_ = err
	}
	if err := xml.Unmarshal(data, &awsErr); err != nil {
		_ = err
	}
	if resp.Status == http.StatusOK && awsErr.Code == "" && identity.Arn != "" {
		return VerifyResult{Valid: true, AccountID: identity.Account, Arn: identity.Arn}, nil
	}
	code, message := awsErr.Code, awsErr.Message
	if code == "" {
		code, message = fmt.Sprintf("HTTP%d", resp.Status), strings.TrimSpace(string(data))
		if len(message) > 200 {
			message = message[:200]
		}
	}
	res := VerifyResult{Valid: false, Code: code, Message: message}
	res.Status = classifyStatus(code,
		map[string]bool{
			"InvalidClientTokenId":  true,
			"InvalidAccessKeyId":    true,
			"SignatureDoesNotMatch": true,
			"ExpiredToken":          true,
			"ExpiredTokenException": true,
		},
		map[string]bool{
			"AccessDenied": true, "AccessDeniedException": true,
		})
	return res, nil
}

// ────────────────────────── 华为云（SDK-HMAC-SHA256）──────────────────────────

func verifyHuaweiAt(ctx context.Context, f core.Fetcher, base, ak, sk string) (VerifyResult, error) {
	const host, path = "iam.myhuaweicloud.com", "/v3/auth/projects"
	now := time.Now().UTC()
	sdkDate := now.Format("20060102T150405Z")

	canonicalHeaders := "host:" + host + "\nx-sdk-date:" + sdkDate + "\n"
	canonicalRequest := strings.Join([]string{
		http.MethodGet,
		path,
		"",
		canonicalHeaders,
		"host;x-sdk-date",
		sha256Hex(""),
	}, "\n")
	stringToSign := "SDK-HMAC-SHA256\n" + sdkDate + "\n" + sha256Hex(canonicalRequest)
	signature := hex.EncodeToString(hmacSHA256([]byte(sk), []byte(stringToSign)))

	req := core.Request{
		Method: http.MethodGet,
		URL:    base + path,
		Headers: map[string]string{
			"X-Sdk-Date":    sdkDate,
			"Accept":        "application/json",
			"Authorization": fmt.Sprintf("SDK-HMAC-SHA256 Access=%s, SignedHeaders=host;x-sdk-date, Signature=%s", ak, signature),
		},
	}
	resp, err := f.Fetch(ctx, req)
	if err != nil {
		return VerifyResult{}, err
	}
	data := resp.Body
	var payload struct {
		Projects  []json.RawMessage `json:"projects"`
		ErrorCode string            `json:"error_code"`
		ErrorMsg  string            `json:"error_msg"`
		Error     *struct {
			Code    any    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		_ = err
	}
	code, message := payload.ErrorCode, payload.ErrorMsg
	if payload.Error != nil {
		code = normalizeCode(payload.Error.Code)
		message = payload.Error.Message
	}
	switch {
	case resp.Status == http.StatusOK && code == "":
		return VerifyResult{Valid: true, Status: StatusValid, AccountID: fmt.Sprintf("%d 个项目", len(payload.Projects))}, nil
	case resp.Status == http.StatusUnauthorized:
		return VerifyResult{Valid: false, Status: StatusInvalid, Code: code, Message: message}, nil
	case resp.Status == http.StatusForbidden:
		return VerifyResult{Valid: false, Status: StatusRestricted, Code: code, Message: message}, nil
	default:
		if code == "" {
			code, message = fmt.Sprintf("HTTP%d", resp.Status), strings.TrimSpace(string(data))
			if len(message) > 200 {
				message = message[:200]
			}
		}
		return VerifyResult{Valid: false, Status: StatusUnverifiable, Code: code, Message: message}, nil
	}
}

func normalizeCode(raw any) string {
	switch v := raw.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return fmt.Sprintf("%v", int(v))
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ────────────────────────── 火山引擎（签名 V4,HMAC-SHA256/request）──────────────────────────

func verifyVolcAt(ctx context.Context, f core.Fetcher, base, ak, sk string) (VerifyResult, error) {
	const host, region, service = "iam.volcengineapi.com", "cn-north-1", "iam"
	now := time.Now().UTC()
	vDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	query := canonicalQuery(map[string]string{"Action": "ListUsers", "Version": "2018-01-01"})
	bodyHash := sha256Hex("")
	canonicalHeaders := "content-type:application/json\nhost:" + host + "\nx-content-sha256:" + bodyHash + "\nx-date:" + vDate + "\n"
	canonicalRequest := strings.Join([]string{
		http.MethodGet,
		"/",
		query,
		canonicalHeaders,
		"content-type;host;x-content-sha256;x-date",
		bodyHash,
	}, "\n")
	scope := date + "/" + region + "/" + service + "/request"
	stringToSign := strings.Join([]string{
		"HMAC-SHA256",
		vDate,
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")
	kDate := hmacSHA256([]byte(sk), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req := core.Request{
		Method: http.MethodGet,
		URL:    base + "/?" + query,
		Headers: map[string]string{
			"Content-Type":     "application/json",
			"X-Date":           vDate,
			"X-Content-Sha256": bodyHash,
			"Accept":           "application/json",
			"Authorization": fmt.Sprintf("HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host;x-content-sha256;x-date, Signature=%s",
				ak, scope, signature),
		},
	}

	var payload struct {
		ResponseMetadata struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"ResponseMetadata"`
		Result *struct {
			Details []json.RawMessage `json:"Details"`
		} `json:"Result"`
	}
	ok, err := fetchJSON(ctx, f, req, &payload)
	if err != nil {
		return VerifyResult{}, err
	}
	code, message := "", ""
	if payload.ResponseMetadata.Error != nil {
		code = payload.ResponseMetadata.Error.Code
		message = payload.ResponseMetadata.Error.Message
	}
	if ok && payload.ResponseMetadata.Error == nil {
		n := 0
		if payload.Result != nil {
			n = len(payload.Result.Details)
		}
		return VerifyResult{Valid: true, Status: StatusValid, AccountID: fmt.Sprintf("%d 个 IAM 用户", n)}, nil
	}
	res := VerifyResult{Valid: false, Code: code, Message: message}
	res.Status = classifyStatus(code,
		map[string]bool{
			"InvalidAccessKey":           true,
			"InvalidAccessKeyId":         true,
			"SignatureDoesNotMatch":      true,
			"MissingAuthenticationToken": true,
			"InvalidCredential":          true,
		},
		map[string]bool{
			"AccessDenied":          true,
			"AccessDeniedException": true,
			"PermissionDenied":      true,
			"Forbidden":             true,
		})
	if res.Status == StatusUnverifiable && code == "" && ok {
		res.Status = StatusInvalid
	}
	return res, nil
}

// ────────────────────────── 公共工具 ──────────────────────────

// fetchJSON issues a request via the injected fetcher and unmarshals a JSON body.
// Returns HTTP 2xx and any unmarshal result. Vendor-specific error code/message
// structures are read by the caller from its own decode target.
func fetchJSON(ctx context.Context, f core.Fetcher, req core.Request, out any) (ok bool, err error) {
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	req.Headers["User-Agent"] = ua
	resp, err := f.Fetch(ctx, req)
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return false, fmt.Errorf("解析响应失败 (HTTP %d): %w", resp.Status, err)
	}
	return resp.Status >= 200 && resp.Status < 300, nil
}

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"

func classifyStatus(code string, rejected, restricted map[string]bool) string {
	switch {
	case rejected[code]:
		return StatusInvalid
	case restricted[code]:
		return StatusRestricted
	default:
		return StatusUnverifiable
	}
}

func canonicalQuery(params map[string]string) string {
	parts := make([]string, 0, len(params))
	for k, v := range params {
		parts = append(parts, awsURIEscape(k)+"="+awsURIEscape(v))
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

func awsURIEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// LooksLikePlaceholder rejects obvious placeholder values for credential entry.
func LooksLikePlaceholder(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return true
	}
	if strings.ContainsAny(t, "<> \t\n") {
		return true
	}
	compact := strings.ToLower(t)
	compact = strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(compact)
	for _, q := range []string{
		"your", "example", "sample", "placeholder", "replace", "insert", "paste",
		"changeme", "fillme", "dummy", "fake", "redacted", "notconfigured", "notset",
		"todo", "tbd", "xxxx",
	} {
		if strings.Contains(compact, q) {
			return true
		}
	}
	return false
}

// MaskKey masks a key for display: first 4 + … + last 4.
func MaskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "…" + key[len(key)-4:]
}

// ErrNotFound is returned when a single record does not exist.
var ErrNotFound = errors.New("cloud key 不存在")
