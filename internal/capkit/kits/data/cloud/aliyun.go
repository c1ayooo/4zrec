package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	ram "github.com/alibabacloud-go/ram-20150501/v2/client"
	rds "github.com/alibabacloud-go/rds-20140815/v6/client"
	sts "github.com/alibabacloud-go/sts-20150401/v2/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/alibabacloud-go/tea/tea"
	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	osscred "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
)

// aliyunProvider talks to Alibaba Cloud through the official alibabacloud-go
// SDKs. Signing (the RPC scheme and ACS3-HMAC-SHA256) is entirely the SDK's:
// this file only injects the host's HTTPDoer and maps responses onto the
// internal types. Nothing here hand-rolls a signature.
type aliyunProvider struct{ h *httpDoerClient }

func newAliyunProvider(h *httpDoerClient) Provider { return &aliyunProvider{h: h} }

func (p *aliyunProvider) Name() string { return ProviderAliyun }

// aliyunDefaultRegion is used when the caller gave none. Alibaba Cloud APIs are
// regional; STS/RAM are reachable from any, and this keeps the endpoint non-empty
// so the SDK never falls back to its (network) endpoint resolver.
const aliyunDefaultRegion = "cn-hangzhou"

// aliyunEndpoint resolves the endpoint for one product. Credentials.Endpoint
// (sovereign cloud, private endpoint, or a test double's host) wins; otherwise a
// deterministic <product>.<region>.aliyuncs.com is used so a request never needs
// the SDK's remote endpoint resolver.
func aliyunEndpoint(creds Credentials, product string) string {
	if ep := strings.TrimSpace(creds.Endpoint); ep != "" {
		return ep
	}
	region := strings.TrimSpace(creds.Region)
	switch product {
	case "sts":
		return "sts.aliyuncs.com"
	case "ram":
		return "ram.aliyuncs.com"
	case "ecs":
		if region != "" {
			return "ecs." + region + ".aliyuncs.com"
		}
		return "ecs.aliyuncs.com"
	case "rds":
		if region != "" {
			return "rds." + region + ".aliyuncs.com"
		}
		return "rds.aliyuncs.com"
	case "oss":
		if region != "" {
			return "oss-" + region + ".aliyuncs.com"
		}
		return ""
	}
	return ""
}

// aliyunRegion picks the effective region for a call: the request's own region
// first (cloud_run_command carries one), then the credential's, then the default.
func aliyunRegion(creds Credentials, override string) string {
	if r := strings.TrimSpace(override); r != "" {
		return r
	}
	if r := strings.TrimSpace(creds.Region); r != "" {
		return r
	}
	return aliyunDefaultRegion
}

// aliyunConfig builds the SDK config from the caller's credential only. The
// injected HTTPDoer rides along as openapi.Config.HttpClient (typed dara.HttpClient),
// so every SDK request reaches the host's scope check, limiter and audit.
func (p *aliyunProvider) aliyunConfig(creds Credentials, endpoint string) (*openapi.Config, *Error) {
	ak := strings.TrimSpace(creds.AccessKey)
	sk := strings.TrimSpace(creds.SecretKey)
	if ak == "" || sk == "" {
		return nil, newError(ReasonInvalidCredential, ProviderAliyun, "MissingCredential",
			"access_key/secret_key 必填", maskAK(ak))
	}
	region := strings.TrimSpace(creds.Region)
	if region == "" {
		region = aliyunDefaultRegion
	}
	return &openapi.Config{
		AccessKeyId:     tea.String(ak),
		AccessKeySecret: tea.String(sk),
		RegionId:        tea.String(region),
		Endpoint:        tea.String(endpoint),
		HttpClient:      p.h,
	}, nil
}

// ────────────────────────── cloud_ak_verify ──────────────────────────

func (p *aliyunProvider) Verify(_ context.Context, creds Credentials) (Identity, error) {
	cfg, cerr := p.aliyunConfig(creds, aliyunEndpoint(creds, "sts"))
	if cerr != nil {
		return Identity{}, cerr
	}
	client, err := sts.NewClient(cfg)
	if err != nil {
		return Identity{}, aliyunError(err)
	}
	out, err := client.GetCallerIdentity()
	if err != nil {
		return Identity{}, aliyunError(err)
	}
	if out == nil || out.Body == nil {
		return Identity{}, newError(ReasonUpstream, ProviderAliyun, "empty_response",
			"GetCallerIdentity 返回空响应", maskAK(creds.AccessKey))
	}
	arn := tea.StringValue(out.Body.Arn)
	return Identity{
		AccountID: tea.StringValue(out.Body.AccountId),
		ARN:       arn,
		Type:      aliyunIdentityType(arn),
		Alias:     tea.StringValue(out.Body.UserId),
	}, nil
}

// aliyunIdentityType reads the principal kind out of an ACS ARN, so an operator
// can tell an account root key from a scoped RAM user or an assumed role.
func aliyunIdentityType(arn string) string {
	resource := strings.TrimSpace(arn)
	if i := strings.LastIndex(resource, ":"); i >= 0 {
		resource = resource[i+1:]
	}
	switch {
	case resource == "root":
		return "root_account"
	case strings.HasPrefix(resource, "user/"):
		return "ram_user"
	case strings.HasPrefix(resource, "assumed-role/"):
		return "assumed_role"
	case strings.HasPrefix(resource, "role/"):
		return "ram_role"
	case strings.HasPrefix(resource, "federated-user/"):
		return "federated_user"
	case strings.HasPrefix(resource, "group/"):
		return "ram_group"
	default:
		return resource
	}
}

// ────────────────────────── cloud_asset_list ──────────────────────────

func (p *aliyunProvider) ListAssets(_ context.Context, creds Credentials, req AssetRequest) (AssetPage, error) {
	var out AssetPage
	var errs []error
	attempted, failed := 0, 0
	for _, kind := range req.Kinds {
		switch kind {
		case AssetCompute:
			attempted++
			instances, next, err := p.ecsInstances(creds, req)
			if err != nil {
				failed++
				errs = append(errs, err)
				out.Warnings = append(out.Warnings, "ECS 列举失败："+reasonLabel(err))
				continue
			}
			out.Instances = append(out.Instances, instances...)
			if next != "" {
				out.Cursor, out.HasMore = next, true
			}
		case AssetDatabase:
			attempted++
			instances, next, err := p.rdsInstances(creds, req)
			if err != nil {
				failed++
				errs = append(errs, err)
				out.Warnings = append(out.Warnings, "RDS 列举失败："+reasonLabel(err))
				continue
			}
			out.Instances = append(out.Instances, instances...)
			if next != "" {
				out.Cursor, out.HasMore = next, true
			}
		default:
			out.Warnings = append(out.Warnings, "跳过不支持的资产类型："+kind)
		}
	}
	// Only when every kind we attempted failed (and nothing came back) is the whole
	// call a failure; one failing kind is a partial result carried in Warnings.
	if attempted > 0 && failed == attempted && len(out.Instances) == 0 {
		return out, errs[0]
	}
	out.Total = len(out.Instances)
	return out, nil
}

func (p *aliyunProvider) ecsInstances(creds Credentials, req AssetRequest) ([]Instance, string, error) {
	cfg, cerr := p.aliyunConfig(creds, aliyunEndpoint(creds, "ecs"))
	if cerr != nil {
		return nil, "", cerr
	}
	client, err := ecs.NewClient(cfg)
	if err != nil {
		return nil, "", aliyunError(err)
	}
	region := aliyunRegion(creds, req.Region)
	in := &ecs.DescribeInstancesRequest{
		RegionId:   tea.String(region),
		MaxResults: tea.Int32(int32(clampMax(req.PageSize))), // ECS caps MaxResults at 100
	}
	if req.Cursor != "" {
		in.NextToken = tea.String(req.Cursor)
	}
	out, err := client.DescribeInstances(in)
	if err != nil {
		return nil, "", aliyunError(err)
	}
	if out == nil || out.Body == nil {
		return nil, "", nil
	}
	var instances []Instance
	if out.Body.Instances != nil {
		for _, inst := range out.Body.Instances.Instance {
			if inst == nil {
				continue
			}
			item := Instance{
				ID:     tea.StringValue(inst.InstanceId),
				Name:   tea.StringValue(inst.InstanceName),
				Kind:   AssetCompute,
				Status: tea.StringValue(inst.Status),
				Type:   tea.StringValue(inst.InstanceType),
				Region: region,
				Zone:   tea.StringValue(inst.ZoneId),
			}
			if inst.PublicIpAddress != nil {
				item.PublicIP = aliyunIPs(inst.PublicIpAddress.IpAddress)
			}
			if inst.VpcAttributes != nil && inst.VpcAttributes.PrivateIpAddress != nil {
				item.PrivateIP = aliyunIPs(inst.VpcAttributes.PrivateIpAddress.IpAddress)
			}
			instances = append(instances, item)
		}
	}
	return instances, tea.StringValue(out.Body.NextToken), nil
}

func (p *aliyunProvider) rdsInstances(creds Credentials, req AssetRequest) ([]Instance, string, error) {
	cfg, cerr := p.aliyunConfig(creds, aliyunEndpoint(creds, "rds"))
	if cerr != nil {
		return nil, "", cerr
	}
	client, err := rds.NewClient(cfg)
	if err != nil {
		return nil, "", aliyunError(err)
	}
	region := aliyunRegion(creds, req.Region)
	in := &rds.DescribeDBInstancesRequest{
		RegionId:   tea.String(region),
		MaxResults: tea.Int32(int32(clampMax(req.PageSize))),
	}
	if req.Cursor != "" {
		in.NextToken = tea.String(req.Cursor)
	}
	out, err := client.DescribeDBInstances(in)
	if err != nil {
		return nil, "", aliyunError(err)
	}
	if out == nil || out.Body == nil {
		return nil, "", nil
	}
	var instances []Instance
	if out.Body.Items != nil {
		for _, db := range out.Body.Items.DBInstance {
			if db == nil {
				continue
			}
			dbRegion := tea.StringValue(db.RegionId)
			if strings.TrimSpace(dbRegion) == "" {
				dbRegion = region
			}
			item := Instance{
				ID:     tea.StringValue(db.DBInstanceId),
				Name:   tea.StringValue(db.DBInstanceDescription),
				Kind:   AssetDatabase,
				Status: tea.StringValue(db.DBInstanceStatus),
				Type:   tea.StringValue(db.DBInstanceClass),
				Region: dbRegion,
				Zone:   tea.StringValue(db.ZoneId),
				Engine: aliyunEngine(tea.StringValue(db.Engine), tea.StringValue(db.EngineVersion)),
			}
			if cs := tea.StringValue(db.ConnectionString); strings.TrimSpace(cs) != "" {
				item.PrivateIP = nonEmpty(cs)
			}
			instances = append(instances, item)
		}
	}
	return instances, tea.StringValue(out.Body.NextToken), nil
}

// aliyunIPs trims a repeated address list, dropping empties so an absent field
// maps to nil rather than []"".
func aliyunIPs(in []*string) []string {
	var out []string
	for _, s := range in {
		if v := strings.TrimSpace(tea.StringValue(s)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// aliyunEngine joins a database engine with its version, matching the AWS "mysql 8.0"
// shape.
func aliyunEngine(engine, version string) string {
	engine = strings.TrimSpace(engine)
	version = strings.TrimSpace(version)
	switch {
	case engine == "":
		return version
	case version == "":
		return engine
	default:
		return engine + " " + version
	}
}

// ────────────────────────── cloud_iam_list ──────────────────────────

func (p *aliyunProvider) ListIAM(ctx context.Context, creds Credentials, req IAMRequest) (IAMPage, error) {
	cfg, cerr := p.aliyunConfig(creds, aliyunEndpoint(creds, "ram"))
	if cerr != nil {
		return IAMPage{}, cerr
	}
	client, err := ram.NewClient(cfg)
	if err != nil {
		return IAMPage{}, aliyunError(err)
	}
	runtime := &dara.RuntimeOptions{}
	maxItems := tea.Int32(int32(clampMax(req.MaxResults)))
	marker := aliyunCursor(req.Cursor)

	var page IAMPage
	attempted, failed := 0, 0
	for _, include := range req.Include {
		switch include {
		case "users":
			attempted++
			out, err := client.ListUsersWithContext(ctx, &ram.ListUsersRequest{
				Marker: marker, MaxItems: maxItems,
			}, runtime)
			if err != nil {
				failed++
				page.Warnings = append(page.Warnings, "子用户列举失败："+reasonLabel(aliyunError(err)))
				continue
			}
			if out != nil && out.Body != nil {
				if out.Body.Users != nil {
					for _, u := range out.Body.Users.User {
						if u == nil {
							continue
						}
						page.Users = append(page.Users, IAMUser{
							Name:      tea.StringValue(u.UserName),
							ID:        tea.StringValue(u.UserId),
							CreatedAt: tea.StringValue(u.CreateDate),
						})
					}
				}
				page.Cursor, page.HasMore = tea.StringValue(out.Body.Marker), tea.BoolValue(out.Body.IsTruncated)
			}
		case "policies":
			attempted++
			out, err := client.ListPoliciesWithContext(ctx, &ram.ListPoliciesRequest{
				PolicyType: tea.String("Custom"), Marker: marker, MaxItems: maxItems,
			}, runtime)
			if err != nil {
				failed++
				page.Warnings = append(page.Warnings, "策略列举失败："+reasonLabel(aliyunError(err)))
				continue
			}
			if out != nil && out.Body != nil && out.Body.Policies != nil {
				for _, policy := range out.Body.Policies.Policy {
					if policy == nil {
						continue
					}
					page.Policies = append(page.Policies, IAMPolicy{
						Name:        tea.StringValue(policy.PolicyName),
						Description: strings.TrimSpace(tea.StringValue(policy.Description)),
						Attachments: int(tea.Int32Value(policy.AttachmentCount)),
						Admin:       aliyunAdminPolicy(tea.StringValue(policy.PolicyName)),
					})
				}
				page.Cursor, page.HasMore = tea.StringValue(out.Body.Marker), tea.BoolValue(out.Body.IsTruncated)
			}
		case "access_keys":
			attempted++
			out, err := client.ListAccessKeysWithContext(ctx, &ram.ListAccessKeysRequest{}, runtime)
			if err != nil {
				failed++
				page.Warnings = append(page.Warnings, "AccessKey 列举失败："+reasonLabel(aliyunError(err)))
				continue
			}
			if out != nil && out.Body != nil && out.Body.AccessKeys != nil {
				for _, key := range out.Body.AccessKeys.AccessKey {
					if key == nil {
						continue
					}
					page.AccessKeys = append(page.AccessKeys, AccessKey{
						ID:        tea.StringValue(key.AccessKeyId),
						Status:    tea.StringValue(key.Status),
						CreatedAt: tea.StringValue(key.CreateDate),
					})
				}
			}
		default:
			page.Warnings = append(page.Warnings, "跳过不支持的 IAM 类别："+include)
		}
	}

	// Mark users whose directly attached policy looks administrative. Probing the
	// attached policies is one API call per user, so it is bounded by maxAdminProbe
	// (aws.go): the privesc surface is worth exposing, a call storm is not.
	for i := range page.Users {
		if i >= maxAdminProbe {
			break
		}
		out, err := client.ListPoliciesForUserWithContext(ctx, &ram.ListPoliciesForUserRequest{
			UserName: tea.String(page.Users[i].Name),
		}, runtime)
		if err != nil {
			continue
		}
		if out == nil || out.Body == nil || out.Body.Policies == nil {
			continue
		}
		for _, policy := range out.Body.Policies.Policy {
			if policy == nil {
				continue
			}
			if aliyunAdminPolicy(tea.StringValue(policy.PolicyName)) {
				page.Users[i].AdminHint = tea.StringValue(policy.PolicyName)
				break
			}
		}
	}

	page.Total = len(page.Users) + len(page.Policies) + len(page.AccessKeys)
	if attempted > 0 && failed == attempted && page.Total == 0 {
		return page, newError(ReasonUpstream, ProviderAliyun, "iam", strings.Join(page.Warnings, "；"), "")
	}
	return page, nil
}

// aliyunCursor turns an optional marker into the SDK's *string.
func aliyunCursor(cursor string) *string {
	if strings.TrimSpace(cursor) == "" {
		return nil
	}
	return tea.String(cursor)
}

// aliyunAdminPolicy reports whether a RAM policy name looks like full admin. It
// defers to the shared adminish() and adds RAM's bare "Administrator" alias,
// which adminish() (built for AWS names) does not catch.
func aliyunAdminPolicy(name string) bool {
	if adminish(name) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(name), "administrator")
}

// ────────────────────────── cloud_storage_list ──────────────────────────

func (p *aliyunProvider) ListStorage(ctx context.Context, creds Credentials, req StorageRequest) (StoragePage, error) {
	ak := strings.TrimSpace(creds.AccessKey)
	sk := strings.TrimSpace(creds.SecretKey)
	if ak == "" || sk == "" {
		return StoragePage{}, newError(ReasonInvalidCredential, ProviderAliyun, "MissingCredential",
			"access_key/secret_key 必填", maskAK(ak))
	}
	cfg := oss.LoadDefaultConfig().
		WithCredentialsProvider(osscred.NewStaticCredentialsProvider(ak, sk, "")).
		WithHttpClient(p.h.client())
	if region := strings.TrimSpace(creds.Region); region != "" {
		cfg = cfg.WithRegion(region)
	}
	if ep := aliyunEndpoint(creds, "oss"); ep != "" {
		cfg = cfg.WithEndpoint(ep)
	}
	client := oss.NewClient(cfg)

	bucket := strings.TrimSpace(req.Bucket)
	if bucket == "" {
		in := &oss.ListBucketsRequest{MaxKeys: int32(clampMax(req.MaxResults))}
		if req.Prefix != "" {
			in.Prefix = oss.Ptr(req.Prefix)
		}
		if req.Cursor != "" {
			in.Marker = oss.Ptr(req.Cursor)
		}
		out, err := client.ListBuckets(ctx, in)
		if err != nil {
			return StoragePage{}, aliyunError(err)
		}
		var page StoragePage
		for _, b := range out.Buckets {
			page.Buckets = append(page.Buckets, Bucket{
				Name:      oss.ToString(b.Name),
				Region:    oss.ToString(b.Location),
				CreatedAt: aliyunTime(b.CreationDate),
			})
		}
		sort.Slice(page.Buckets, func(i, j int) bool { return page.Buckets[i].Name < page.Buckets[j].Name })
		page.Cursor, page.HasMore = oss.ToString(out.NextMarker), out.IsTruncated
		page.Total = len(page.Buckets)
		return page, nil
	}

	// Objects only: key, size and last-modified travel; a body is never fetched.
	in := &oss.ListObjectsV2Request{
		Bucket:  oss.Ptr(bucket),
		MaxKeys: int32(clampMax(req.MaxResults)),
	}
	if req.Prefix != "" {
		in.Prefix = oss.Ptr(req.Prefix)
	}
	if req.Cursor != "" {
		in.ContinuationToken = oss.Ptr(req.Cursor)
	}
	out, err := client.ListObjectsV2(ctx, in)
	if err != nil {
		return StoragePage{}, aliyunError(err)
	}
	var page StoragePage
	for _, obj := range out.Contents {
		page.Objects = append(page.Objects, Object{
			Key:          oss.ToString(obj.Key),
			Size:         obj.Size,
			LastModified: aliyunTime(obj.LastModified),
		})
	}
	page.Cursor, page.HasMore = oss.ToString(out.NextContinuationToken), out.IsTruncated
	page.Total = len(page.Objects)
	return page, nil
}

// aliyunTime formats an OSS timestamp the way the other providers do.
func aliyunTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ────────────────────────── cloud_run_command ──────────────────────────

func (p *aliyunProvider) RunCommand(ctx context.Context, creds Credentials, req CommandRequest) (CommandResult, error) {
	cfg, cerr := p.aliyunConfig(creds, aliyunEndpoint(creds, "ecs"))
	if cerr != nil {
		return CommandResult{}, cerr
	}
	client, err := ecs.NewClient(cfg)
	if err != nil {
		return CommandResult{}, aliyunError(err)
	}
	region := aliyunRegion(creds, req.Region)
	timeout := int64(req.TimeoutSec)
	if timeout <= 0 {
		timeout = int64(defaultCommandTimeout / time.Second)
	}
	// CommandContent must be base64; Type selects the shell interpreter.
	encoded := base64.StdEncoding.EncodeToString([]byte(req.Command))
	out, err := client.RunCommand(&ecs.RunCommandRequest{
		RegionId:       tea.String(region),
		InstanceId:     []*string{tea.String(req.InstanceID)},
		CommandContent: tea.String(encoded),
		Type:           tea.String("RunShellScript"),
		Timeout:        tea.Int64(timeout),
	})
	if err != nil {
		return CommandResult{}, aliyunError(err)
	}
	if out == nil || out.Body == nil {
		return CommandResult{}, newError(ReasonUpstream, ProviderAliyun, "empty_response",
			"RunCommand 返回空响应", maskAK(creds.AccessKey))
	}
	result := CommandResult{InstanceID: req.InstanceID, CommandID: tea.StringValue(out.Body.CommandId)}
	invokeID := tea.StringValue(out.Body.InvokeId)
	if invokeID == "" {
		return result, nil
	}
	for {
		res, err := client.DescribeInvocationResults(&ecs.DescribeInvocationResultsRequest{
			RegionId:   tea.String(region),
			InvokeId:   tea.String(invokeID),
			InstanceId: tea.String(req.InstanceID),
		})
		if err != nil {
			return result, aliyunError(err)
		}
		if inv := aliyunInvocationResult(res); inv != nil {
			result.Status = tea.StringValue(inv.InvocationStatus)
			result.ExitCode = int(tea.Int64Value(inv.ExitCode))
			result.Stdout = aliyunDecodeOutput(tea.StringValue(inv.Output))
			result.StdoutSize = len(result.Stdout)
			if aliyunCommandTerminal(result.Status) {
				return result, nil
			}
		}
		if werr := waitFor(ctx, commandPollInterval); werr != nil {
			return result, aliyunError(werr)
		}
	}
}

// aliyunInvocationResult pulls the single execution result out of a
// DescribeInvocationResults response.
func aliyunInvocationResult(res *ecs.DescribeInvocationResultsResponse) *ecs.DescribeInvocationResultsResponseBodyInvocationInvocationResultsInvocationResult {
	if res == nil || res.Body == nil || res.Body.Invocation == nil ||
		res.Body.Invocation.InvocationResults == nil {
		return nil
	}
	list := res.Body.Invocation.InvocationResults.InvocationResult
	if len(list) == 0 {
		return nil
	}
	return list[0]
}

// aliyunCommandTerminal reports whether a cloud-assistant status is final. The
// poll keeps running for Pending/Running.
func aliyunCommandTerminal(status string) bool {
	switch status {
	case "Success", "Failed", "Stopped", "Timeout":
		return true
	}
	return false
}

// aliyunDecodeOutput decodes the base64 command output; if it is not base64 the
// raw string is returned rather than losing it.
func aliyunDecodeOutput(s string) string {
	if s == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(b)
}

// ────────────────────────── aliyun error classification ──────────────────────────

// aliyunReasons maps documented Alibaba Cloud error codes onto the normalized
// reasons, so "my key is wrong" is distinguishable from "my key lacks this
// permission".
var aliyunReasons = map[string]Reason{
	// 凭据无效
	"InvalidAccessKeyId.NotFound":  ReasonInvalidCredential,
	"InvalidAccessKeyId":           ReasonInvalidCredential,
	"SignatureDoesNotMatch":        ReasonInvalidCredential,
	"MissingAuthenticationToken":   ReasonInvalidCredential,
	"InvalidSecurityToken.Expired": ReasonInvalidCredential,
	// 权限不足
	"Forbidden":                   ReasonPermissionDenied,
	"Forbidden.RAM":               ReasonPermissionDenied,
	"AccessDenied":                ReasonPermissionDenied,
	"NoPermission":                ReasonPermissionDenied,
	"Forbidden.AccessKeyDisabled": ReasonPermissionDenied,
	// 地域错误
	"InvalidRegionId":           ReasonRegionInvalid,
	"InvalidParameter.RegionId": ReasonRegionInvalid,
	"InvalidRegionId.NotFound":  ReasonRegionInvalid,
	// 实例不在运行态
	"IncorrectInstanceStatus": ReasonInstanceNotRunning,
	"InvalidInstanceStatus":   ReasonInstanceNotRunning,
	"InvalidDBInstanceState":  ReasonInstanceNotRunning,
	// 不存在
	"InvalidInstanceId.NotFound":   ReasonNotFound,
	"InvalidDBInstanceId.NotFound": ReasonNotFound,
	"NoSuchBucket":                 ReasonNotFound,
	"InvalidBucketName":            ReasonNotFound,
	// 限流
	"Throttling":                      ReasonThrottled,
	"Throttling.User":                 ReasonThrottled,
	"ServiceUnavailable":              ReasonThrottled,
	"RequestLimitExceeded":            ReasonThrottled,
	"OperationDenied.TooManyRequests": ReasonThrottled,
	// 超时
	"RequestTimeout": ReasonTimeout,
	"Timeout":        ReasonTimeout,
}

// aliyunFallback catches undocumented codes and OSS's prose errors.
var aliyunFallback = []matchRule{
	{"invalid accesskey", ReasonInvalidCredential},
	{"invalidaccesskeyid", ReasonInvalidCredential},
	{"signature", ReasonInvalidCredential},
	{"security token", ReasonInvalidCredential},
	{"accesskeydisabled", ReasonPermissionDenied},
	{"not authorized", ReasonPermissionDenied},
	{"forbidden", ReasonPermissionDenied},
	{"no permission", ReasonPermissionDenied},
	{"access denied", ReasonPermissionDenied},
	{"invalid region", ReasonRegionInvalid},
	{"invalidparameter.regionid", ReasonRegionInvalid},
	{"not in a valid state", ReasonInstanceNotRunning},
	{"not running", ReasonInstanceNotRunning},
	{"no such", ReasonNotFound},
	{"not found", ReasonNotFound},
	{"does not exist", ReasonNotFound},
	{"throttl", ReasonThrottled},
	{"too many requests", ReasonThrottled},
	{"requestlimitexceeded", ReasonThrottled},
	{"service unavailable", ReasonThrottled},
	{"deadline exceeded", ReasonTimeout},
	{"timed out", ReasonTimeout},
	{"requesttimeout", ReasonTimeout},
}

// classifyAliyun turns an SDK error into a normalized *Error. The alibabacloud-go
// SDKs surface the vendor code through tea.SDKError / dara.SDKError (and the
// openapi ClientError / ServerError / ThrottlingError on 4xx/5xx); OSS surfaces
// its own ServiceError. All expose Code/Message, so no string parsing is needed
// for the documented cases and reasonFor only falls back to prose.
func classifyAliyun(err error) *Error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return newError(ReasonTimeout, ProviderAliyun, "context", err.Error(), "")
	}
	code, message := "", err.Error()
	var teaErr *tea.SDKError
	var daraErr *dara.SDKError
	var ossErr *oss.ServiceError
	var ossClientErr *oss.ClientError
	var coder interface {
		GetCode() *string
		GetMessage() *string
	}
	switch {
	case errors.As(err, &teaErr):
		code, message = tea.StringValue(teaErr.Code), tea.StringValue(teaErr.Message)
	case errors.As(err, &daraErr):
		code, message = tea.StringValue(daraErr.Code), tea.StringValue(daraErr.Message)
	case errors.As(err, &ossErr):
		code, message = ossErr.Code, ossErr.Message
	case errors.As(err, &ossClientErr):
		code, message = ossClientErr.Code, ossClientErr.Message
	case errors.As(err, &coder):
		code, message = tea.StringValue(coder.GetCode()), tea.StringValue(coder.GetMessage())
	}
	if strings.TrimSpace(message) == "" {
		message = err.Error()
	}
	return newError(reasonFor(code, message, aliyunReasons, aliyunFallback), ProviderAliyun, code, message, "")
}

// aliyunError classifies a vendor error but lets a failure raised by capkit
// itself (scope_denied / rate_limited / timeout from the host's HTTPDoer) pass
// through verbatim, so cloudkit.go's k.failure keeps the host's own error code
// instead of re-labelling it an upstream cloud failure.
func aliyunError(err error) error {
	if err == nil {
		return nil
	}
	if ce := asCapkitError(err); ce != nil {
		return ce
	}
	return classifyAliyun(err)
}
