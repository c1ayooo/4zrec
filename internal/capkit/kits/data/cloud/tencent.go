package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"

	cam "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam/v20190116"
	cdb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdb/v20170320"
	tc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
	sts "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sts/v20180813"
	"github.com/tencentyun/cos-go-sdk-v5"
)

// tencentProvider talks to Tencent Cloud through tencentcloud-sdk-go. Signing
// (TC3-HMAC-SHA256) is entirely the SDK's: this file only wires the caller's
// credential, the injected HTTP transport and the response mapping.
//
// Every request is forced through p.h (a core.HTTPDoer adapter acting as an
// http.RoundTripper), so the host's scope check, rate limit and audit still see
// the call. No request is ever handed to the SDK's own client/transport.
type tencentProvider struct{ h *httpDoerClient }

func newTencentProvider(h *httpDoerClient) Provider { return &tencentProvider{h: h} }

func (p *tencentProvider) Name() string { return ProviderTencent }

// Tencent Cloud API endpoints. These are the public regional gateways; a caller
// can override them with Credentials.Endpoint (sovereign cloud / test double).
const (
	tencentEndpointSTS = "sts.tencentcloudapi.com"
	tencentEndpointCVM = "cvm.tencentcloudapi.com"
	tencentEndpointCDB = "cdb.tencentcloudapi.com"
	tencentEndpointCAM = "cam.tencentcloudapi.com"
	// RunCommand / DescribeInvocationTasks live in TencentCloud Automation Tools
	// (TAT), not in CVM: the CVM SDK has no cloud-assistant API. TAT is reached
	// through the SDK's generic common client below, still signed by the SDK.
	tencentEndpointTAT = "tat.tencentcloudapi.com"

	// defaultTencentRegion is used when the caller gave no region. Tencent
	// requires a region on the wire even for account-global reads.
	defaultTencentRegion = "ap-guangzhou"

	// TAT service/version/actions.
	tencentTATService                    = "tat"
	tencentTATVersion                    = "2020-10-28"
	tencentRunCommandAction              = "RunCommand"
	tencentDescribeInvocationTasksAction = "DescribeInvocationTasks"

	// tencentMaxAPIPage is the largest page both CVM and CDB accept in one call.
	tencentMaxAPIPage = 100
	// tencentCOSMaxKeys bounds one COS listing.
	tencentCOSMaxKeys = 1000
)

// tencentAvailable guards every method: without an injected HTTPDoer nothing can
// leave the process, so the tool reports unavailable instead of dialing out.
func (p *tencentProvider) tencentAvailable() error {
	if p == nil || p.h == nil || p.h.doer == nil {
		return core.Unavailable("cloudkit: HTTPDoer 未注入，无法发起云 API 调用")
	}
	return nil
}

// tencentCredential projects the caller's AK/SK into a credential the SDK signs
// with. The credential is never cached.
func tencentCredential(creds Credentials) (*tc.Credential, error) {
	ak := strings.TrimSpace(creds.AccessKey)
	sk := strings.TrimSpace(creds.SecretKey)
	if ak == "" || sk == "" {
		return nil, newError(ReasonInvalidCredential, ProviderTencent, "MissingCredential",
			"access_key/secret_key 必填", maskAK(ak))
	}
	return tc.NewCredential(ak, sk), nil
}

// tencentRegion returns the region to sign for, defaulting when the caller left
// it empty.
func tencentRegion(region string) string {
	if r := strings.TrimSpace(region); r != "" {
		return r
	}
	return defaultTencentRegion
}

// tencentEndpointHost strips a scheme from an endpoint override: the SDK's
// HttpProfile wants a bare host (an optional path is preserved and split off by
// the SDK itself).
func tencentEndpointHost(endpoint string) string {
	e := strings.TrimSpace(endpoint)
	if i := strings.Index(e, "://"); i >= 0 {
		e = e[i+3:]
	}
	return strings.TrimRight(e, "/")
}

// tencentProfile builds a client profile whose endpoint is the caller's override
// or def, with the region breaker disabled (we do not want the SDK silently
// switching hosts behind the injected transport).
func tencentProfile(override, def string, timeout time.Duration) *profile.ClientProfile {
	cp := profile.NewClientProfile()
	endpoint := strings.TrimSpace(override)
	if endpoint == "" {
		endpoint = def
	}
	cp.HttpProfile.Endpoint = tencentEndpointHost(endpoint)
	if timeout > 0 {
		cp.HttpProfile.ReqTimeout = int(timeout / time.Second)
	}
	cp.DisableRegionBreaker = true
	return cp
}

// ────────────────────────── cloud_ak_verify ──────────────────────────

func (p *tencentProvider) Verify(ctx context.Context, creds Credentials) (Identity, error) {
	if err := p.tencentAvailable(); err != nil {
		return Identity{}, err
	}
	cred, cerr := tencentCredential(creds)
	if cerr != nil {
		return Identity{}, cerr
	}
	client, err := sts.NewClient(cred, tencentRegion(creds.Region),
		tencentProfile(creds.Endpoint, tencentEndpointSTS, defaultTimeout))
	if err != nil {
		return Identity{}, classifyTencent(err)
	}
	client.WithHttpTransport(p.h)
	out, err := client.GetCallerIdentityWithContext(ctx, sts.NewGetCallerIdentityRequest())
	if err != nil {
		return Identity{}, classifyTencent(err)
	}
	if out == nil || out.Response == nil {
		return Identity{}, newError(ReasonUpstream, ProviderTencent, "sts.GetCallerIdentity", "空响应", maskAK(creds.AccessKey))
	}
	arn := tencentString(out.Response.Arn)
	userID := tencentString(out.Response.UserId)
	return Identity{
		AccountID: tencentString(out.Response.AccountId),
		ARN:       arn,
		Type:      tencentIdentityType(arn, userID),
		Alias:     userID,
	}, nil
}

// tencentIdentityType classifies the caller from the CAM ARN. A role ARN also
// carries a non-empty UserId (roleId:sessionName), so the role check must come
// before the UserId fallback or every assumed role would read as a sub-account.
func tencentIdentityType(arn, userID string) string {
	switch {
	case strings.Contains(arn, ":root"):
		return "root_account"
	case strings.Contains(arn, ":role/"):
		return "assumed_role"
	case strings.Contains(arn, ":uinfo/") || strings.TrimSpace(userID) != "":
		return "sub_account"
	default:
		return ""
	}
}

// ────────────────────────── cloud_asset_list ──────────────────────────

func (p *tencentProvider) ListAssets(ctx context.Context, creds Credentials, req AssetRequest) (AssetPage, error) {
	if err := p.tencentAvailable(); err != nil {
		return AssetPage{}, err
	}
	cred, cerr := tencentCredential(creds)
	if cerr != nil {
		return AssetPage{}, cerr
	}
	region := tencentRegion(req.Region)
	offset := tencentCursorOffset(req.Cursor)
	limit := tencentPageLimit(req.PageSize)

	var out AssetPage
	for _, kind := range req.Kinds {
		switch kind {
		case AssetCompute:
			instances, total, err := p.tencentCompute(ctx, cred, region, creds.Endpoint, offset, limit)
			if err != nil {
				out.Warnings = append(out.Warnings, "CVM 列举失败："+reasonLabel(err))
				continue
			}
			out.Instances = append(out.Instances, instances...)
			tencentAdvanceCursor(&out, offset, len(instances), total)
		case AssetDatabase:
			instances, total, err := p.tencentDatabase(ctx, cred, region, creds.Endpoint, offset, limit)
			if err != nil {
				out.Warnings = append(out.Warnings, "CDB 列举失败："+reasonLabel(err))
				continue
			}
			out.Instances = append(out.Instances, instances...)
			tencentAdvanceCursor(&out, offset, len(instances), total)
		default:
			out.Warnings = append(out.Warnings, "跳过不支持的资产类型："+kind)
		}
	}
	// Every requested kind failed: surface a classified error rather than an
	// empty success. A partial failure stays in Warnings.
	if len(out.Instances) == 0 && len(out.Warnings) > 0 && len(out.Warnings) == len(req.Kinds) {
		return out, newError(ReasonUpstream, ProviderTencent, "assets", strings.Join(out.Warnings, "；"), "")
	}
	out.Total = len(out.Instances)
	return out, nil
}

// tencentCompute lists CVM instances.
func (p *tencentProvider) tencentCompute(ctx context.Context, cred *tc.Credential, region, endpoint string, offset, limit int) ([]Instance, int, error) {
	client, err := cvm.NewClient(cred, region, tencentProfile(endpoint, tencentEndpointCVM, defaultTimeout))
	if err != nil {
		return nil, 0, classifyTencent(err)
	}
	client.WithHttpTransport(p.h)
	request := cvm.NewDescribeInstancesRequest()
	request.Offset = tencentInt64(int64(offset))
	request.Limit = tencentInt64(int64(limit))
	out, err := client.DescribeInstancesWithContext(ctx, request)
	if err != nil {
		return nil, 0, classifyTencent(err)
	}
	if out == nil || out.Response == nil {
		return nil, 0, newError(ReasonUpstream, ProviderTencent, "cvm.DescribeInstances", "空响应", "")
	}
	instances := make([]Instance, 0, len(out.Response.InstanceSet))
	for _, inst := range out.Response.InstanceSet {
		if inst == nil {
			continue
		}
		zone := ""
		if inst.Placement != nil {
			zone = tencentString(inst.Placement.Zone)
		}
		instances = append(instances, Instance{
			ID:        tencentString(inst.InstanceId),
			Name:      tencentString(inst.InstanceName),
			Kind:      AssetCompute,
			Status:    tencentString(inst.InstanceState),
			Type:      tencentString(inst.InstanceType),
			Region:    region,
			Zone:      zone,
			PrivateIP: tencentStrings(inst.PrivateIpAddresses),
			PublicIP:  tencentStrings(inst.PublicIpAddresses),
		})
	}
	return instances, int(tencentInt64Value(out.Response.TotalCount)), nil
}

// tencentDatabase lists CDB/RDS instances.
func (p *tencentProvider) tencentDatabase(ctx context.Context, cred *tc.Credential, region, endpoint string, offset, limit int) ([]Instance, int, error) {
	client, err := cdb.NewClient(cred, region, tencentProfile(endpoint, tencentEndpointCDB, defaultTimeout))
	if err != nil {
		return nil, 0, classifyTencent(err)
	}
	client.WithHttpTransport(p.h)
	request := cdb.NewDescribeDBInstancesRequest()
	request.Offset = tencentUint64(uint64(offset))
	request.Limit = tencentUint64(uint64(limit))
	out, err := client.DescribeDBInstancesWithContext(ctx, request)
	if err != nil {
		return nil, 0, classifyTencent(err)
	}
	if out == nil || out.Response == nil {
		return nil, 0, newError(ReasonUpstream, ProviderTencent, "cdb.DescribeDBInstances", "空响应", "")
	}
	instances := make([]Instance, 0, len(out.Response.Items))
	for _, db := range out.Response.Items {
		if db == nil {
			continue
		}
		instances = append(instances, Instance{
			ID:        tencentString(db.InstanceId),
			Name:      tencentString(db.InstanceName),
			Kind:      AssetDatabase,
			Status:    strconv.FormatInt(tencentInt64Value(db.Status), 10),
			Type:      strconv.FormatInt(tencentInt64Value(db.InstanceType), 10),
			Region:    region,
			Zone:      tencentString(db.Zone),
			Engine:    tencentString(db.EngineVersion),
			PrivateIP: nonEmpty(tencentString(db.Vip)),
		})
	}
	return instances, int(tencentInt64Value(out.Response.TotalCount)), nil
}

// tencentAdvanceCursor turns an offset page into a next-cursor when the vendor
// reported more rows than came back.
func tencentAdvanceCursor(page *AssetPage, offset, got, total int) {
	if total > 0 && offset+got < total {
		page.Cursor = strconv.Itoa(offset + got)
		page.HasMore = true
	}
}

// tencentCursorOffset reads the numeric cursor; a non-numeric cursor is treated
// as the first page (0).
func tencentCursorOffset(cursor string) int {
	c := strings.TrimSpace(cursor)
	if c == "" {
		return 0
	}
	n, err := strconv.Atoi(c)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// tencentPageLimit clamps the page size to the vendor maximum.
func tencentPageLimit(pageSize int) int {
	limit := clampMax(pageSize)
	if limit > tencentMaxAPIPage {
		limit = tencentMaxAPIPage
	}
	return limit
}

// ────────────────────────── cloud_iam_list ──────────────────────────

func (p *tencentProvider) ListIAM(ctx context.Context, creds Credentials, req IAMRequest) (IAMPage, error) {
	if err := p.tencentAvailable(); err != nil {
		return IAMPage{}, err
	}
	cred, cerr := tencentCredential(creds)
	if cerr != nil {
		return IAMPage{}, cerr
	}
	client, err := cam.NewClient(cred, tencentRegion(creds.Region),
		tencentProfile(creds.Endpoint, tencentEndpointCAM, defaultTimeout))
	if err != nil {
		return IAMPage{}, classifyTencent(err)
	}
	client.WithHttpTransport(p.h)

	limit := clampMax(req.MaxResults)
	var page IAMPage
	for _, include := range req.Include {
		switch include {
		case "users":
			out, err := client.ListUsersWithContext(ctx, cam.NewListUsersRequest())
			if err != nil {
				page.Warnings = append(page.Warnings, "子用户列举失败："+reasonLabel(classifyTencent(err)))
				continue
			}
			if out == nil || out.Response == nil {
				page.Warnings = append(page.Warnings, "子用户列举失败：空响应")
				continue
			}
			for _, u := range out.Response.Data {
				if u == nil {
					continue
				}
				page.Users = append(page.Users, IAMUser{
					Name:      tencentString(u.Name),
					ID:        strconv.FormatUint(tencentUint64Value(u.Uin), 10),
					CreatedAt: tencentString(u.CreateTime),
				})
				if len(page.Users) >= limit {
					break
				}
			}
		case "policies":
			request := cam.NewListPoliciesRequest()
			request.Page = tencentUint64(1)
			request.Rp = tencentUint64(uint64(limit))
			out, err := client.ListPoliciesWithContext(ctx, request)
			if err != nil {
				page.Warnings = append(page.Warnings, "策略列举失败："+reasonLabel(classifyTencent(err)))
				continue
			}
			if out == nil || out.Response == nil {
				page.Warnings = append(page.Warnings, "策略列举失败：空响应")
				continue
			}
			for _, pol := range out.Response.List {
				if pol == nil {
					continue
				}
				name := tencentString(pol.PolicyName)
				page.Policies = append(page.Policies, IAMPolicy{
					Name:        name,
					ID:          strconv.FormatUint(tencentUint64Value(pol.PolicyId), 10),
					Description: strings.TrimSpace(tencentString(pol.Description)),
					Attachments: int(tencentUint64Value(pol.Attachments)),
					Admin:       adminish(name),
				})
				if len(page.Policies) >= limit {
					break
				}
			}
		case "access_keys":
			out, err := client.ListAccessKeysWithContext(ctx, cam.NewListAccessKeysRequest())
			if err != nil {
				page.Warnings = append(page.Warnings, "AccessKey 列举失败："+reasonLabel(classifyTencent(err)))
				continue
			}
			if out == nil || out.Response == nil {
				page.Warnings = append(page.Warnings, "AccessKey 列举失败：空响应")
				continue
			}
			for _, key := range out.Response.AccessKeys {
				if key == nil {
					continue
				}
				page.AccessKeys = append(page.AccessKeys, AccessKey{
					ID:        tencentString(key.AccessKeyId),
					Status:    tencentString(key.Status),
					CreatedAt: tencentString(key.CreateTime),
				})
				if len(page.AccessKeys) >= limit {
					break
				}
			}
		default:
			page.Warnings = append(page.Warnings, "跳过不支持的 IAM 类别："+include)
		}
	}

	// Mark users whose directly attached policy looks administrative. Bounded by
	// maxAdminProbe so a large account does not turn one call into hundreds.
	for i := range page.Users {
		if i >= maxAdminProbe {
			break
		}
		uin, err := strconv.ParseUint(page.Users[i].ID, 10, 64)
		if err != nil || uin == 0 {
			continue
		}
		request := cam.NewListAttachedUserPoliciesRequest()
		request.TargetUin = tencentUint64(uin)
		out, err := client.ListAttachedUserPoliciesWithContext(ctx, request)
		if err != nil || out == nil || out.Response == nil {
			continue
		}
		for _, pol := range out.Response.List {
			if pol == nil {
				continue
			}
			if adminish(tencentString(pol.PolicyName)) {
				page.Users[i].AdminHint = tencentString(pol.PolicyName)
				break
			}
		}
	}

	page.Total = len(page.Users) + len(page.Policies) + len(page.AccessKeys)
	if page.Total == 0 && len(page.Warnings) > 0 && len(page.Warnings) == len(req.Include) {
		return page, newError(ReasonUpstream, ProviderTencent, "iam", strings.Join(page.Warnings, "；"), "")
	}
	return page, nil
}

// ────────────────────────── cloud_storage_list ──────────────────────────

func (p *tencentProvider) ListStorage(ctx context.Context, creds Credentials, req StorageRequest) (StoragePage, error) {
	if err := p.tencentAvailable(); err != nil {
		return StoragePage{}, err
	}
	ak := strings.TrimSpace(creds.AccessKey)
	sk := strings.TrimSpace(creds.SecretKey)
	if ak == "" || sk == "" {
		return StoragePage{}, newError(ReasonInvalidCredential, ProviderTencent, "MissingCredential",
			"access_key/secret_key 必填", maskAK(ak))
	}
	region := tencentRegion(creds.Region)
	baseURL, err := tencentCOSBaseURL(creds.Endpoint, region, req.Bucket)
	if err != nil {
		return StoragePage{}, err
	}
	// The COS SDK signs by wrapping our transport with an AuthorizationTransport
	// that adds the q-sign-algorithm header, then delegates to it. The injected
	// doer therefore stays the innermost RoundTripper and every request reaches
	// the host's port.
	auth := &cos.AuthorizationTransport{SecretID: ak, SecretKey: sk, Transport: p.h}
	httpClient := p.h.client()
	httpClient.Transport = auth
	client := cos.NewClient(baseURL, httpClient)
	// The host's limiter and audit already wrap the port; an SDK retry would
	// just multiply the requests the host counts.
	client.Conf.RetryOpt.Count = 0

	if strings.TrimSpace(req.Bucket) == "" {
		opt := &cos.ServiceGetOptions{MaxKeys: int64(tencentCOSMaxKeys)}
		if req.Cursor != "" {
			opt.Marker = req.Cursor
		}
		out, _, err := client.Service.Get(ctx, opt)
		if err != nil {
			return StoragePage{}, classifyTencent(err)
		}
		var page StoragePage
		for _, b := range out.Buckets {
			page.Buckets = append(page.Buckets, Bucket{
				Name:      b.Name,
				Region:    b.Region,
				CreatedAt: b.CreationDate,
			})
		}
		sort.Slice(page.Buckets, func(i, j int) bool { return page.Buckets[i].Name < page.Buckets[j].Name })
		page.Total = len(page.Buckets)
		return page, nil
	}

	opt := &cos.BucketGetOptions{
		Prefix:  req.Prefix,
		Marker:  req.Cursor,
		MaxKeys: tencentCOSKeyLimit(req.MaxResults),
	}
	out, _, err := client.Bucket.Get(ctx, opt)
	if err != nil {
		return StoragePage{}, classifyTencent(err)
	}
	var page StoragePage
	for _, obj := range out.Contents {
		page.Objects = append(page.Objects, Object{
			Key:          obj.Key,
			Size:         obj.Size,
			LastModified: obj.LastModified,
		})
	}
	page.Cursor, page.HasMore = out.NextMarker, out.IsTruncated
	page.Total = len(page.Objects)
	return page, nil
}

// tencentCOSBaseURL resolves the COS base URL. With no bucket it points at the
// service endpoint (list buckets); with a bucket it points at the bucket host.
// An endpoint override is used verbatim for both.
func tencentCOSBaseURL(endpoint, region, bucket string) (*cos.BaseURL, error) {
	bucket = strings.TrimSpace(bucket)
	if ep := strings.TrimSpace(endpoint); ep != "" {
		u, err := url.Parse(ep)
		if err != nil {
			return nil, invalidInput(ProviderTencent, "endpoint 非法: "+err.Error())
		}
		return &cos.BaseURL{BucketURL: u, ServiceURL: u}, nil
	}
	if bucket == "" {
		u, _ := url.Parse("https://cos." + region + ".myqcloud.com")
		return &cos.BaseURL{ServiceURL: u}, nil
	}
	// NewBucketURL also validates the bucket name (name-appid) and region.
	u, err := cos.NewBucketURL(bucket, region, true)
	if err != nil {
		return nil, invalidInput(ProviderTencent, "bucket 非法: "+err.Error())
	}
	return &cos.BaseURL{BucketURL: u}, nil
}

// tencentCOSKeyLimit clamps a COS page size.
func tencentCOSKeyLimit(maxResults int) int {
	n := clampMax(maxResults)
	if n > tencentCOSMaxKeys {
		n = tencentCOSMaxKeys
	}
	return n
}

// ────────────────────────── cloud_run_command ──────────────────────────

func (p *tencentProvider) RunCommand(ctx context.Context, creds Credentials, req CommandRequest) (CommandResult, error) {
	if err := p.tencentAvailable(); err != nil {
		return CommandResult{}, err
	}
	cred, cerr := tencentCredential(creds)
	if cerr != nil {
		return CommandResult{}, cerr
	}
	instance := strings.TrimSpace(req.InstanceID)
	if instance == "" {
		return CommandResult{}, invalidInput(ProviderTencent, "instance_id 必填")
	}
	command := strings.TrimSpace(req.Command)
	if command == "" {
		return CommandResult{}, invalidInput(ProviderTencent, "command 必填")
	}
	timeout := req.TimeoutSec
	if timeout <= 0 {
		timeout = int(defaultCommandTimeout / time.Second)
	}

	// TAT has no typed SDK module wired into this build, so it is called through
	// the SDK's generic common client: the request still carries service=tat, so
	// the SDK signs it with the TAT credential scope.
	client := tc.NewCommonClient(cred, tencentRegion(req.Region),
		tencentProfile(creds.Endpoint, tencentEndpointTAT, defaultTimeout))
	client.WithHttpTransport(p.h)

	sendReq := tchttp.NewCommonRequest(tencentTATService, tencentTATVersion, tencentRunCommandAction)
	sendReq.SetContext(ctx)
	if err := sendReq.SetActionParameters(map[string]interface{}{
		"Content":     base64.StdEncoding.EncodeToString([]byte(command)),
		"InstanceIds": []string{instance},
		"CommandType": "SHELL",
		"Timeout":     uint64(timeout),
	}); err != nil {
		return CommandResult{}, classifyTencent(err)
	}
	sendResp := tchttp.NewCommonResponse()
	if err := client.Send(sendReq, sendResp); err != nil {
		return CommandResult{}, classifyTencent(err)
	}
	var sent tencentRunCommandResult
	if err := json.Unmarshal(sendResp.GetBody(), &sent); err != nil {
		return CommandResult{}, newError(ReasonUpstream, ProviderTencent, "tat.RunCommand", err.Error(), "")
	}

	result := CommandResult{
		InstanceID: instance,
		CommandID:  sent.Response.CommandId,
		Status:     "pending",
	}
	invocationID := sent.Response.InvocationId
	for {
		task, terminal, err := p.tencentPollTask(ctx, client, invocationID, instance)
		if err != nil {
			return result, err
		}
		if task != nil {
			if s := strings.TrimSpace(task.TaskStatus); s != "" {
				result.Status = strings.ToLower(s)
			}
			if task.TaskResult != nil {
				if task.TaskResult.ExitCode != nil {
					result.ExitCode = int(*task.TaskResult.ExitCode)
				}
				// TaskResult.Output is Base64-encoded command output; decode it
				// (falling back to the raw value if it is not valid Base64).
				if raw := tencentString(task.TaskResult.Output); raw != "" {
					if decoded, derr := base64.StdEncoding.DecodeString(raw); derr == nil {
						result.Stdout = string(decoded)
					} else {
						result.Stdout = raw
					}
				}
			}
		}
		if terminal {
			return result, nil
		}
		if werr := waitFor(ctx, commandPollInterval); werr != nil {
			return result, classifyTencent(werr)
		}
	}
}

// tencentPollTask reads the invocation task for the instance (or invocation).
func (p *tencentProvider) tencentPollTask(ctx context.Context, client *tc.Client, invocationID, instance string) (*tencentInvocationTask, bool, error) {
	request := tchttp.NewCommonRequest(tencentTATService, tencentTATVersion, tencentDescribeInvocationTasksAction)
	request.SetContext(ctx)
	filterName, filterValue := "instance-id", instance
	if strings.TrimSpace(invocationID) != "" {
		filterName, filterValue = "invocation-id", invocationID
	}
	if err := request.SetActionParameters(map[string]interface{}{
		"HideOutput": false,
		"Limit":      uint64(50),
		"Filters": []map[string]interface{}{
			{"Name": filterName, "Values": []string{filterValue}},
		},
	}); err != nil {
		return nil, false, classifyTencent(err)
	}
	response := tchttp.NewCommonResponse()
	if err := client.Send(request, response); err != nil {
		return nil, false, classifyTencent(err)
	}
	var parsed tencentDescribeInvocationTasksResult
	if err := json.Unmarshal(response.GetBody(), &parsed); err != nil {
		return nil, false, newError(ReasonUpstream, ProviderTencent, "tat.DescribeInvocationTasks", err.Error(), "")
	}
	for i := range parsed.Response.InvocationTaskSet {
		task := &parsed.Response.InvocationTaskSet[i]
		if instance != "" && task.InstanceId != "" && !strings.EqualFold(task.InstanceId, instance) {
			continue
		}
		return task, tencentCommandTerminal(task.TaskStatus), nil
	}
	// The task is registered a moment after RunCommand; keep polling.
	return nil, false, nil
}

// tencentCommandTerminal reports whether a TAT task status is final.
func tencentCommandTerminal(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "SUCCESS", "FAILED", "TIMEOUT", "TASK_TIMEOUT", "CANCELLED", "TERMINATED", "DELIVER_FAILED", "START_FAILED":
		return true
	}
	return false
}

// TAT response shapes (parsed from the common client's generic body).
type tencentRunCommandResult struct {
	Response struct {
		InvocationId string `json:"InvocationId"`
		CommandId    string `json:"CommandId"`
		RequestId    string `json:"RequestId"`
	} `json:"Response"`
}

type tencentInvocationTask struct {
	InvocationId string `json:"InvocationId"`
	CommandId    string `json:"CommandId"`
	InstanceId   string `json:"InstanceId"`
	TaskStatus   string `json:"TaskStatus"`
	TaskResult   *struct {
		ExitCode *int64  `json:"ExitCode"`
		Output   *string `json:"Output"`
	} `json:"TaskResult"`
}

type tencentDescribeInvocationTasksResult struct {
	Response struct {
		TotalCount        int64                   `json:"TotalCount"`
		InvocationTaskSet []tencentInvocationTask `json:"InvocationTaskSet"`
		RequestId         string                  `json:"RequestId"`
	} `json:"Response"`
}

// ────────────────────────── Tencent error classification ──────────────────────────

// tencentReasons maps documented Tencent Cloud error codes onto the normalized
// reasons.
var tencentReasons = map[string]Reason{
	// Invalid credential.
	"AuthFailure.SignatureFailure": ReasonInvalidCredential,
	"AuthFailure.SecretIdNotFound": ReasonInvalidCredential,
	"AuthFailure.InvalidSecretId":  ReasonInvalidCredential,
	"AuthFailure.TokenFailure":     ReasonInvalidCredential,
	"AuthFailure.MFAFailure":       ReasonInvalidCredential,
	"InvalidCredential":            ReasonInvalidCredential,
	// Permission denied.
	"UnauthorizedOperation":                  ReasonPermissionDenied,
	"UnauthorizedOperation.PermissionDenied": ReasonPermissionDenied,
	"AccessDenied":                           ReasonPermissionDenied,
	"AuthFailure.UnauthorizedOperation":      ReasonPermissionDenied,
	// Region invalid.
	"InvalidRegion":                ReasonRegionInvalid,
	"InvalidRegion.NotFound":       ReasonRegionInvalid,
	"InvalidParameterValue.Region": ReasonRegionInvalid,
	// Instance not running.
	"InvalidInstanceState":                    ReasonInstanceNotRunning,
	"UnsupportedOperation.InstanceNotRunning": ReasonInstanceNotRunning,
	"OperationDenied.InstanceStatus":          ReasonInstanceNotRunning,
	// Not found.
	"InvalidInstanceId.NotFound":                ReasonNotFound,
	"ResourceNotFound":                          ReasonNotFound,
	"NoSuchBucket":                              ReasonNotFound,
	"InvalidParameterValue.InstanceIdMalformed": ReasonNotFound,
	// Throttled.
	"RequestLimitExceeded":            ReasonThrottled,
	"LimitExceeded":                   ReasonThrottled,
	"FailedOperation.TooManyRequests": ReasonThrottled,
	// Timeout.
	"RequestTimeout":        ReasonTimeout,
	"InternalError.Timeout": ReasonTimeout,
	"ClientNetworkError":    ReasonTimeout,
	// Transport-level errors: a scope-denied / unavailable port surfaces here as a
	// wrapped error with no service code, so it falls through to the message
	// fallback below.
	"ClientError.HttpStatusCodeError": ReasonUpstream,
	"ClientError.NetworkError":        ReasonUpstream,
	"ClientError.ParseJsonError":      ReasonUpstream,
}

// tencentFallback catches undocumented variants of the same failures.
var tencentFallback = []matchRule{
	{"signature", ReasonInvalidCredential},
	{"secretid", ReasonInvalidCredential},
	{"secret key", ReasonInvalidCredential},
	{"credential", ReasonInvalidCredential},
	{"unauthorized", ReasonPermissionDenied},
	{"permission", ReasonPermissionDenied},
	{"denied", ReasonPermissionDenied},
	{"region", ReasonRegionInvalid},
	{"not running", ReasonInstanceNotRunning},
	{"instance state", ReasonInstanceNotRunning},
	{"instance status", ReasonInstanceNotRunning},
	{"not found", ReasonNotFound},
	{"notfound", ReasonNotFound},
	{"no such", ReasonNotFound},
	{"limit exceeded", ReasonThrottled},
	{"too many requests", ReasonThrottled},
	{"throttl", ReasonThrottled},
	{"rate limit", ReasonThrottled},
	{"timeout", ReasonTimeout},
	{"timed out", ReasonTimeout},
	{"deadline exceeded", ReasonTimeout},
}

// classifyTencent turns an SDK error into a normalized error. A *core.Error
// raised by the host's own gates (scope denial, rate limit, timeout, unavailable)
// passes through verbatim: re-classifying it as a vendor failure would hide the
// gate's code from the agent.
func classifyTencent(err error) error {
	if err == nil {
		return nil
	}
	if ce := asCapkitError(err); ce != nil {
		return ce
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return newError(ReasonTimeout, ProviderTencent, "context", err.Error(), "")
	}
	code, message := "", err.Error()
	// The SDK wraps transport-level failures as ClientError.* but keeps the
	// original service error as the cause; walk the chain and prefer the most
	// specific (non-ClientError) code so "signature failure behind a network
	// wrapper" is still classified as a credential problem.
	for e := err; e != nil; e = errors.Unwrap(e) {
		sdkErr, ok := e.(*tcerr.TencentCloudSDKError)
		if !ok {
			continue
		}
		if code == "" {
			code, message = sdkErr.Code, sdkErr.Message
		}
		if !strings.HasPrefix(sdkErr.Code, "ClientError.") {
			code, message = sdkErr.Code, sdkErr.Message
			break
		}
	}
	return newError(reasonFor(code, message, tencentReasons, tencentFallback), ProviderTencent, code, message, "")
}

// ────────────────────────── small tencent helpers ──────────────────────────

func tencentString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func tencentStrings(ps []*string) []string {
	var out []string
	for _, p := range ps {
		if s := strings.TrimSpace(tencentString(p)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func tencentInt64Value(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func tencentUint64Value(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

func tencentInt64(v int64) *int64    { return &v }
func tencentUint64(v uint64) *uint64 { return &v }
