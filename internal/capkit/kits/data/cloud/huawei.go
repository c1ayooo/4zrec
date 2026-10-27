package cloud

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	hcRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/region"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	ecsModel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	iamModel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	rds "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3"
	rdsModel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3/model"
	sts "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1"
	stsModel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/model"
)

// huaweiProvider talks to Huawei Cloud through huaweicloud-sdk-go-v3. Signing
// (SDK-HMAC-SHA256), endpoint/paging and retry are entirely the SDK's: this file
// wires the caller's credential plus the host's HTTPDoer and maps responses.
//
// Two Huawei-specific facts shape this file:
//
//  1. Region-scoped services (ECS/RDS) carry {project_id} in the request path.
//     The SDK fills it from the credential's ProjectId, and when that is unset
//     it resolves the account's project for the region itself (an IAM
//     KeystoneListProjects call, also signed by the SDK and also routed through
//     the injected HTTPDoer). We therefore build those clients WithRegion rather
//     than WithEndpoint and let the SDK own the project lookup. Global services
//     (STS/IAM) have no {project_id} and are built WithEndpoint so no needless
//     project lookup happens.
//  2. The object-storage and cloud-assistant APIs are not part of this SDK, so
//     those two methods report unsupported with the reason rather than
//     fabricating a call (see ListStorage / RunCommand).
type huaweiProvider struct{ h *httpDoerClient }

func newHuaweiProvider(h *httpDoerClient) Provider { return &huaweiProvider{h: h} }

func (p *huaweiProvider) Name() string { return ProviderHuawei }

// huaweiDefaultRegion is used when the caller named none: Huawei endpoints are
// fully regional, so a project lookup needs a region to key on.
const huaweiDefaultRegion = "cn-north-4"

// huaweiRegion picks the effective region: the request's own region (RDS/ECS
// listing carries one) first, then the credential's, then the default.
func huaweiRegion(creds Credentials, override string) string {
	if r := strings.TrimSpace(override); r != "" {
		return r
	}
	if r := strings.TrimSpace(creds.Region); r != "" {
		return r
	}
	return huaweiDefaultRegion
}

// huaweiEndpoint returns the service host for one product. Credentials.Endpoint
// (sovereign cloud, private endpoint, or a test double's host) wins, so a
// request never needs the SDK's remote endpoint resolver.
func huaweiEndpoint(creds Credentials, product string) string {
	if ep := strings.TrimSpace(creds.Endpoint); ep != "" {
		return ep
	}
	region := huaweiRegion(creds, "")
	switch product {
	case "sts":
		return "https://sts." + region + ".myhuaweicloud.com"
	case "iam":
		return "https://iam." + region + ".myhuaweicloud.com"
	case "ecs":
		return "https://ecs." + region + ".myhuaweicloud.com"
	case "rds":
		return "https://rds." + region + ".myhuaweicloud.com"
	}
	return ""
}

// huaweiCredential builds the SDK credential from the caller's AK/SK only. It
// deliberately never falls back to a default credential chain: that would read
// environment variables and shared config files, and a cloud tool must never
// pick up ambient credentials the caller did not pass.
func (p *huaweiProvider) huaweiCredential(creds Credentials) (*basic.Credentials, error) {
	ak := strings.TrimSpace(creds.AccessKey)
	sk := strings.TrimSpace(creds.SecretKey)
	if ak == "" || sk == "" {
		return nil, newError(ReasonInvalidCredential, ProviderHuawei, "MissingCredential",
			"access_key/secret_key 必填", maskAK(ak))
	}
	cred, err := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).SafeBuild()
	if err != nil {
		return nil, classifyHuawei(err)
	}
	return cred, nil
}

// huaweiHTTP is the shared SDK HTTP config. Its RoundTripper is the injected
// core.HTTPDoer, so every SDK request (including the SDK's own project-id
// lookup) passes the host's scope check, rate limit and audit. Retries are
// pinned to one attempt: the host's limiter already owns retry policy, and a
// silent SDK retry would multiply what Meta.Requests reports.
func (p *huaweiProvider) huaweiHTTP() *config.HttpConfig {
	return config.DefaultHttpConfig().
		WithTimeout(defaultTimeout).
		WithRetries(0).
		WithHttpRoundTripper(p.h)
}

// ────────────────────────── cloud_ak_verify ──────────────────────────

func (p *huaweiProvider) Verify(ctx context.Context, creds Credentials) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, classifyHuawei(err)
	}
	cred, cerr := p.huaweiCredential(creds)
	if cerr != nil {
		return Identity{}, cerr
	}
	// STS is a global service (path /v5/caller-identity): no project_id, so the
	// client is built WithEndpoint and no project lookup is triggered.
	hcClient, err := sts.StsClientBuilder().
		WithCredential(cred).
		WithEndpoint(huaweiEndpoint(creds, "sts")).
		WithHttpConfig(p.huaweiHTTP()).
		SafeBuild()
	if err != nil {
		return Identity{}, classifyHuawei(err)
	}
	out, err := sts.NewStsClient(hcClient).GetCallerIdentity(&stsModel.GetCallerIdentityRequest{})
	if err != nil {
		return Identity{}, classifyHuawei(err)
	}
	if out == nil {
		return Identity{}, newError(ReasonUpstream, ProviderHuawei, "sts.GetCallerIdentity", "空响应", "")
	}
	urn := huaweiString(out.PrincipalUrn)
	return Identity{
		AccountID: huaweiString(out.AccountId),
		ARN:       urn,
		Type:      huaweiIdentityType(urn),
		Alias:     huaweiString(out.PrincipalId),
	}, nil
}

// huaweiIdentityType reads the principal kind out of the URN
// (iam::<account-id>:user/<name>, iam::<account-id>:root, ...), so the agent can
// tell a root account AK from a scoped IAM user.
func huaweiIdentityType(urn string) string {
	parts := strings.Split(urn, ":")
	if len(parts) < 4 {
		return ""
	}
	resource := parts[len(parts)-1]
	switch {
	case resource == "root":
		return "root_account"
	case strings.HasPrefix(resource, "user/"):
		return "iam_user"
	case strings.HasPrefix(resource, "agency/"):
		return "agency"
	case strings.HasPrefix(resource, "group/"):
		return "iam_group"
	default:
		return resource
	}
}

// ────────────────────────── cloud_asset_list ──────────────────────────

func (p *huaweiProvider) ListAssets(ctx context.Context, creds Credentials, req AssetRequest) (AssetPage, error) {
	if err := ctx.Err(); err != nil {
		return AssetPage{}, classifyHuawei(err)
	}
	cred, cerr := p.huaweiCredential(creds)
	if cerr != nil {
		return AssetPage{}, cerr
	}
	region := huaweiRegion(creds, req.Region)
	offset := huaweiCursorOffset(req.Cursor)
	limit := huaweiPageLimit(req.PageSize)

	var out AssetPage
	var errs []error
	attempted, failed := 0, 0
	for _, kind := range req.Kinds {
		switch kind {
		case AssetCompute:
			attempted++
			instances, total, err := p.huaweiECS(ctx, cred, creds, region, offset, limit)
			if err != nil {
				failed++
				errs = append(errs, err)
				out.Warnings = append(out.Warnings, "ECS 列举失败："+reasonLabel(err))
				continue
			}
			out.Instances = append(out.Instances, instances...)
			huaweiAdvanceCursor(&out, offset, len(instances), total)
		case AssetDatabase:
			attempted++
			instances, total, err := p.huaweiRDS(ctx, cred, creds, region, offset, limit)
			if err != nil {
				failed++
				errs = append(errs, err)
				out.Warnings = append(out.Warnings, "RDS 列举失败："+reasonLabel(err))
				continue
			}
			out.Instances = append(out.Instances, instances...)
			huaweiAdvanceCursor(&out, offset, len(instances), total)
		default:
			out.Warnings = append(out.Warnings, "跳过不支持的资产类型："+kind)
		}
	}
	// Only when every kind we attempted failed (and nothing came back) is the
	// whole call a failure; the underlying classified reason is preserved so the
	// agent still sees invalid_credential / permission_denied / region_invalid.
	if attempted > 0 && failed == attempted && len(out.Instances) == 0 {
		return out, errs[0]
	}
	out.Total = len(out.Instances)
	return out, nil
}

func (p *huaweiProvider) huaweiECS(ctx context.Context, cred *basic.Credentials, creds Credentials, region string, offset, limit int) ([]Instance, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, classifyHuawei(err)
	}
	// WithRegion makes the SDK resolve (and cache) the account's project for the
	// region — an IAM call through the injected doer — and fill {project_id} in
	// the path. The endpoint override rides along as the region's only endpoint.
	hcClient, err := ecs.EcsClientBuilder().
		WithCredential(cred).
		WithRegion(hcRegion.NewRegion(region, huaweiEndpoint(creds, "ecs"))).
		WithHttpConfig(p.huaweiHTTP()).
		SafeBuild()
	if err != nil {
		return nil, 0, classifyHuawei(err)
	}
	out, err := ecs.NewEcsClient(hcClient).ListServersDetails(&ecsModel.ListServersDetailsRequest{
		Offset: huaweiInt32(int32(offset)),
		Limit:  huaweiInt32(int32(limit)),
	})
	if err != nil {
		return nil, 0, classifyHuawei(err)
	}
	if out == nil {
		return nil, 0, newError(ReasonUpstream, ProviderHuawei, "ecs.ListServersDetails", "空响应", "")
	}
	var instances []Instance
	if out.Servers != nil {
		for _, srv := range *out.Servers {
			instances = append(instances, Instance{
				ID:        srv.Id,
				Name:      srv.Name,
				Kind:      AssetCompute,
				Status:    srv.Status,
				Type:      huaweiFlavorName(srv.Flavor),
				Region:    region,
				Zone:      srv.OSEXTAZavailabilityZone,
				PrivateIP: nonEmptyList(huaweiAddresses(srv.Addresses, false)),
				PublicIP:  nonEmptyList(huaweiAddresses(srv.Addresses, true)),
			})
		}
	}
	return instances, int(huaweiInt32Value(out.Count)), nil
}

func (p *huaweiProvider) huaweiRDS(ctx context.Context, cred *basic.Credentials, creds Credentials, region string, offset, limit int) ([]Instance, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, classifyHuawei(err)
	}
	if limit > huaweiRDSMaxPageSize {
		limit = huaweiRDSMaxPageSize
	}
	hcClient, err := rds.RdsClientBuilder().
		WithCredential(cred).
		WithRegion(hcRegion.NewRegion(region, huaweiEndpoint(creds, "rds"))).
		WithHttpConfig(p.huaweiHTTP()).
		SafeBuild()
	if err != nil {
		return nil, 0, classifyHuawei(err)
	}
	out, err := rds.NewRdsClient(hcClient).ListInstances(&rdsModel.ListInstancesRequest{
		Offset: huaweiInt32(int32(offset)),
		Limit:  huaweiInt32(int32(limit)),
	})
	if err != nil {
		return nil, 0, classifyHuawei(err)
	}
	if out == nil {
		return nil, 0, newError(ReasonUpstream, ProviderHuawei, "rds.ListInstances", "空响应", "")
	}
	var instances []Instance
	if out.Instances != nil {
		for _, db := range *out.Instances {
			inst := Instance{
				ID:        db.Id,
				Name:      db.Name,
				Kind:      AssetDatabase,
				Status:    db.Status,
				Type:      db.Type,
				Region:    region,
				PrivateIP: nonEmptyList(db.PrivateIps),
				PublicIP:  nonEmptyList(db.PublicIps),
			}
			if db.Datastore != nil {
				inst.Engine = db.Datastore.Type.Value()
				if v := db.Datastore.Version; v != "" {
					inst.Engine += " " + v
				}
			}
			instances = append(instances, inst)
		}
	}
	return instances, int(huaweiInt32Value(out.TotalCount)), nil
}

// huaweiRDSMaxPageSize is RDS ListInstances' documented limit ceiling.
const huaweiRDSMaxPageSize = 100

// huaweiAddresses picks the fixed (private) or floating (public) addresses out
// of an ECS server's per-network address map. Network names are sorted so the
// returned order is deterministic instead of following Go's map iteration.
func huaweiAddresses(addrs map[string][]ecsModel.ServerAddress, floating bool) []string {
	names := make([]string, 0, len(addrs))
	for name := range addrs {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []string
	for _, name := range names {
		for _, a := range addrs[name] {
			isFloating := a.OSEXTIPStype != nil && a.OSEXTIPStype.Value() == "floating"
			if isFloating == floating && strings.TrimSpace(a.Addr) != "" {
				out = append(out, a.Addr)
			}
		}
	}
	return out
}

// huaweiFlavorName maps ECS's flavor into Instance.Type, preferring the flavor
// id (the brief's Flavor.ID) and falling back to the display name.
func huaweiFlavorName(flavor *ecsModel.ServerFlavor) string {
	if flavor == nil {
		return ""
	}
	if flavor.Id != "" {
		return flavor.Id
	}
	return flavor.Name
}

// huaweiAdvanceCursor turns an offset page into a next-cursor when the vendor
// reported more rows than came back.
func huaweiAdvanceCursor(page *AssetPage, offset, got, total int) {
	if total > 0 && offset+got < total {
		page.Cursor = strconv.Itoa(offset + got)
		page.HasMore = true
	}
}

// huaweiCursorOffset reads the numeric cursor; a non-numeric cursor is treated
// as the first page (0).
func huaweiCursorOffset(cursor string) int {
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

func huaweiPageLimit(pageSize int) int { return clampMax(pageSize) }

// ────────────────────────── cloud_iam_list ──────────────────────────

// huaweiIAMMaxPageSize bounds each IAM list so one call cannot pull an entire
// enterprise account.
const huaweiIAMMaxPageSize = 300

func (p *huaweiProvider) ListIAM(ctx context.Context, creds Credentials, req IAMRequest) (IAMPage, error) {
	if err := ctx.Err(); err != nil {
		return IAMPage{}, classifyHuawei(err)
	}
	cred, cerr := p.huaweiCredential(creds)
	if cerr != nil {
		return IAMPage{}, cerr
	}
	// IAM v3 Keystone endpoints (/v3/users, /v3/roles, /v3.0/OS-CREDENTIAL/...)
	// are not project-scoped, so no region/project lookup is needed.
	hcClient, err := iam.IamClientBuilder().
		WithCredential(cred).
		WithEndpoint(huaweiEndpoint(creds, "iam")).
		WithHttpConfig(p.huaweiHTTP()).
		SafeBuild()
	if err != nil {
		return IAMPage{}, classifyHuawei(err)
	}
	client := iam.NewIamClient(hcClient)
	max := req.MaxResults
	if max <= 0 {
		max = defaultPageSize
	}

	var page IAMPage
	userDomainID := ""
	var errs []error
	attempted, failed := 0, 0
	for _, include := range req.Include {
		switch include {
		case "users":
			attempted++
			out, err := client.KeystoneListUsers(&iamModel.KeystoneListUsersRequest{
				Enabled: huaweiBool(true),
			})
			if err != nil {
				failed++
				errs = append(errs, classifyHuawei(err))
				page.Warnings = append(page.Warnings, "子用户列举失败："+reasonLabel(classifyHuawei(err)))
				continue
			}
			if out != nil && out.Users != nil {
				for _, u := range *out.Users {
					page.Users = append(page.Users, IAMUser{Name: u.Name, ID: u.Id})
					if userDomainID == "" {
						userDomainID = u.DomainId
					}
				}
			}
		case "policies":
			attempted++
			out, err := client.KeystoneListPermissions(&iamModel.KeystoneListPermissionsRequest{
				PerPage: huaweiInt32(int32(huaweiIAMMaxPageSize)),
			})
			if err != nil {
				failed++
				errs = append(errs, classifyHuawei(err))
				page.Warnings = append(page.Warnings, "策略列举失败："+reasonLabel(classifyHuawei(err)))
				continue
			}
			if out != nil && out.Roles != nil {
				for _, role := range *out.Roles {
					name := huaweiString(role.DisplayName)
					if name == "" {
						name = role.Name
					}
					page.Policies = append(page.Policies, IAMPolicy{
						Name:        name,
						ID:          role.Id,
						Description: strings.TrimSpace(huaweiString(role.Description)),
						Admin:       huaweiAdminish(name) || huaweiAdminish(role.Name),
					})
				}
			}
		case "access_keys":
			attempted++
			out, err := client.ListPermanentAccessKeys(&iamModel.ListPermanentAccessKeysRequest{})
			if err != nil {
				failed++
				errs = append(errs, classifyHuawei(err))
				page.Warnings = append(page.Warnings, "AccessKey 列举失败："+reasonLabel(classifyHuawei(err)))
				continue
			}
			if out != nil && out.Credentials != nil {
				for _, key := range *out.Credentials {
					page.AccessKeys = append(page.AccessKeys, AccessKey{
						User:      key.UserId,
						ID:        key.Access,
						Status:    key.Status,
						CreatedAt: key.CreateTime,
					})
				}
			}
		default:
			page.Warnings = append(page.Warnings, "跳过不支持的 IAM 类别："+include)
		}
	}
	// Huawei attaches permissions to user groups rather than to users directly,
	// so the admin hint walks KeystoneListGroupsForUser → each group's
	// domain-level roles (KeystoneListDomainPermissionsForGroup). Both are
	// read-only. Bounded by maxAdminProbe users and maxAdminGroups per user so a
	// large account cannot turn one tool call into hundreds of requests.
	// KeystoneListUsers is both the user list and (here) the account id the
	// group-role lookup needs as a path param. Reuse what the "users" branch
	// already fetched when that branch ran; otherwise fetch once, ignoring a
	// failure — the admin hint is best-effort and never fails the call.
	domainID := userDomainID
	if domainID == "" {
		if out, uerr := client.KeystoneListUsers(&iamModel.KeystoneListUsersRequest{
			Enabled: huaweiBool(true),
		}); uerr == nil && out != nil && out.Users != nil && len(*out.Users) > 0 {
			domainID = (*out.Users)[0].DomainId
		}
	}
	probed := len(page.Users)
	if probed > maxAdminProbe {
		probed = maxAdminProbe
	}
	for i := 0; i < probed; i++ {
		uid := page.Users[i].ID
		if uid == "" {
			continue
		}
		groups, err := client.KeystoneListGroupsForUser(&iamModel.KeystoneListGroupsForUserRequest{UserId: uid})
		if err != nil || groups == nil || groups.Groups == nil {
			continue
		}
		for gi, g := range *groups.Groups {
			if gi >= maxAdminGroups {
				break
			}
			roles, rerr := client.KeystoneListDomainPermissionsForGroup(&iamModel.KeystoneListDomainPermissionsForGroupRequest{
				DomainId: domainID,
				GroupId:  g.Id,
			})
			if rerr != nil || roles == nil || roles.Roles == nil {
				continue
			}
			for _, role := range *roles.Roles {
				name := huaweiString(role.DisplayName)
				if name == "" {
					name = role.Name
				}
				if huaweiAdminish(name) || huaweiAdminish(role.Name) {
					page.Users[i].AdminHint = name
					break
				}
			}
			if page.Users[i].AdminHint != "" {
				break
			}
		}
	}
	if len(page.Users) > max {
		page.Users = page.Users[:max]
	}
	if len(page.Policies) > max {
		page.Policies = page.Policies[:max]
	}
	if len(page.AccessKeys) > max {
		page.AccessKeys = page.AccessKeys[:max]
	}
	page.Total = len(page.Users) + len(page.Policies) + len(page.AccessKeys)
	// Only when every requested category failed is the whole call a failure; the
	// underlying classified reason is preserved (aliyun/tencent behave the same).
	if attempted > 0 && failed == attempted && page.Total == 0 {
		return page, errs[0]
	}
	return page, nil
}

// ────────────────────────── cloud_storage_list ──────────────────────────

func (p *huaweiProvider) ListStorage(context.Context, Credentials, StorageRequest) (StoragePage, error) {
	// OBS (object storage) is a separate SDK (huaweicloud-sdk-go-obs) that this
	// module does not depend on, and hand-rolling the OBS signature scheme would
	// break the "signing is the SDK's job" rule. Report the gap honestly.
	return StoragePage{}, unsupported(ProviderHuawei, "华为云对象存储列举需要 huaweicloud-sdk-go-obs，当前依赖未引入")
}

// ────────────────────────── cloud_run_command ──────────────────────────

func (p *huaweiProvider) RunCommand(context.Context, Credentials, CommandRequest) (CommandResult, error) {
	// huaweicloud-sdk-go-v3 v0.1.219's ECS service exposes no cloud-assistant
	// RunCommand/BatchRunCommands API (verified: no command method in the ECS
	// client), so there is nothing to call. Report unsupported, do not fabricate.
	return CommandResult{}, unsupported(ProviderHuawei, "huaweicloud-sdk-go-v3 v0.1.219 的 ECS 服务未暴露云助手 RunCommand API")
}

// ────────────────────────── Huawei error classification ──────────────────────────

// huaweiReasons maps documented Huawei error codes onto the normalized reasons.
// Huawei surfaces most failures as an apigw/iam code plus an HTTP status; the
// status table below catches the rest, and the prose fallback catches an
// undocumented code.
var huaweiReasons = map[string]Reason{
	"APIGW.0301": ReasonInvalidCredential, // authentication failed
	"APIGW.0302": ReasonPermissionDenied,  // the AK lacks permission
	"APIGW.0308": ReasonThrottled,         // rate limited by the gateway
	"APIGW.0303": ReasonRegionInvalid,
	"IAM.0005":   ReasonPermissionDenied,
	"IAM.0007":   ReasonNotFound,
	// ECS: the instance exists but cannot accept the request in its state.
	"Ecs.0100": ReasonInstanceNotRunning,
	"Ecs.0114": ReasonInstanceNotRunning,
	// RDS
	"DBS.0005": ReasonPermissionDenied,
	"DBS.0044": ReasonNotFound,
	"DBS.0039": ReasonRegionInvalid,
}

// maxAdminGroups bounds how many of a user's groups are inspected: the privesc
// surface is worth exposing, one call per group in a large account is not. The
// per-user bound is the shared maxAdminProbe (aws.go), reused so both providers
// probe the same number of sub-accounts.
const maxAdminGroups = 5

// huaweiStatusReason maps the HTTP status onto a reason. It is the fallback the
// brief calls out: Huawei surfaces an invalid AK/SK as 401, a scoped permission
// failure as 403, a missing resource as 404, throttling as 429, and any server
// fault as 5xx. A status outside this set (notably 400) falls through to the
// code/message table so its vendor code can still tell the cases apart.
func huaweiStatusReason(status int) (Reason, bool) {
	switch {
	case status == 401:
		return ReasonInvalidCredential, true
	case status == 403:
		return ReasonPermissionDenied, true
	case status == 404:
		return ReasonNotFound, true
	case status == 429:
		return ReasonThrottled, true
	case status >= 500 && status < 600:
		return ReasonUpstream, true
	default:
		return "", false
	}
}

// huaweiFallback catches the undocumented variants of the same failures. The
// state / not-found / region cases live here rather than in the code table
// because Huawei's per-service codes are not stable across services; the prose
// carries them reliably.
var huaweiFallback = []matchRule{
	{"signature", ReasonInvalidCredential},
	{"authentication", ReasonInvalidCredential},
	{"invalid ak", ReasonInvalidCredential},
	{"security token", ReasonInvalidCredential},
	{"token is expired", ReasonInvalidCredential},
	{"permission", ReasonPermissionDenied},
	{"not authorized", ReasonPermissionDenied},
	{"forbidden", ReasonPermissionDenied},
	{"denied", ReasonPermissionDenied},
	{"not found", ReasonNotFound},
	{"not exist", ReasonNotFound},
	{"does not exist", ReasonNotFound},
	{"throttl", ReasonThrottled},
	{"too many request", ReasonThrottled},
	{"rate limit", ReasonThrottled},
	{"rate exceeds", ReasonThrottled},
	{"quota exceeded", ReasonThrottled},
	{"deadline exceeded", ReasonTimeout},
	{"timed out", ReasonTimeout},
	{"timeout", ReasonTimeout},
	{"invalid region", ReasonRegionInvalid},
	{"region is not", ReasonRegionInvalid},
	{"not in a valid state", ReasonInstanceNotRunning},
	{"not in the running state", ReasonInstanceNotRunning},
	{"not running", ReasonInstanceNotRunning},
}

// classifyHuawei turns an SDK error into a normalized error. A capkit error from
// the host's own gates (scope denial, rate limit, timeout) passes through
// verbatim; a context deadline is a timeout; a *sdkerr.ServiceResponseError is
// classified by HTTP status first (Huawei's most reliable discriminator), then
// by vendor code and prose.
func classifyHuawei(err error) error {
	if err == nil {
		return nil
	}
	if ce := asCapkitError(err); ce != nil {
		return ce
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return newError(ReasonTimeout, ProviderHuawei, "context", err.Error(), "")
	}
	code, message := "", err.Error()
	var sre *sdkerr.ServiceResponseError
	if errors.As(err, &sre) {
		code, message = sre.ErrorCode, sre.ErrorMessage
		if message == "" {
			message = err.Error()
		}
		if r, ok := huaweiStatusReason(sre.StatusCode); ok {
			return newError(r, ProviderHuawei, code, message, "")
		}
	}
	return newError(reasonFor(code, message, huaweiReasons, huaweiFallback), ProviderHuawei, code, message, "")
}

// ────────────────────────── small shared helpers ──────────────────────────

func huaweiString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func huaweiInt32(v int32) *int32 { return &v }

func huaweiInt32Value(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}

func huaweiBool(v bool) *bool { return &v }

// huaweiAdminish extends the shared adminish heuristic with Huawei's naming: the
// built-in administrative role is plain "admin", and "Tenant Administrator" /
// "Server Administrator" carry a space that adminish's concatenated patterns
// ("administratoraccess", "fullaccess") would miss.
func huaweiAdminish(name string) bool {
	if adminish(name) {
		return true
	}
	n := strings.ToLower(strings.TrimSpace(name))
	return n == "admin" || strings.Contains(n, "administrator")
}

func nonEmptyList(v []string) []string {
	out := v[:0:0]
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
