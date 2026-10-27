package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

const kitVersion = "0.1.0"

// Limits. Output that would exceed them is truncated and, for command output,
// recorded as evidence instead of travelling inline (docs §5.5.4).
const (
	// maxCommandOutput is the stdout ceiling returned in Data. Anything larger is
	// stored through the evidence port and referenced by id.
	maxCommandOutput = 4 << 10
	// defaultPageSize is the per-call item ceiling; list results paginate above
	// core.MaxListItems.
	defaultPageSize = core.MaxListItems
	// defaultTimeout bounds one cloud API call.
	defaultTimeout = 30 * time.Second
	// defaultCommandTimeout bounds one cloud-assistant command.
	defaultCommandTimeout = 120 * time.Second
)

// Kit is the cloud capability. It holds only ports: credentials arrive per call
// and are never retained.
type Kit struct {
	deps core.Deps
	http *httpDoerClient
	now  func() time.Time
}

// New builds the kit. A host wires core.Deps.HTTP; without it the tools report
// unavailable rather than dialing a vendor directly.
func New(deps core.Deps) *Kit {
	k := &Kit{deps: deps, http: newHTTPDoerClient(deps.HTTP, defaultTimeout)}
	k.now = time.Now
	if deps.Clock != nil {
		k.now = deps.Clock.Now
	}
	return k
}

// NewCapability is the registry constructor: it satisfies core.Spec.New.
func NewCapability(deps core.Deps) (core.Capability, error) { return New(deps), nil }

// Manifest exposes the read-only cloud surface plus the one high-risk
// cloud-assistant tool.
func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "cloudkit", Version: kitVersion, APIVersion: "v1",
		Requires: []string{"http"},
		Tools: []core.ToolSpec{
			{
				Name:        "cloud_ak_verify",
				Description: "对一组云 AK/SK 做最小化验证：只调厂商的 GetCallerIdentity 类接口，返回账号 ID、身份类型与 AK 脱敏标识。只读，不列举任何资源。",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "provider":{"type":"string","enum":["aliyun","tencent","aws","huawei"]},
    "access_key":{"type":"string"},
    "secret_key":{"type":"string"},
    "region":{"type":"string","description":"可选，默认厂商默认地域"},
    "endpoint":{"type":"string","description":"可选，覆盖厂商 endpoint"}
  },
  "required":["provider","access_key","secret_key"]
}`),
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"},"ak_masked":{"type":"string"},"valid":{"type":"boolean"},"account_id":{"type":"string"},"arn":{"type":"string"},"identity_type":{"type":"string"}}}`),
				Risk:         core.RiskLow,
			},
			{
				Name:        "cloud_asset_list",
				Description: "列举云上资产：ECS/CVM/EC2 计算实例与 RDS/CDB 数据库实例，按地域过滤、分页返回。只读。",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "provider":{"type":"string","enum":["aliyun","tencent","aws","huawei"]},
    "access_key":{"type":"string"},
    "secret_key":{"type":"string"},
    "region":{"type":"string"},
    "kinds":{"type":"array","items":{"type":"string","enum":["compute","database"]},"description":"默认两者都要"},
    "page_size":{"type":"integer","description":"默认 100"},
    "cursor":{"type":"string","description":"上一次返回的 page.cursor"},
    "endpoint":{"type":"string"}
  },
  "required":["provider","access_key","secret_key","region"]
}`),
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"},"region":{"type":"string"},"count":{"type":"integer"},"instances":{"type":"array","items":{"type":"object"}},"warnings":{"type":"array","items":{"type":"string"}}}}`),
				Risk:         core.RiskMedium,
			},
			{
				Name:        "cloud_iam_list",
				Description: "列举子用户、托管策略与 AccessKey 元数据（不返回密钥），用于提权面分析：标出疑似管理员权限的子用户。只读。",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "provider":{"type":"string","enum":["aliyun","tencent","aws","huawei"]},
    "access_key":{"type":"string"},
    "secret_key":{"type":"string"},
    "region":{"type":"string"},
    "include":{"type":"array","items":{"type":"string","enum":["users","policies","access_keys"]},"description":"默认三者都要"},
    "max_results":{"type":"integer","description":"每类最多返回多少条，默认 100"},
    "cursor":{"type":"string"},
    "endpoint":{"type":"string"}
  },
  "required":["provider","access_key","secret_key"]
}`),
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"},"count":{"type":"integer"},"users":{"type":"array","items":{"type":"object"}},"policies":{"type":"array","items":{"type":"object"}},"access_keys":{"type":"array","items":{"type":"object"}},"warnings":{"type":"array","items":{"type":"string"}}}}`),
				Risk:         core.RiskMedium,
			},
			{
				Name:        "cloud_run_command",
				Description: "通过厂商云助手在指定实例上执行一条命令（阿里 RunCommand / 腾讯 RunCommand / AWS SSM SendCommand / 华为 ECS 云助手），返回命令 ID、执行状态与 stdout（≤4KB，超出转证据引用）。高危：需审批门禁。",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "provider":{"type":"string","enum":["aliyun","tencent","aws","huawei"]},
    "access_key":{"type":"string"},
    "secret_key":{"type":"string"},
    "region":{"type":"string"},
    "instance_id":{"type":"string"},
    "command":{"type":"string"},
    "timeout_sec":{"type":"integer","description":"默认 120"},
    "endpoint":{"type":"string"}
  },
  "required":["provider","access_key","secret_key","instance_id","command"]
}`),
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"},"instance_id":{"type":"string"},"command_id":{"type":"string"},"status":{"type":"string"},"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stdout_bytes":{"type":"integer"},"truncated":{"type":"boolean"},"evidence_id":{"type":"string"}}}`),
				Risk:         core.RiskHigh,
				RateLimit:    core.RateLimitSpec{PerSecond: 1, Burst: 2, Concurrency: 2},
				// A command runs against one instance: declare it so the runtime
				// scope-checks the instance before the kit is called.
				ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
					var in struct {
						InstanceID string `json:"instance_id"`
					}
					if err := json.Unmarshal(input, &in); err != nil {
						return nil, err
					}
					if strings.TrimSpace(in.InstanceID) == "" {
						return nil, nil
					}
					return []core.Target{{Kind: core.TargetHost, Host: strings.ToLower(in.InstanceID)}}, nil
				},
			},
			{
				Name:        "cloud_storage_list",
				Description: "列举对象存储桶（OSS/COS/S3/OBS）；给出 bucket 时改为列举该桶下的对象元数据（可带 prefix），不下载对象内容。只读。",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "provider":{"type":"string","enum":["aliyun","tencent","aws","huawei"]},
    "access_key":{"type":"string"},
    "secret_key":{"type":"string"},
    "region":{"type":"string"},
    "bucket":{"type":"string","description":"可选：给出则列举桶内对象"},
    "prefix":{"type":"string"},
    "page_size":{"type":"integer","description":"默认 100"},
    "cursor":{"type":"string"},
    "endpoint":{"type":"string"}
  },
  "required":["provider","access_key","secret_key"]
}`),
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"},"count":{"type":"integer"},"buckets":{"type":"array","items":{"type":"object"}},"objects":{"type":"array","items":{"type":"object"}},"warnings":{"type":"array","items":{"type":"string"}}}}`),
				Risk:         core.RiskMedium,
			},
		},
	}
}

// Call routes one tool invocation and stamps the envelope.
func (k *Kit) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := k.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

func (k *Kit) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "cloud_ak_verify":
		return k.verify(ctx, call), nil
	case "cloud_asset_list":
		return k.listAssets(ctx, call), nil
	case "cloud_iam_list":
		return k.listIAM(ctx, call), nil
	case "cloud_run_command":
		return k.runCommand(ctx, call), nil
	case "cloud_storage_list":
		return k.listStorage(ctx, call), nil
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

// callInput is the union of the five tools' inputs. Keeping one struct means one
// place validates the shared provider/credential fields.
type callInput struct {
	Provider   string   `json:"provider"`
	AccessKey  string   `json:"access_key"`
	SecretKey  string   `json:"secret_key"`
	Region     string   `json:"region"`
	Endpoint   string   `json:"endpoint"`
	Kinds      []string `json:"kinds"`
	Include    []string `json:"include"`
	PageSize   int      `json:"page_size"`
	MaxResults int      `json:"max_results"`
	Cursor     string   `json:"cursor"`
	Bucket     string   `json:"bucket"`
	Prefix     string   `json:"prefix"`
	InstanceID string   `json:"instance_id"`
	Command    string   `json:"command"`
	TimeoutSec int      `json:"timeout_sec"`
}

func parseInput(raw json.RawMessage) (callInput, *core.Error) {
	var in callInput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return in, core.InvalidInput("输入不是合法 JSON: " + err.Error())
		}
	}
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	if err := requireAK(in.Provider, in.AccessKey, in.SecretKey); err != nil {
		return in, err
	}
	return in, nil
}

// creds projects the input into the provider-facing credential set.
func (in callInput) creds() Credentials {
	return Credentials{
		AccessKey: strings.TrimSpace(in.AccessKey),
		SecretKey: strings.TrimSpace(in.SecretKey),
		Region:    strings.TrimSpace(in.Region),
		Endpoint:  strings.TrimSpace(in.Endpoint),
	}
}

func (in callInput) pageSize() int {
	if in.PageSize <= 0 {
		return defaultPageSize
	}
	if in.PageSize > core.MaxListItems {
		return core.MaxListItems
	}
	return in.PageSize
}

// provider resolves the vendor implementation.
func (k *Kit) provider(name string) (Provider, *core.Error) {
	switch name {
	case ProviderAliyun:
		return newAliyunProvider(k.http), nil
	case ProviderTencent:
		return newTencentProvider(k.http), nil
	case ProviderAWS:
		return newAWSProvider(k.http), nil
	case ProviderHuawei:
		return newHuaweiProvider(k.http), nil
	case "":
		return nil, core.InvalidInput("provider 必填（aliyun/tencent/aws/huawei）")
	default:
		return nil, core.InvalidInput("不支持的云厂商: " + name + "（可选 aliyun/tencent/aws/huawei）")
	}
}

// open validates the shared fields and resolves the provider, so every handler
// starts from the same three checks.
func (k *Kit) open(call core.Call) (callInput, Provider, *core.Error) {
	in, err := parseInput(call.Input)
	if err != nil {
		return in, nil, err
	}
	if k.deps.HTTP == nil {
		return in, nil, core.Unavailable("cloudkit 未注入 HTTPDoer，云 API 调用无法通过门禁")
	}
	p, err := k.provider(in.Provider)
	if err != nil {
		return in, nil, err
	}
	return in, p, nil
}

// ────────────────────────── cloud_ak_verify ──────────────────────────

func (k *Kit) verify(ctx context.Context, call core.Call) core.Result {
	in, p, cerr := k.open(call)
	if cerr != nil {
		return core.FailResult(cerr)
	}
	masked := maskAK(in.AccessKey)
	id, err := p.Verify(ctx, in.creds())
	if err != nil {
		return k.failure(in.Provider, masked, err)
	}
	summary := fmt.Sprintf("验证 %s AK %s 有效，账号 %s", in.Provider, masked, orDash(id.AccountID))
	if id.Type != "" {
		summary += fmt.Sprintf("（身份 %s）", id.Type)
	}
	res, _ := core.SuccessResult(summary, map[string]any{
		"provider":      in.Provider,
		"ak_masked":     masked,
		"valid":         true,
		"account_id":    id.AccountID,
		"arn":           id.ARN,
		"identity_type": id.Type,
		"alias":         id.Alias,
	})
	res.Next = []core.NextStep{
		{Tool: "cloud_asset_list", Reason: "凭据有效，可只读列举该账号资产", Risk: core.RiskMedium,
			Preconditions: []string{"凭据具备只读列举权限"}},
		{Tool: "cloud_iam_list", Reason: "分析子用户与策略，评估提权面", Risk: core.RiskMedium},
	}
	return res
}

// ────────────────────────── cloud_asset_list ──────────────────────────

func (k *Kit) listAssets(ctx context.Context, call core.Call) core.Result {
	in, p, cerr := k.open(call)
	if cerr != nil {
		return core.FailResult(cerr)
	}
	if strings.TrimSpace(in.Region) == "" {
		return core.FailResult(invalidInput(in.Provider, "region 必填（云实例列表按地域查询）"))
	}
	masked := maskAK(in.AccessKey)
	page, err := p.ListAssets(ctx, in.creds(), AssetRequest{
		Kinds:    normalizeKinds(in.Kinds),
		Region:   strings.TrimSpace(in.Region),
		PageSize: in.pageSize(),
		Cursor:   strings.TrimSpace(in.Cursor),
	})
	if err != nil {
		return k.failure(in.Provider, masked, err)
	}
	compute, database := 0, 0
	for _, inst := range page.Instances {
		if inst.Kind == AssetDatabase {
			database++
			continue
		}
		compute++
	}
	summary := fmt.Sprintf("列举 %s %s 的资产：计算实例 %d 台、数据库 %d 个，共 %d 项",
		in.Provider, in.Region, compute, database, len(page.Instances))
	if len(page.Warnings) > 0 {
		summary += "；" + strings.Join(page.Warnings, "；")
	}
	res, _ := core.SuccessResult(summary, map[string]any{
		"provider":  in.Provider,
		"region":    in.Region,
		"count":     len(page.Instances),
		"instances": page.Instances,
		"warnings":  page.Warnings,
	})
	res.Page = pageOf(page.Total, page.Cursor, page.HasMore)
	if len(page.Instances) == 0 {
		res.Summary = core.ClampSummary(fmt.Sprintf("%s %s 未发现计算或数据库实例", in.Provider, in.Region))
	}
	if len(page.Warnings) > 0 && len(page.Instances) > 0 {
		res.Status = core.StatusPartial
		res.OK = true
	}
	res.Next = []core.NextStep{
		{Tool: "cloud_storage_list", Reason: "继续列举对象存储桶", Risk: core.RiskMedium},
		{Tool: "cloud_iam_list", Reason: "列举子用户与策略，评估提权面", Risk: core.RiskMedium},
	}
	return res
}

// ────────────────────────── cloud_iam_list ──────────────────────────

func (k *Kit) listIAM(ctx context.Context, call core.Call) core.Result {
	in, p, cerr := k.open(call)
	if cerr != nil {
		return core.FailResult(cerr)
	}
	masked := maskAK(in.AccessKey)
	page, err := p.ListIAM(ctx, in.creds(), IAMRequest{
		Include:    normalizeInclude(in.Include),
		MaxResults: in.maxResults(),
		Cursor:     strings.TrimSpace(in.Cursor),
	})
	if err != nil {
		return k.failure(in.Provider, masked, err)
	}
	admins := 0
	for _, u := range page.Users {
		if u.AdminHint != "" {
			admins++
		}
	}
	summary := fmt.Sprintf("列举 %s IAM：子用户 %d 个、策略 %d 条、AccessKey %d 个",
		in.Provider, len(page.Users), len(page.Policies), len(page.AccessKeys))
	if admins > 0 {
		summary += fmt.Sprintf("，其中 %d 个子用户疑似管理员权限", admins)
	} else if page.Users != nil {
		summary += "，未发现直连管理员策略的子用户"
	}
	if len(page.Warnings) > 0 {
		summary += "；" + strings.Join(page.Warnings, "；")
	}
	res, _ := core.SuccessResult(summary, map[string]any{
		"provider":    in.Provider,
		"count":       len(page.Users) + len(page.Policies) + len(page.AccessKeys),
		"admin_users": admins,
		"users":       page.Users,
		"policies":    page.Policies,
		"access_keys": page.AccessKeys,
		"warnings":    page.Warnings,
	})
	res.Page = pageOf(page.Total, page.Cursor, page.HasMore)
	if len(page.Warnings) > 0 {
		res.Status = core.StatusPartial
		res.OK = true
	}
	if admins > 0 {
		res.Next = append(res.Next, core.NextStep{
			Tool: "cloud_run_command", Reason: "子用户持有管理员策略，可在实例上执行只读核查命令",
			Risk: core.RiskHigh, Preconditions: []string{"已获得审批", "目标实例在授权范围"},
		})
	}
	return res
}

// ────────────────────────── cloud_run_command ──────────────────────────

func (k *Kit) runCommand(ctx context.Context, call core.Call) core.Result {
	in, p, cerr := k.open(call)
	if cerr != nil {
		return core.FailResult(cerr)
	}
	instance := strings.TrimSpace(in.InstanceID)
	if instance == "" {
		return core.FailResult(invalidInput(in.Provider, "instance_id 必填"))
	}
	command := strings.TrimSpace(in.Command)
	if command == "" {
		return core.FailResult(invalidInput(in.Provider, "command 必填"))
	}
	masked := maskAK(in.AccessKey)
	timeout := defaultCommandTimeout
	if in.TimeoutSec > 0 {
		timeout = time.Duration(in.TimeoutSec) * time.Second
	}
	out, err := p.RunCommand(ctx, in.creds(), CommandRequest{
		InstanceID: instance,
		Command:    command,
		TimeoutSec: int(timeout / time.Second),
		Region:     strings.TrimSpace(in.Region),
	})
	if err != nil {
		return k.failure(in.Provider, masked, err)
	}
	stdout := out.Stdout
	stdoutBytes := len(stdout)
	truncated := out.Truncated || stdoutBytes > maxCommandOutput
	if stdoutBytes > maxCommandOutput {
		stdout = stdout[:maxCommandOutput]
	}
	data := map[string]any{
		"provider":     in.Provider,
		"instance_id":  instance,
		"command_id":   out.CommandID,
		"status":       out.Status,
		"exit_code":    out.ExitCode,
		"stdout":       stdout,
		"stdout_bytes": stdoutBytes,
		"truncated":    truncated,
		"ak_masked":    masked,
	}
	res, _ := core.SuccessResult(
		fmt.Sprintf("在 %s 实例 %s 执行云助手命令（command_id %s），状态 %s，退出码 %d，stdout %d 字节",
			in.Provider, instance, orDash(out.CommandID), orDash(out.Status), out.ExitCode, stdoutBytes),
		data)
	res.Truncated = truncated

	// The body of a command output belongs in the evidence store, not inline
	// (docs §5.5.4): record the full stdout and hand back a reference.
	if truncated && k.deps.Evidence != nil {
		id, rerr := k.deps.Evidence.Record(ctx, core.Evidence{
			Kind: "command_output", Title: "cloud_run_command " + in.Provider + " " + instance,
			Target:    core.Target{Kind: core.TargetHost, Host: strings.ToLower(instance)},
			Data:      mustJSON(map[string]any{"stdout": out.Stdout, "stderr": out.Stderr, "command": command}),
			Metadata:  map[string]string{"provider": in.Provider, "command_id": out.CommandID, "status": out.Status},
			CreatedAt: k.now(),
		})
		if rerr == nil && id != "" {
			res.Evidence = []core.EvidenceRef{{
				ID: id, Kind: "command_output", Size: len(out.Stdout),
				Preview: core.PreviewRunes(out.Stdout, 200),
			}}
			data["evidence_id"] = id
			res.Data, _ = json.Marshal(data)
		}
	}
	return res
}

// ────────────────────────── cloud_storage_list ──────────────────────────

func (k *Kit) listStorage(ctx context.Context, call core.Call) core.Result {
	in, p, cerr := k.open(call)
	if cerr != nil {
		return core.FailResult(cerr)
	}
	masked := maskAK(in.AccessKey)
	bucket := strings.TrimSpace(in.Bucket)
	page, err := p.ListStorage(ctx, in.creds(), StorageRequest{
		Bucket:     bucket,
		Prefix:     strings.TrimSpace(in.Prefix),
		MaxResults: in.pageSize(),
		Cursor:     strings.TrimSpace(in.Cursor),
	})
	if err != nil {
		return k.failure(in.Provider, masked, err)
	}
	count := len(page.Buckets)
	var summary string
	if bucket != "" {
		count = len(page.Objects)
		summary = fmt.Sprintf("列举存储桶 %s（%s）下 %d 个对象", bucket, in.Provider, count)
		if in.Prefix != "" {
			summary += fmt.Sprintf("，前缀 %s", in.Prefix)
		}
	} else {
		summary = fmt.Sprintf("列举 %s 的对象存储桶 %d 个", in.Provider, count)
	}
	if len(page.Warnings) > 0 {
		summary += "；" + strings.Join(page.Warnings, "；")
	}
	res, _ := core.SuccessResult(summary, map[string]any{
		"provider": in.Provider,
		"count":    count,
		"buckets":  page.Buckets,
		"objects":  page.Objects,
		"warnings": page.Warnings,
	})
	res.Page = pageOf(page.Total, page.Cursor, page.HasMore)
	if len(page.Warnings) > 0 {
		res.Status = core.StatusPartial
		res.OK = true
	}
	return res
}

// ────────────────────────── shared helpers ──────────────────────────

// failure converts a provider error into an envelope. A capkit error raised by
// the host's own gates (blocked / timeout / rate_limited) keeps its code; only
// genuine vendor failures are classified.
func (k *Kit) failure(provider, masked string, err error) core.Result {
	if ce := asCapkitError(err); ce != nil {
		return core.FailResult(ce)
	}
	return describe(provider, masked, err).AsResult()
}

func normalizeKinds(kinds []string) []string {
	if len(kinds) == 0 {
		return []string{AssetCompute, AssetDatabase}
	}
	var out []string
	seen := map[string]bool{}
	for _, kind := range kinds {
		k := strings.ToLower(strings.TrimSpace(kind))
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	if len(out) == 0 {
		return []string{AssetCompute, AssetDatabase}
	}
	return out
}

func normalizeInclude(include []string) []string {
	if len(include) == 0 {
		return []string{"users", "policies", "access_keys"}
	}
	var out []string
	seen := map[string]bool{}
	for _, item := range include {
		i := strings.ToLower(strings.TrimSpace(item))
		if i == "" || seen[i] {
			continue
		}
		seen[i] = true
		out = append(out, i)
	}
	if len(out) == 0 {
		return []string{"users", "policies", "access_keys"}
	}
	return out
}

func (in callInput) maxResults() int {
	if in.MaxResults <= 0 {
		return defaultPageSize
	}
	if in.MaxResults > core.MaxListItems {
		return core.MaxListItems
	}
	return in.MaxResults
}

// pageOf builds the pagination block shared by the list tools.
func pageOf(total int, cursor string, hasMore bool) *core.Page {
	if total == 0 && cursor == "" && !hasMore {
		return nil
	}
	return &core.Page{Total: total, Cursor: cursor, HasMore: hasMore}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
