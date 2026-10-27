// Package cloudkit is the cloud-asset capability: it uses a caller-supplied
// AK/SK to read the account's identity, instances, IAM surface and object
// storage, and to run a command through the vendor's cloud assistant.
//
// Two rules shape this package:
//
//  1. Signing is the vendor SDK's job. Each provider file wires an official Go
//     SDK (alibabacloud-go, tencentcloud-sdk-go, aws-sdk-go-v2,
//     huaweicloud-sdk-go-v3) and lets the SDK sign. Nothing here hand-rolls a
//     signature, so a vendor changing its scheme is a dependency bump, not a
//     silent breakage.
//  2. Every SDK request goes through the injected core.HTTPDoer, so the
//     host's scope check, rate limit and audit still apply. A host must allow
//     the vendor endpoints it wants reachable, otherwise the tool is blocked
//     like any other out-of-scope call.
//
// All tools are read-only except cloud_run_command, which is risk=high and
// therefore requires the runtime's approval gate. Nothing here deletes or
// mutates a cloud resource: no instance termination, no object deletion, no
// IAM policy write, no AccessKey creation.
package cloud

import "context"

// Providers supported by this kit. huawei is present because the SDK injects
// cleanly; the tool surface is identical across providers.
const (
	ProviderAliyun  = "aliyun"
	ProviderTencent = "tencent"
	ProviderAWS     = "aws"
	ProviderHuawei  = "huawei"
)

// Providers lists the supported vendors, for the manifest and for validation.
var Providers = []string{ProviderAliyun, ProviderTencent, ProviderAWS, ProviderHuawei}

// Asset kinds for cloud_asset_list.
const (
	AssetCompute  = "compute"  // ECS / CVM / EC2
	AssetDatabase = "database" // RDS / CDB
)

// Credentials is one AK/SK pair plus its scope. It is built from the tool input
// on every call and never stored: no kit state, no disk, no log line.
type Credentials struct {
	AccessKey string
	SecretKey string
	Region    string
	// Endpoint optionally overrides the vendor endpoint (sovereign cloud,
	// private endpoint, or a test double's host).
	Endpoint string
}

// Identity is the caller a credential belongs to, as reported by the vendor.
type Identity struct {
	AccountID string `json:"account_id,omitempty"`
	ARN       string `json:"arn,omitempty"`
	Type      string `json:"type,omitempty"` // root_account | ram_user | iam_user | assumed_role | federated_user | ...
	Alias     string `json:"alias,omitempty"`
}

// Instance is one compute or database asset, normalized across vendors.
type Instance struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Kind      string   `json:"kind"` // compute | database
	Status    string   `json:"status,omitempty"`
	Type      string   `json:"type,omitempty"`
	Region    string   `json:"region,omitempty"`
	Zone      string   `json:"zone,omitempty"`
	PrivateIP []string `json:"private_ips,omitempty"`
	PublicIP  []string `json:"public_ips,omitempty"`
	Engine    string   `json:"engine,omitempty"` // database engine/version
}

// IAMUser is one sub-account.
type IAMUser struct {
	Name      string `json:"name"`
	ID        string `json:"id,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	// AdminHint is set when a directly attached policy looks like full
	// administrative access — the privesc surface an operator cares about.
	AdminHint string `json:"admin_hint,omitempty"`
}

// IAMPolicy is one managed policy and how widely it is attached.
type IAMPolicy struct {
	Name        string `json:"name"`
	ID          string `json:"id,omitempty"`
	Description string `json:"description,omitempty"`
	Attachments int    `json:"attachments"`
	Admin       bool   `json:"admin,omitempty"`
}

// AccessKey is one access key belonging to a sub-account. It is metadata only:
// the secret is never returned by any vendor API.
type AccessKey struct {
	User      string `json:"user"`
	ID        string `json:"id"`
	Status    string `json:"status,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// Bucket is one object-storage bucket.
type Bucket struct {
	Name      string `json:"name"`
	Region    string `json:"region,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// Object is one object inside a bucket. Only object metadata travels in Data;
// bodies never do.
type Object struct {
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	LastModified string `json:"last_modified,omitempty"`
}

// Requests are the per-tool inputs a Provider receives.

// AssetRequest lists compute/database instances.
type AssetRequest struct {
	Kinds    []string
	Region   string
	PageSize int
	Cursor   string
}

// IAMRequest lists the sub-account surface.
type IAMRequest struct {
	Include    []string // users | policies | access_keys
	MaxResults int
	Cursor     string
}

// StorageRequest lists buckets, or the objects of one bucket.
type StorageRequest struct {
	Bucket     string
	Prefix     string
	MaxResults int
	Cursor     string
}

// CommandRequest runs one command through the vendor's cloud assistant.
type CommandRequest struct {
	InstanceID string
	Command    string
	TimeoutSec int
	Region     string
}

// Pages are the paged responses a Provider returns.

type AssetPage struct {
	Instances []Instance
	Total     int
	Cursor    string
	HasMore   bool
	// Warnings records a kind that failed while another succeeded, so the tool
	// can report StatusPartial honestly instead of dropping it.
	Warnings []string
}

type IAMPage struct {
	Users      []IAMUser
	Policies   []IAMPolicy
	AccessKeys []AccessKey
	Total      int
	Cursor     string
	HasMore    bool
	Warnings   []string
}

type StoragePage struct {
	Buckets  []Bucket
	Objects  []Object
	Total    int
	Cursor   string
	HasMore  bool
	Warnings []string
}

// CommandResult is the outcome of one cloud-assistant invocation. Stdout is
// bounded by the caller; anything larger is stored as evidence and referenced.
type CommandResult struct {
	InstanceID string `json:"instance_id"`
	CommandID  string `json:"command_id"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	StdoutSize int    `json:"stdout_bytes,omitempty"`
}

// Provider is one vendor, implemented by the per-vendor files in this package.
// Every method must be safe for concurrent use and must return a *Error for
// vendor-side failures so the kit can classify them.
type Provider interface {
	// Name is the provider constant.
	Name() string
	// Verify performs the minimal read that proves the credential works
	// (GetCallerIdentity and its equivalents).
	Verify(ctx context.Context, creds Credentials) (Identity, error)
	// ListAssets lists compute and database instances.
	ListAssets(ctx context.Context, creds Credentials, req AssetRequest) (AssetPage, error)
	// ListIAM lists sub-accounts, policies and access-key metadata.
	ListIAM(ctx context.Context, creds Credentials, req IAMRequest) (IAMPage, error)
	// ListStorage lists buckets, or the objects of one bucket.
	ListStorage(ctx context.Context, creds Credentials, req StorageRequest) (StoragePage, error)
	// RunCommand runs one command through the vendor's cloud assistant.
	RunCommand(ctx context.Context, creds Credentials, req CommandRequest) (CommandResult, error)
}

// ValidProvider reports whether p is a vendor this kit implements.
func ValidProvider(p string) bool {
	for _, v := range Providers {
		if v == p {
			return true
		}
	}
	return false
}
