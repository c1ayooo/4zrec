// Deprecated: 迁移到 kits/data/cloud，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package cloudkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/data/cloud"

type (
	AccessKey      = cloud.AccessKey
	AssetPage      = cloud.AssetPage
	AssetRequest   = cloud.AssetRequest
	Bucket         = cloud.Bucket
	CommandRequest = cloud.CommandRequest
	CommandResult  = cloud.CommandResult
	Credentials    = cloud.Credentials
	Error          = cloud.Error
	IAMPage        = cloud.IAMPage
	IAMPolicy      = cloud.IAMPolicy
	IAMRequest     = cloud.IAMRequest
	IAMUser        = cloud.IAMUser
	Identity       = cloud.Identity
	Instance       = cloud.Instance
	Kit            = cloud.Kit
	Object         = cloud.Object
	Provider       = cloud.Provider
	Reason         = cloud.Reason
	StoragePage    = cloud.StoragePage
	StorageRequest = cloud.StorageRequest
)

const (
	AssetCompute             = cloud.AssetCompute
	AssetDatabase            = cloud.AssetDatabase
	ProviderAWS              = cloud.ProviderAWS
	ProviderAliyun           = cloud.ProviderAliyun
	ProviderHuawei           = cloud.ProviderHuawei
	ProviderTencent          = cloud.ProviderTencent
	ReasonInstanceNotRunning = cloud.ReasonInstanceNotRunning
	ReasonInvalidCredential  = cloud.ReasonInvalidCredential
	ReasonNotFound           = cloud.ReasonNotFound
	ReasonPermissionDenied   = cloud.ReasonPermissionDenied
	ReasonRegionInvalid      = cloud.ReasonRegionInvalid
	ReasonThrottled          = cloud.ReasonThrottled
	ReasonTimeout            = cloud.ReasonTimeout
	ReasonUnsupported        = cloud.ReasonUnsupported
	ReasonUpstream           = cloud.ReasonUpstream
)

var (
	Providers     = cloud.Providers
	New           = cloud.New
	NewCapability = cloud.NewCapability
	ValidProvider = cloud.ValidProvider
)
