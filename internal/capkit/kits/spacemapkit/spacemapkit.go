// Deprecated: 迁移到 kits/recon/spacemap，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package spacemapkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/recon/spacemap"

type (
	Client         = spacemap.Client
	Result         = spacemap.Result
	SearchRequest  = spacemap.SearchRequest
	SearchResponse = spacemap.SearchResponse
)

var (
	EnvKeyNames              = spacemap.EnvKeyNames
	Providers                = spacemap.Providers
	BaseURLSettingsKey       = spacemap.BaseURLSettingsKey
	DefaultFieldsForProvider = spacemap.DefaultFieldsForProvider
	DomainQuery              = spacemap.DomainQuery
	DomainQueryTemplate      = spacemap.DomainQueryTemplate
	Mask                     = spacemap.Mask
	NewCapability            = spacemap.NewCapability
	NewClient                = spacemap.NewClient
	ProviderDisplayName      = spacemap.ProviderDisplayName
	ResultsFromRows          = spacemap.ResultsFromRows
	SettingsKey              = spacemap.SettingsKey
	SummarizeRow             = spacemap.SummarizeRow
	ValidProvider            = spacemap.ValidProvider
)
