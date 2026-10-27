// Deprecated: 迁移到 kits/recon/recon，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package reconkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/recon/recon"

type (
	Asset             = recon.Asset
	AssetKind         = recon.AssetKind
	AssetSink         = recon.AssetSink
	Capability        = recon.Capability
	HTTPInfo          = recon.HTTPInfo
	HTTPProber        = recon.HTTPProber
	Options           = recon.Options
	Pipeline          = recon.Pipeline
	Port              = recon.Port
	PortScanner       = recon.PortScanner
	Resolution        = recon.Resolution
	Resolver          = recon.Resolver
	Stats             = recon.Stats
	SubdomainProvider = recon.SubdomainProvider
)

const (
	AssetDomain    = recon.AssetDomain
	AssetIP        = recon.AssetIP
	AssetService   = recon.AssetService
	AssetSubdomain = recon.AssetSubdomain
	AssetURL       = recon.AssetURL
)

var (
	Manifest      = recon.Manifest
	NewCapability = recon.NewCapability
)
