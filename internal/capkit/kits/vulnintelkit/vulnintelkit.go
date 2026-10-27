// Deprecated: 迁移到 kits/vuln/intel，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package vulnintelkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/intel"

type (
	Info   = intel.Info
	Kit    = intel.Kit
	Source = intel.Source
)

const (
	SeverityCritical = intel.SeverityCritical
	SeverityHigh     = intel.SeverityHigh
	SeverityLow      = intel.SeverityLow
	SeverityMedium   = intel.SeverityMedium
	SeverityUnknown  = intel.SeverityUnknown
)

var (
	ContainsHan       = intel.ContainsHan
	Manifest          = intel.Manifest
	New               = intel.New
	NewCapability     = intel.NewCapability
	NormalizeSeverity = intel.NormalizeSeverity
	SeverityRank      = intel.SeverityRank
)
