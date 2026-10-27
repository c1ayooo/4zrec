// Deprecated: 迁移到 kits/recon/icp，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package icpkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/recon/icp"

type (
	Client   = icp.Client
	Kit      = icp.Kit
	TypeInfo = icp.TypeInfo
)

const (
	TypeApp   = icp.TypeApp
	TypeBApp  = icp.TypeBApp
	TypeBKapp = icp.TypeBKapp
	TypeBMapp = icp.TypeBMapp
	TypeBWeb  = icp.TypeBWeb
	TypeKapp  = icp.TypeKapp
	TypeMapp  = icp.TypeMapp
	TypeWeb   = icp.TypeWeb
)

var (
	IsBlackType     = icp.IsBlackType
	IsSupportedType = icp.IsSupportedType
	New             = icp.New
	NewCapability   = icp.NewCapability
	NewClient       = icp.NewClient
	TypeCatalog     = icp.TypeCatalog
)
