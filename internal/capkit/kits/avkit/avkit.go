// Deprecated: 迁移到 kits/postex/av，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package avkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/av"

type (
	Capability = av.Capability
	Category   = av.Category
	Database   = av.Database
	Detection  = av.Detection
	Match      = av.Match
	Product    = av.Product
)

const (
	CatAV      = av.CatAV
	CatEDR     = av.CatEDR
	CatEPP     = av.CatEPP
	CatFW      = av.CatFW
	CatLogging = av.CatLogging
	CatNGAV    = av.CatNGAV
)

var (
	DefaultDatabase = av.DefaultDatabase
	Manifest        = av.Manifest
	NewCapability   = av.NewCapability
)
