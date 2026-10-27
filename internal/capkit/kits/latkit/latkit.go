// Deprecated: 迁移到 kits/postex/lat，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package latkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/lat"

type (
	Capability = lat.Capability
	CredHash   = lat.CredHash
	Input      = lat.Input
)

var (
	BuildAsrepRoast  = lat.BuildAsrepRoast
	BuildCommand     = lat.BuildCommand
	BuildDCSync      = lat.BuildDCSync
	BuildKerberoast  = lat.BuildKerberoast
	BuildPassTheHash = lat.BuildPassTheHash
	BuildPsexec      = lat.BuildPsexec
	BuildSmbexec     = lat.BuildSmbexec
	BuildWinRM       = lat.BuildWinRM
	BuildWmiexec     = lat.BuildWmiexec
	Manifest         = lat.Manifest
	NewCapability    = lat.NewCapability
	ParseHashes      = lat.ParseHashes
)
