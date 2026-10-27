// Deprecated: 迁移到 kits/postex/privesc，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package privesckit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/privesc"

type (
	AutoLogon      = privesc.AutoLogon
	Capability     = privesc.Capability
	FileCapability = privesc.FileCapability
	Privilege      = privesc.Privilege
	ServiceConfig  = privesc.ServiceConfig
	Signals        = privesc.Signals
	SudoRule       = privesc.SudoRule
)

var (
	Manifest      = privesc.Manifest
	NewCapability = privesc.NewCapability
)
