// Deprecated: 迁移到 kits/vuln/verify，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package verifykit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/verify"

type (
	Kit = verify.Kit
)

var (
	Manifest      = verify.Manifest
	New           = verify.New
	NewCapability = verify.NewCapability
)
