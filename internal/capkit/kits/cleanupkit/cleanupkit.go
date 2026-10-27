// Deprecated: 迁移到 kits/postex/cleanup，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package cleanupkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/cleanup"

type (
	Capability = cleanup.Capability
)

var (
	Manifest      = cleanup.Manifest
	NewCapability = cleanup.NewCapability
)
