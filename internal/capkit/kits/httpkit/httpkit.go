// Deprecated: 迁移到 kits/recon/http，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package httpkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/recon/http"

type (
	Kit = http.Kit
)

var (
	New           = http.New
	NewCapability = http.NewCapability
)
