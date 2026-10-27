// Deprecated: 迁移到 kits/vuln/oast，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package oastkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/oast"

type (
	Client = oast.Client
	Kit    = oast.Kit
)

const (
	DefaultBaseURL = oast.DefaultBaseURL
)

var (
	New           = oast.New
	NewCapability = oast.NewCapability
)
