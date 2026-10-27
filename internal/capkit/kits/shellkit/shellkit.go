// Deprecated: 迁移到 kits/postex/shell，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package shellkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell"

type (
	Capability         = shell.Capability
	WebShellDeployer   = shell.WebShellDeployer
	WebShellDrop       = shell.WebShellDrop
	WebShellDropResult = shell.WebShellDropResult
	WebShellOpener     = shell.WebShellOpener
)

var (
	Manifest                  = shell.Manifest
	NewCapability             = shell.NewCapability
	NewCapabilityWithDeployer = shell.NewCapabilityWithDeployer
)
