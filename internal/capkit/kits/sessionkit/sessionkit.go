// Deprecated: 迁移到 kits/flow/session，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package sessionkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/flow/session"

type (
	CLIOpener    = session.CLIOpener
	CLISession   = session.CLISession
	Manager      = session.Manager
	SMBOpener    = session.SMBOpener
	SMBSession   = session.SMBSession
	SSHOwner     = session.SSHOwner
	SSHSession   = session.SSHSession
	WinRMOpener  = session.WinRMOpener
	WinRMSession = session.WinRMSession
)

var (
	NewManager = session.NewManager
)
