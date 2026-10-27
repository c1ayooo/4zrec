// Deprecated: 迁移到 kits/postex/shell/session，本包仅作兼容，M3 后移除。
// shellkit 子包路径的过渡 shim：只做类型别名与函数变量转发。
package session

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/session"

type (
	CapabilitySession = session.CapabilitySession
	ExecResult        = session.ExecResult
	Executor          = session.Executor
	FileOp            = session.FileOp
	Session           = session.Session
)
