// Deprecated: 迁移到 kits/postex/shell/listener，本包仅作兼容，M3 后移除。
// shellkit 子包路径的过渡 shim：只做类型别名与函数变量转发。
package listener

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/listener"

type (
	Manager     = listener.Manager
	Session     = listener.Session
	SessionInfo = listener.SessionInfo
)

const (
	DefaultReadTimeout = listener.DefaultReadTimeout
	UploadChunkSize    = listener.UploadChunkSize
)

var (
	NewManager = listener.NewManager
)
