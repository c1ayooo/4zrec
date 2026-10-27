// Deprecated: 迁移到 kits/postex/shell/tunnel，本包仅作兼容，M3 后移除。
// shellkit 子包路径的过渡 shim：只做类型别名与函数变量转发。
package tunnel

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/tunnel"

type (
	PageDeployer = tunnel.PageDeployer
	Plan         = tunnel.Plan
	Sink         = tunnel.Sink
	Status       = tunnel.Status
)

var (
	PageLangFor     = tunnel.PageLangFor
	RenderPage      = tunnel.RenderPage
	SuggestPagePath = tunnel.SuggestPagePath
)
