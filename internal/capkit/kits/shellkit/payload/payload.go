// Deprecated: 迁移到 kits/postex/shell/payload，本包仅作兼容，M3 后移除。
// shellkit 子包路径的过渡 shim：只做类型别名与函数变量转发。
package payload

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/payload"

type (
	Options   = payload.Options
	Payload   = payload.Payload
	ShellType = payload.ShellType
	Variant   = payload.Variant
)

const (
	ShellASP     = payload.ShellASP
	ShellASPX    = payload.ShellASPX
	ShellJSP     = payload.ShellJSP
	ShellPHP     = payload.ShellPHP
	VariantEnc   = payload.VariantEnc
	VariantLite  = payload.VariantLite
	VariantPlain = payload.VariantPlain
)

var (
	Generate           = payload.Generate
	NormalizeShellType = payload.NormalizeShellType
	NormalizeVariant   = payload.NormalizeVariant
)
