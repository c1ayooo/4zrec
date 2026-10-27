// Deprecated: 迁移到 kits/postex/shell/protocol，本包仅作兼容，M3 后移除。
// shellkit 子包路径的过渡 shim：只做类型别名与函数变量转发。
package protocol

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/protocol"

type (
	ParamChannel = protocol.ParamChannel
	Protocol     = protocol.Protocol
	Request      = protocol.Request
)

const (
	Behinder         = protocol.Behinder
	DefaultPassParam = protocol.DefaultPassParam
	Godzilla         = protocol.Godzilla
	MaxURLQueryChars = protocol.MaxURLQueryChars
	ParamBody        = protocol.ParamBody
	ParamCookie      = protocol.ParamCookie
	ParamHeader      = protocol.ParamHeader
	ParamQuery       = protocol.ParamQuery
	Plain            = protocol.Plain
)

var (
	ApplyResponseFilter   = protocol.ApplyResponseFilter
	Build                 = protocol.Build
	DeriveKey             = protocol.DeriveKey
	NormalizeParamChannel = protocol.NormalizeParamChannel
	NormalizeProtocol     = protocol.NormalizeProtocol
	SupportsProtocol      = protocol.SupportsProtocol
	Unwrap                = protocol.Unwrap
)
