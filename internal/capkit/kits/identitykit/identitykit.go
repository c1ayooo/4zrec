// Deprecated: 迁移到 kits/data/identity，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package identitykit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/data/identity"

type (
	AuthFlowRegistry = identity.AuthFlowRegistry
	Capability       = identity.Capability
	FormFlow         = identity.FormFlow
	JarIdentity      = identity.JarIdentity
	TokenIdentity    = identity.TokenIdentity
)

var (
	AuthKinds              = identity.AuthKinds
	CSRFNames              = identity.CSRFNames
	ExtractCSRF            = identity.ExtractCSRF
	ExtractCSRFNamed       = identity.ExtractCSRFNamed
	ExtractCSRFWithSource  = identity.ExtractCSRFWithSource
	Manifest               = identity.Manifest
	NewAuthFlowRegistry    = identity.NewAuthFlowRegistry
	NewCapability          = identity.NewCapability
	NewCapabilityWithFlows = identity.NewCapabilityWithFlows
	NewJarIdentity         = identity.NewJarIdentity
	NewTokenIdentity       = identity.NewTokenIdentity
	NormalizeAuthKind      = identity.NormalizeAuthKind
)
