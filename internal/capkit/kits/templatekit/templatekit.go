// Deprecated: 迁移到 kits/vuln/template，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package templatekit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/template"

type (
	Capability   = template.Capability
	Catalog      = template.Catalog
	DirSource    = template.DirSource
	Extract      = template.Extract
	Kind         = template.Kind
	Matcher      = template.Matcher
	Pack         = template.Pack
	PackManifest = template.PackManifest
	PackSource   = template.PackSource
	Provenance   = template.Provenance
	RequestSpec  = template.RequestSpec
	Template     = template.Template
)

const (
	KindChain  = template.KindChain
	KindHTTP   = template.KindHTTP
	KindNuclei = template.KindNuclei
	KindShell  = template.KindShell
)

var (
	Manifest         = template.Manifest
	NewCapability    = template.NewCapability
	NewCatalog       = template.NewCatalog
	ValidatePack     = template.ValidatePack
	ValidateTemplate = template.ValidateTemplate
)
