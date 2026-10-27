// Deprecated: 迁移到 kits/data/binding，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package bindingkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/data/binding"

type (
	Binding    = binding.Binding
	Kit        = binding.Kit
	Resolution = binding.Resolution
)

var (
	DefaultBindings = binding.DefaultBindings
	Manifest        = binding.Manifest
	New             = binding.New
	NewCapability   = binding.NewCapability
	Normalize       = binding.Normalize
	ProductForCVE   = binding.ProductForCVE
	QueryTerms      = binding.QueryTerms
	Resolve         = binding.Resolve
	Validate        = binding.Validate
)
