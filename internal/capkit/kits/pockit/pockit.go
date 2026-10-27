// Deprecated: 迁移到 kits/vuln/poc，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package pockit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/poc"

type (
	Analysis           = poc.Analysis
	FingerprintDraft   = poc.FingerprintDraft
	FingerprintPattern = poc.FingerprintPattern
	IntelInput         = poc.IntelInput
	Kit                = poc.Kit
	POC                = poc.POC
	PoCParam           = poc.PoCParam
	PoCSpec            = poc.PoCSpec
	TemplateDraft      = poc.TemplateDraft
)

var (
	Manifest                 = poc.Manifest
	MarshalFingerprint       = poc.MarshalFingerprint
	MarshalPoCSpec           = poc.MarshalPoCSpec
	New                      = poc.New
	NewCapability            = poc.NewCapability
	ValidateFingerprintDraft = poc.ValidateFingerprintDraft
	ValidatePoCScript        = poc.ValidatePoCScript
	ValidateTemplateYAML     = poc.ValidateTemplateYAML
)
