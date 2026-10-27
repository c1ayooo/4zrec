// Deprecated: 迁移到 kits/data/toolparse，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package toolparse

import "github.com/c1ayooo/4zrec/internal/capkit/kits/data/toolparse"

type (
	Capability       = toolparse.Capability
	ConcludeEnvelope = toolparse.ConcludeEnvelope
	FactCandidate    = toolparse.FactCandidate
	FactLink         = toolparse.FactLink
	Injection        = toolparse.Injection
	Parser           = toolparse.Parser
	Result           = toolparse.Result
	TargetAware      = toolparse.TargetAware
)

const (
	ConcludeMaxFacts     = toolparse.ConcludeMaxFacts
	MaxFactsIndexEntries = toolparse.MaxFactsIndexEntries
	MaxReceiptBytes      = toolparse.MaxReceiptBytes
	TmpDirPlaceholder    = toolparse.TmpDirPlaceholder
)

var (
	ValidCategories     = toolparse.ValidCategories
	InjectedTools       = toolparse.InjectedTools
	InjectionFor        = toolparse.InjectionFor
	Lookup              = toolparse.Lookup
	Manifest            = toolparse.Manifest
	NewCapability       = toolparse.NewCapability
	NormalizeFact       = toolparse.NormalizeFact
	ParseConcludeOutput = toolparse.ParseConcludeOutput
	Register            = toolparse.Register
	RegisteredTools     = toolparse.RegisteredTools
	RenderParseError    = toolparse.RenderParseError
	RenderReceipt       = toolparse.RenderReceipt
	Sluggify            = toolparse.Sluggify
	ValidateFactKey     = toolparse.ValidateFactKey
)
