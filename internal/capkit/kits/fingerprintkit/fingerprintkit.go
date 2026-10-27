// Deprecated: 迁移到 kits/recon/fingerprint，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package fingerprintkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/recon/fingerprint"

type (
	Capability = fingerprint.Capability
	Fetcher    = fingerprint.Fetcher
	Format     = fingerprint.Format
	Pattern    = fingerprint.Pattern
	Provider   = fingerprint.Provider
	Response   = fingerprint.Response
	Rule       = fingerprint.Rule
	RuleSet    = fingerprint.RuleSet
	Source     = fingerprint.Source
	Syncer     = fingerprint.Syncer
	Tech       = fingerprint.Tech
)

const (
	FormatDDDD       = fingerprint.FormatDDDD
	FormatWappalyzer = fingerprint.FormatWappalyzer
	FormatWebanalyze = fingerprint.FormatWebanalyze
)

var (
	FaviconHash   = fingerprint.FaviconHash
	Manifest      = fingerprint.Manifest
	NewCapability = fingerprint.NewCapability
	NewRuleSet    = fingerprint.NewRuleSet
)
