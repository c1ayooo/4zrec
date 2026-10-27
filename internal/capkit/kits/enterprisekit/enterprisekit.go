// Deprecated: 迁移到 kits/data/enterprise，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package enterprisekit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/data/enterprise"

type (
	CandidateAsset     = enterprise.CandidateAsset
	Collector          = enterprise.Collector
	CompanyDetail      = enterprise.CompanyDetail
	CompanyRef         = enterprise.CompanyRef
	DomainHit          = enterprise.DomainHit
	Entity             = enterprise.Entity
	ErrSessionMissing  = enterprise.ErrSessionMissing
	FingerprintScanner = enterprise.FingerprintScanner
	FingerprintStats   = enterprise.FingerprintStats
	Job                = enterprise.Job
	Kit                = enterprise.Kit
	Provider           = enterprise.Provider
	ProviderKind       = enterprise.ProviderKind
	ProviderResolver   = enterprise.ProviderResolver
	ResolverFunc       = enterprise.ResolverFunc
	Store              = enterprise.Store
)

var (
	Registry                   = enterprise.Registry
	IsSessionMissing           = enterprise.IsSessionMissing
	NewAqcProvider             = enterprise.NewAqcProvider
	NewCollector               = enterprise.NewCollector
	NewFengniaoAccountProvider = enterprise.NewFengniaoAccountProvider
	NewFengniaoProvider        = enterprise.NewFengniaoProvider
	NewKit                     = enterprise.NewKit
	NewKuaichaProvider         = enterprise.NewKuaichaProvider
	NewProvider                = enterprise.NewProvider
	NewTycProvider             = enterprise.NewTycProvider
	SessionMissing             = enterprise.SessionMissing
)
