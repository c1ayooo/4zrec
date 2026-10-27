// Deprecated: 迁移到 kits/recon/github，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package githubkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/recon/github"

type (
	Client       = github.Client
	Credibility  = github.Credibility
	DorkTemplate = github.DorkTemplate
	Kit          = github.Kit
	SearchItem   = github.SearchItem
	SearchResult = github.SearchResult
)

var (
	BuildQuery       = github.BuildQuery
	Classify         = github.Classify
	New              = github.New
	NewCapability    = github.NewCapability
	ScoreCredibility = github.ScoreCredibility
	SearchURL        = github.SearchURL
	TemplateByID     = github.TemplateByID
	Templates        = github.Templates
)
