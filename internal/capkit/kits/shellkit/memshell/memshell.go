// Deprecated: 迁移到 kits/postex/shell/memshell，本包仅作兼容，M3 后移除。
// shellkit 子包路径的过渡 shim：只做类型别名与函数变量转发。
package memshell

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/memshell"

type (
	DeployPlan   = memshell.DeployPlan
	DeployResult = memshell.DeployResult
	Deployer     = memshell.Deployer
	Kind         = memshell.Kind
	Options      = memshell.Options
	Payload      = memshell.Payload
	ProbeInput   = memshell.ProbeInput
	ProbeResult  = memshell.ProbeResult
)

const (
	KindAspxHttpModule      = memshell.KindAspxHttpModule
	KindPhpUserIni          = memshell.KindPhpUserIni
	KindSpringController    = memshell.KindSpringController
	KindTomcatFilter        = memshell.KindTomcatFilter
	KindTomcatFilterJakarta = memshell.KindTomcatFilterJakarta
	KindTomcatServlet       = memshell.KindTomcatServlet
	KindTomcatValve         = memshell.KindTomcatValve
	TriggerParam            = memshell.TriggerParam
)

var (
	Generate        = memshell.Generate
	GenerateRemover = memshell.GenerateRemover
	Kinds           = memshell.Kinds
	NormalizeKind   = memshell.NormalizeKind
	Probe           = memshell.Probe
	SupportsRemover = memshell.SupportsRemover
)
