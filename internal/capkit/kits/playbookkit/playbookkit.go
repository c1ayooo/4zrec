// Deprecated: 迁移到 kits/flow/playbook，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package playbookkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/flow/playbook"

type (
	Capability  = playbook.Capability
	DNSResolver = playbook.DNSResolver
	Expectation = playbook.Expectation
	Limits      = playbook.Limits
	Playbook    = playbook.Playbook
	RunOptions  = playbook.RunOptions
	RunResult   = playbook.RunResult
	Step        = playbook.Step
	StepExtract = playbook.StepExtract
	StepRequest = playbook.StepRequest
	StepResult  = playbook.StepResult
	TCPDialer   = playbook.TCPDialer
)

const (
	DefaultMaxRequests  = playbook.DefaultMaxRequests
	DefaultStepTimeout  = playbook.DefaultStepTimeout
	MaxRedirectsPerStep = playbook.MaxRedirectsPerStep
	MaxRepeatPerStep    = playbook.MaxRepeatPerStep
	MaxRequestsHard     = playbook.MaxRequestsHard
	MaxResponseBody     = playbook.MaxResponseBody
	MaxStepTimeout      = playbook.MaxStepTimeout
	MaxStepsHard        = playbook.MaxStepsHard
	MaxTCPPayloadBytes  = playbook.MaxTCPPayloadBytes
	RespSnippetLen      = playbook.RespSnippetLen
	StepKindDNS         = playbook.StepKindDNS
	StepKindHTTP        = playbook.StepKindHTTP
	StepKindTCP         = playbook.StepKindTCP
	VerdictBlocked      = playbook.VerdictBlocked
	VerdictConfirmed    = playbook.VerdictConfirmed
	VerdictRefuted      = playbook.VerdictRefuted
)

var (
	EmbeddedPresets       = playbook.EmbeddedPresets
	KindOf                = playbook.KindOf
	LoadPlaybookFromBytes = playbook.LoadPlaybookFromBytes
	LoadPlaybooksFromDir  = playbook.LoadPlaybooksFromDir
	Manifest              = playbook.Manifest
	NewCapability         = playbook.NewCapability
	RenderVars            = playbook.RenderVars
	Run                   = playbook.Run
	ValidatePlaybook      = playbook.ValidatePlaybook
)
