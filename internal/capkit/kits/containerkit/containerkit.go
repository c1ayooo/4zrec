// Deprecated: 迁移到 kits/postex/container，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package containerkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/container"

type (
	Capability    = container.Capability
	CheckResult   = container.CheckResult
	DockerVersion = container.DockerVersion
	EscapeCheck   = container.EscapeCheck
	EscapeFinding = container.EscapeFinding
	EscapeSurface = container.EscapeSurface
	EtcdKV        = container.EtcdKV
	KubeletPod    = container.KubeletPod
)

const (
	Version = container.Version
)

var (
	EscapeChecks  = container.EscapeChecks
	Manifest      = container.Manifest
	NewCapability = container.NewCapability
)
