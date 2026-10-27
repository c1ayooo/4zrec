// flow 域：编排底座——确定性剧本与会话管理。session 是后渗透各 kit 的
// 目标解析通道（RegisterPostex 依赖它），所以宿主组合顺序通常是
// RegisterFlow → RegisterPostex。
package all

import (
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/flow/playbook"
)

// RegisterPlaybook registers deterministic playbook execution.
func RegisterPlaybook(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: playbook.Manifest(), New: playbook.NewCapability})
}

// RegisterFlow registers the flow domain: playbook + session（shellkit 的
// 会话工具归本聚合——目录在 flow/，后渗透域依赖它）。
func RegisterFlow(reg *core.Registry) error {
	if err := RegisterPlaybook(reg); err != nil {
		return err
	}
	return RegisterSession(reg)
}
