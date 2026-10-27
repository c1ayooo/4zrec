package core

// Guard 端口：执行侧围栏的宿主裁决面。
//
// 分工（capkit README 约束「宿主实现端口，capkit 提供可复用实现」）：
//   - capkit 的 guard 包负责**目标提取**（从工具输入识别出网对象，纯逻辑）；
//   - 宿主实现 Guard，负责**决策**：查授权范围、查黑名单、合成审批。
//
// runtime.Call 在门禁链最前面调用 Guard（Guard → scope → approval →
// limiter → audit）：它要看原始输入，而 scope 只看结构化目标字段。Guard
// 为 nil 时跳过——不配围栏的宿主行为与历史上完全一致。
//
// 语义约定：Decision 三值 allow/deny/ask。ask 的阻塞等待（审批卡片、
// pending 落库、批准即授权）全是宿主的事——Check 返回时裁决必须已完成，
// runtime 不感知等待。

import (
	"context"
	"encoding/json"
)

// GuardDecision 是围栏对一次工具调用的处置。
type GuardDecision string

const (
	GuardAllow GuardDecision = "allow" // 目标在授权范围内
	GuardDeny  GuardDecision = "deny"  // 命中黑名单，硬阻断
	GuardAsk   GuardDecision = "ask"   // 未授权但非黑名单，交人工裁决
)

// GuardVerdict 是宿主对一次调用的最终裁定。
type GuardVerdict struct {
	Decision GuardDecision
	Reason   string   // 给模型和用户看的理由
	Targets  []Target // 本次调用被识别出的全部目标
}

// Guard 由宿主实现：查授权范围、查黑名单、合成审批。
// capkit 只负责在调用前把原始输入与提取出的目标递过去，不实现策略。
type Guard interface {
	Check(ctx context.Context, tool string, input json.RawMessage, targets []Target) (GuardVerdict, error)
}

// GuardFunc 把函数适配成 Guard（装配期用闭包时的糖）。
type GuardFunc func(ctx context.Context, tool string, input json.RawMessage, targets []Target) (GuardVerdict, error)

// Check 实现 Guard。
func (f GuardFunc) Check(ctx context.Context, tool string, input json.RawMessage, targets []Target) (GuardVerdict, error) {
	return f(ctx, tool, input, targets)
}
