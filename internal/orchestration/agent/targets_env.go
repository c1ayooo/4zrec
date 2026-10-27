package agent

// targets_env.go 会话级目标环境变量（ZREC_TARGETS）的注入约定。
//
// 宿主(server)通过 SetTargetsEnv 注入解析器；每次构建 SessionOptions 时调用，
// 返回追加到 BashEnv 的完整 "KEY=VALUE" 条目。解析器拿到 sessionID（chat 形态
// 是 "conv-<id>"，任务侧是 exploration/intent 会话键）自行定位项目并读取授权
// 目标集（项目范围 ∪ approved 资产）。无项目上下文时返回空 → 不注入，行为与
// 旧行为一致。
//
// 约定语义：agent 引用 $ZREC_TARGETS 即引用已授权目标——围栏对 `$` 形态的
// 目标本就不产生提取对象（宁漏勿扰口径），而这里注入的值按构造就是授权集，
// 两者叠加等于「引用即放行」。范围外目标不走这个变量，直接打会被资产围栏
// 拦下转人工审批。
type targetsEnvResolver func(sessionID string) []string

func targetsEnv(fn targetsEnvResolver, sessionID string) []string {
	if fn == nil {
		return nil
	}
	return fn(sessionID)
}
