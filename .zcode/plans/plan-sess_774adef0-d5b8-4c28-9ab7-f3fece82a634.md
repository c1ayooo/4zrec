# ARTEX 底座迁移:norma → cloudwego/eino(ADK Runner)

按你的三个决策定调:**整体采用 ADK Runner + noa 一并移植 + 直接原地替换**(无双引擎开关)。eino pin `v0.9.21`,在 `feat/eino-migration` 分支开发,全量测试 + 手动 e2e 通过后合入。 norma 是你自己的库,迁移 = 把它的职责吸收进 ARTEX 并重定向到 eino 接口。

## 一、架构映射(norma → eino)

| norma 职责 | 去向 |
|---|---|
| llm.Message/ContentBlock/Usage/StreamEvent | eino `schema.Message`/`TokenUsage`/`StreamReader`;新建 `acllm/` 转换层;**transcript 落盘 JSON 保持 norma 字段形状**(存量会话可恢复) |
| Provider SPI(Stream/Complete) | `model.ToolCallingChatModel`;llmrec / sidequestion / llmpool / taskLLMRuntime 四个装饰器重定向到该接口 |
| FormatOpenAI / FormatAnthropic | eino-ext `model/openai`、`model/claude`(注入 quotaAwareTransport) |
| FormatOpenAIResponses | **自研 provider**(eino-ext 不支持,移植 norma 的 responses wire 代码实现 eino 接口) |
| Config 重试/限流/空响应重试 | ARTEX 限流+重试装饰器 |
| tool.CoreTool/Spec/ToolContext/Result | 新 `tools/` 包:契约原样移植,加 `tool.InvokableTool` 适配器(ToolContext 走 ctx 传递) |
| DefaultTools/ShellSession/NewBash/TodoStore/WebFetch/WebSearch/Capture 截断 | 全部移植进 `tools/`(eino 无内置工具) |
| agentcore+harness(Session/Event/HookRunner/Settlement/QueryDeps) | 新 `askernel/`:`adk.NewChatModelAgent` + `adk.NewRunner`;审批/steer 用**工具包装器前置同步阻塞**(不用 interrupt,分钟级 HandleAsk 语义不变);空轮次提醒内核侧实现;结算=终态后再起一个有界 Runner;TerminalReason 枚举保留,从 ADK 事件映射 |
| hook.Registry(guard) | guard 不动,重新指向 askernel 同形 Hooks 接口 |
| transcript(JSONL 恢复) | 移植为 ARTEX `transcript/`:Resume/cleanResumed/累计用量重建保留;内核从事件流写记录 |
| compaction | 先配 `adk/middlewares/summarization`(Trigger=ContextWindowK);若表达不了「boundary+逐字再注入+413 反应式」,回退为 ARTEX 中间件镜像 norma 语义(闸门 V6) |
| noaadapter+noa | 移植为 ARTEX `noa/`:Compress 工具 + 常驻提示 + Compactor 接管(中间件),与压缩互斥逻辑保留 |
| UnlockSet + SearchExtraTools/ExecuteExtraTool + C2 重放 | 优先 eino `toolsearch` 中间件;不满足解锁门控/C2 重放/缓存稳定块时回退自研中间件(闸门 V5);C2(seedUnlockFromHistory)保留在 ARTEX 侧 |
| skill Registry/meta-tool/OnInvoke | 移植为 ARTEX `skills/` 包 |
| mcp stdio 客户端 | 移植为 `mcpstdio/`;mcphttp 本就是 ARTEX 的,不动 |
| DynamicBoundary 提示缓存边界 | 移除,缓存交 provider 侧;延迟工具块保持在 Instruction 尾部 |

关键重写点:`agent/capture.go:37`(事件漏斗改为消费 AgentEvent)、`agent/provider.go:283`(NewProvider)、`server/assembly.go:25`(wireAgentAugment)、`server/task_llm.go:562`(transcript store)、六类 agent 的 Options 装配(worker/mainagent/planner/chat/goals/orchestrator)。

## 二、P1 尖刺验证(开工先决条件,每项一个最小 spike)

- **V1** eino-ext claude:自定义 HTTPClient、thinking 流式增量 + signature 载体、流内 usage 上报
- **V2** eino-ext openai:请求体 GetBody 可重放(捕获 tee 依赖),否则传输层自行缓冲
- **V3** ChatModelAgent Handlers/中间件可挂点 → 决定 Skill 指导消息注入与 Stop 钩子实现方式
- **V4** ToolsNode 并发策略 → 非并发安全工具的串行化方案(每工具互斥包装)
- **V5** toolsearch 中间件 vs 自研延迟工具中间件(决策闸门)
- **V6** summarization 中间件 vs norma 压缩语义(决策闸门)
- **V7** 流式 usage 在末块的到达路径(live usage 事件依赖)
- **V8** Responses provider 在 eino 接口上的形状(Generate/Stream/WithTools)
- **V9** 与 klauspost/compress、go-mitmproxy 依赖无冲突

## 三、阶段计划

- **P0 基线**(0.5 天):建分支;提交当前未提交变更(go.sum 已脏);`go test ./...` 记录基线;go.mod 引入 eino v0.9.21 + eino-ext
- **P1 尖刺**(2–3 天):V1–V9,产出三份决策(审批包装器形状 / deferred 方案 / 压缩方案)
- **P2 基础移植**(3–4 天):`tools/`、`transcript/`、`acllm/`、`mcpstdio/`,连同 norma 原有测试一起移植改造
- **P3 模型栈**(3–5 天):三格式 provider + 装饰器栈;用 llmrec 现有快照做请求/响应黄金对比;429→402、断路器、安全窗口故障转移行为回归
- **P4 内核**(1–2 周):askernel 全量(Runner 装配/事件漏斗/审批/steer/结算/恢复/压缩/noa);六类 agent 装配改造;`captureRunSession` 重写
- **P5 收尾**(3–5 天):server 重接线;intercept/guard/sidequestion/llmpool 全链路联调;从 go.mod 删除 norma;全量测试 + 手动 e2e 清单(对话、任务运行、审批、暂停恢复、压缩触发、skill 解锁、故障转移)
- **P6 文档**:(0.5 天)CHANGELOG 定版、README 底座说明

## 四、行为不变量(验收标准)

1. SSE / db.Activity 的 Kind 集合与 JSON 形状不变
2. 审批:ask 分钟级阻塞、超时动作、「模型兜底审批」单独 judge 通道计量
3. 恢复:重启后 transcript 恢复、**旧 JSONL 直接可恢复**、压缩视图持久化、C2 重放
4. token 四计数 + llm_usage 台账(成败都记)+ 仪表盘接口不变
5. TerminalReason 枚举与 engine 状态机映射不变
6. 延迟工具/skill 解锁语义不变
7. 流式安全窗口:首事件产出后不再切换成员;ctx 取消与 400 永不切换
8. named cancel causes、guardPanic、每 run MCP 客户端清理不变

## 五、明确取舍(需要你知道的)

- Responses API 靠自研 provider 保全,eino-ext 不覆盖
- DynamicBoundary 提示缓存优化放弃,换 provider 侧缓存
- 若 V5 采用 eino toolsearch,transcript 里会出现 `tool_search` 等新工具名,旧会话重放需名字映射
- eino pre-1.0 有破坏性变更前科(0.8/0.9 各一次):pin 精确版本,升级单独走变更
- 总量约 **4–6 周全职**当量;P1 完成后可复核一次范围