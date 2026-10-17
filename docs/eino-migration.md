# norma → eino 迁移决策记录

> 分支 `feat/eino-migration`。目标:整体采用 cloudwego/eino v0.9.21(ADK Runner 路线),删除 norma 依赖。
> 本文档记录 P1 尖刺验证的结论与三个设计闸门的定案。尖刺代码在 `spike/`,迁移完成后删除。

## 已验证结论(spike/ 下可运行测试)

- **V1 claude**(`spike/wire_providers_test.go`):eino-ext `model/claude` 支持注入 `HTTPClient`;流式 thinking → `Message.ReasoningContent`,signature → `Extra["_eino_claude_thinking_signature"]`;usage 首块(message_start)与末块(message_delta)到达,`PromptTokens = input + cache_read + cache_write`,`PromptTokenDetails.CachedTokens/CacheWriteTokens` 分别对应 cache read/creation。请求体 `GetBody` 可重放。
- **V2 openai**:eino-ext `model/openai` 支持 `HTTPClient`/`BaseURL`/`ReasoningEffort`;`reasoning_content` → `ReasoningContent`;usage 走 `stream_options.include_usage` 末块;body 为 `*bytes.Buffer`,`GetBody` 自动可重放 → `quotaAwareCapture` 传输层可直接复用。
- **V3 挂点**(`spike/middleware_test.go`):`adk.ChatModelAgentMiddleware` 的 `WrapInvokableToolCall` 可在工具执行前拦截(deny 不执行 / allow 放行 / 阻塞等待);`BeforeModelRewriteState` 每轮模型调用前触发且可改 `state.Messages`。事件流经 `AgentEvent.Output.MessageOutput`(Role/ToolName + GetMessage)可完整还原 text/thinking/tool_use/tool_result。
- **V4 并发**:ToolsNode 默认并行;`ToolsConfig.ToolsNodeConfig.ExecuteSequentially` 可全局串行。非并发安全工具用每工具互斥包装(保持并行模型,与 norma 一致)。
- **V9 依赖**:eino 依赖树与 klauspost/compress、x/net、modernc sqlite 无冲突。

## 三个设计闸门定案

### V5 延迟工具 → 自研中间件(不用 eino toolsearch)

eino `toolsearch` 中间件无硬门控(模型直呼隐藏工具会照常执行)、宿主无法程序化解锁、Skill 元工具无法授权解锁,均不满足 norma 语义。定案:

- ARTEX 中间件 `deferredToolMiddleware`:`BeforeAgent` 注入 `SearchExtraTools`/`ExecuteExtraTool`(名字不变,旧会话兼容);`BeforeModelRewriteState` 从 `state.ToolInfos` 摘除未解锁工具 schema;`WrapInvokableToolCall` 硬门控(`UnlockSet.Has` 之外报错「先加载提供它的 skill」)。
- UnlockSet 经 `SetRunLocalValue` 持有(checkpoint 安全);C2(恢复时从历史 Skill 调用重放解锁)保留在 ARTEX 侧。
- 延迟工具提示块保持在 Instruction 尾部(DynamicBoundary 语义放弃,缓存交 provider 侧)。

### V6 压缩 → 移植 norma 语义为自研中间件(不用 eino summarization)

eino `summarization` 中间件是破坏式(直接替换 `state.Messages`,不保留完整历史)且仅预防式(无 413 反应),与 norma「非破坏 boundary + 完整历史在 transcript + 413 反应式压缩重试」不符。定案:

- norma `compaction` 三机制(MicroCompact / AutoCompact / Reactive)移植进 ARTEX `compaction/` 包,适配为 `ChatModelAgentMiddleware`:`BeforeModelRewriteState` 做预算检查与 boundary 压缩,`WrapModel` 捕获 413/prompt-too-long 触发反应式压缩重试。
- 完整历史继续由 ARTEX transcript(JSONL)承载;压缩视图持久化语义不变;skill 指导消息逐字再注入在移植的压缩逻辑内保留。

### V3 运行时挂点分配

| norma 挂点 | eino 落点 |
|---|---|
| guard/intercept 审批(分钟级同步阻塞) | `WrapInvokableToolCall`:先 guard 链,ask 时阻塞 `HandleAsk`,deny 返回管控文本 |
| steer(planner 注入,阻塞工具) | `WrapInvokableToolCall`:drain steering 队列,有则不执行工具、返回 steering 文本 |
| 空轮次提醒(Stop 钩子) | `BeforeModelRewriteState`:检测上一轮输出为空 → 注入续跑指令(RunLocalValue 计数,上限同现状) |
| PostToolUse 审计 | `WrapInvokableToolCall` 尾部 |
| Skill 指导消息(Result.Extra)注入 | `BeforeModelRewriteState`:检测上一轮 skill 调用,在 tool 消息后插入 guidance 消息 |
| 结算(settlement) | 内核包装:Runner 终态(max_iterations/timeout)后另起有界 Runner,PromptByReason 保留 |
| sidequestion CallModel 快照 | 模型装饰器(与 llmrec/llmpool 同层) |
| TerminalReason | 内核从 ADK 事件映射,枚举与 engine 状态机不变 |

## 模型栈映射

| norma | eino |
|---|---|
| `llm.Provider`(Stream/Complete) | `model.ToolCallingChatModel`(Generate/Stream/WithTools) |
| FormatOpenAI | eino-ext `model/openai` |
| FormatAnthropic | eino-ext `model/claude`(ThinkingConfig 承载 norma ThinkingType) |
| FormatOpenAIResponses | 自研 provider(移植 norma responses wire 代码) |
| Config 重试/限流/空响应重试 | ARTEX 装饰器 |
| `llm.Usage` | `schema.TokenUsage`(Prompt/Completion/PromptTokenDetails.CachedTokens/CacheWriteTokens) |
| `llm.StreamEvent` 事件种类 | 内核从 `schema.Message` 流块推导(Content/ReasoningContent/ToolCalls/ResponseMeta) |

transcript 落盘 JSON 字段形状保持 norma 形状(存量会话可恢复),由 `acllm/` 转换层承担 schema.Message ↔ 落盘 DTO 双向转换。

## 测试基线

全绿命令(`server` 包需要 PG):

```
ARTEX_PG_DSN="postgres:///artex_eino_migration?host=/var/run/postgresql&port=5433&sslmode=disable" go test ./...
```
