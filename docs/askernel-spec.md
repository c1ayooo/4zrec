# askernel 内核规格(norma agentcore+harness 的 eino ADK 实现)

> 本文是实现契约。所有决策已在 P1 尖刺与源码调研中定案(见 eino-migration.md)。
> 关键不变量:**db.Activity 的 Kind 集合与形状、TerminalReason 枚举、transcript JSONL 格式、审批长阻塞语义,全部保持与 norma 时代一致。**

## 1. 核心架构:DTO 主历史 + schema 投影

内核持有 **DTO 主历史**(`[]acllm.Message`),它是唯一的事实来源:

- 完整历史 + compact boundary 都在 DTO 里(与 norma 语义一致);
- transcript(JSONL)从 DTO 逐条落盘(RecordMessage/RecordBoundary),格式冻结;
- 每轮模型调用前,`BeforeModelRewriteState` 把 `acllm.MessagesForAPI(dto)`(boundary 剥离+孤儿工具块配对)经 `acllm.ToSchema` 投影到 `state.Messages`,并把可见工具集写入 `state.ToolInfos`;
- 压缩(ARTEX `compaction` 包,MicroCompact/AutoCompact/Reactive)直接操作 DTO,产出 boundary + summary 后同时写入 transcript —— **compaction 语义零漂移**;
- ADK 的 checkpoint 不用于跨进程恢复;暂停/恢复 = ctx 取消(命名 cause)+ transcript 重放(`Resume`)。

## 2. 事件词汇(harness.Event 兼容形状,包内重定义)

```go
type EventKind string
const (KindText, KindThinking, KindToolUse, KindToolResult, KindUsage, KindResult, KindProgress)
type Event struct {
    Kind EventKind
    Text string
    ToolUse *acllm.ContentBlock      // KindToolUse
    ToolResult *acllm.ContentBlock   // KindResult 工具结果块
    Terminal *Terminal               // KindResult
    Usage *acllm.Usage
}
type TerminalReason string  // 与 norma 11 个枚举值逐一同名:completed/blocking_limit/image_error/model_error/aborted_streaming/aborted_tools/prompt_too_long/stop_hook_prevented/hook_stopped/max_turns/timeout
type Terminal struct { Reason TerminalReason; Err error; Usage acllm.Usage; Turns int; Messages []acllm.Message; Text string }
```

`agent/captureRunSession` 的重写版消费此事件流,下游 db.Activity/SSE/审计不动。

## 3. HookRunner(guard/steer 的接缝,与 norma 同形)

```go
type HookRunner interface {
    PreToolUse(ctx context.Context, name string, input json.RawMessage) (block bool, message string, updatedInput json.RawMessage)
    PostToolUse(ctx context.Context, name string, input json.RawMessage, result string, isErr bool)
    Stop(ctx context.Context, messages []acllm.Message) (prevent bool, blockingErrors []string, message string)
}
```
norma/hook 的 Registry(On(EventType, Func))原样移植进 askernel(hookreg.go),guard 改 import。

## 4. Options(六类 agent 装配的唯一入口)

```go
type Options struct {
    Model model.ToolCallingChatModel   // 已装饰好的模型(llmrec→sidequestion→llmpool→taskLLM 顺序由装配方决定)
    SystemPrompt []string              // 分段;延迟工具提示块由内核追加在尾部
    Tools []tools.CoreTool             // 已装配(含 skill meta-tool、MCP、域工具)
    DeferredTools []string             // 延迟隐藏 schema 的工具名
    Unlock *tools.UnlockSet            // 共享解锁门(宿主在 UI 解锁 skill 时 Add)
    PermissionMode tools.Mode          // 现状恒为 bypass;保留字段与语义
    WorkingDir string
    BashEnv []string
    MaxTurns int                       // → ChatModelAgent.MaxIterations
    MaxDuration time.Duration
    Settlement *Settlement
    ToolOutputDir string
    MaxToolOutputChars int             // 默认 30000(tools.Capture 已有同默认)
    Compaction *compaction.Config      // nil = 不压缩;Noa 启用时置空并接管
    Noa *NoaOptions                    // 见 §7
    Todos *tools.TodoStore
    Transcript *transcript.Store; SessionID string
    Hooks HookRunner                   // guard(可能被 engine 的 steerHooks 包裹)
    NonStreaming bool
    MaxTokens int
    OnWarn func(string)
    WebFetch/WebSearch 相关配置字段     // 传递给 tools 构造(见 §6)
    Recorder harness.Recorder 形状      // = transcript.Writer,内核持有
}
type Settlement struct { Prompt string; MaxTurns int; DisabledTools []string; PromptByReason map[TerminalReason]string }
```

## 5. 运行流程(Session.Prompt)

1. 用户输入 → DTO 追加 user 消息 + transcript 记录;
2. Runner.Run/Query(EnableStreaming=true)事件泵:
   - assistant 流块:Content 增量 → KindText;ReasoningContent 增量 → KindThinking;ToolCalls 出现 → (流结束后)KindToolUse;
   - role=tool 消息 → KindToolResult(Content + ExtraIsError → IsError);同步把 assistant 消息(含 thinking/tool_use 的 DTO)与 tool 结果消息写入 DTO + transcript;
   - ResponseMeta.Usage(每轮末块)→ 累计 → KindUsage;
   - `Extra["_acllm_skill_guidance"]` 的消息(见 §6)作为独立 user 消息插到 DTO 中工具结果之后(transcript 同步);
3. 终态:迭代器结束 → KindResult + Terminal;Reason 映射:正常 Exit→completed;ctx.Canceled→aborted_streaming(或按 cause);MaxIterations 触达→max_turns;413 反应式压缩后成功→completed;压缩反应失败→prompt_too_long;Stop 钩子 prevent→stop_hook_prevented/hook_stopped;模型错误重试耗尽→model_error。
4. **结算**:若 Reason∈{max_turns, timeout} 且 opts.Settlement 非 nil → 另起一个**有界 Runner**(注入 Settlement.Prompt 为 user 消息,隐藏 DisabledTools,MaxIterations=Settlement.MaxTurns),事件并入同一泵;结束后终态保持 max_turns/timeout(engine 状态机依赖此语义)。
5. **空轮次提醒**(norma Stop 钩子语义):`BeforeModelRewriteState` 检测上一轮 assistant 无 text/tool_calls → 注入 nudge user 消息(RunLocalValue 计数,上限与 norma 一致:worker 2 次/其他 5 次,达上限放行)。

## 6. 工具执行与审批(WrapInvokableToolCall 门控,顺序与 norma execOne 一致)

内核把每个 `tools.CoreTool` 经适配器(见下)变成 eino 工具;中间件按名取回 CoreTool 执行:

1. schema 校验(eino ToolsNode 已做;若未做则门控内校验 InputSchema);
2. 权限(现状 bypass 直通;非 bypass 走 tools 包 Evaluate 形状);
3. **HookRunner.PreToolUse**:block → 不执行,返回 message 作为工具错误结果(guard/intercept 的 ask 阻塞发生在这里——分钟级同步等待,语义不变);
4. 执行:非并发安全工具共享一把互斥锁;`guardPanic` 语义保留(适配器 recover → 错误结果);
5. **PostToolUse** 审计;
6. 技能指导:CoreTool.Result.Extra 非空时,这些消息进 DTO(在工具结果之后)+ transcript,并标记 Extra 键以便压缩逐字再注入(compaction 已移植该逻辑)。

适配器放 tools 包(`eino.go`):`func ToEino(t CoreTool) tool.InvokableTool`;`func ToolContextFrom(ctx) *ToolContext`(内核每 run 注入 WorkingDir/Env/Capture 配置);`func CallFromEino(ctx, argsJSON)` 反向构造 input。

## 7. deferred 中间件(自研,闸门 V5 定案)

- `BeforeAgent`:DeferredTools 非空时向执行集追加 `SearchExtraTools`/`ExecuteExtraTool`(tools 包已移植,构造时闭包 Registry+UnlockSet);
- `BeforeModelRewriteState`:未解锁的 DeferredTools 名从 `state.ToolInfos` 摘除;已解锁的加回;
- `WrapInvokableToolCall`:ExecuteExtraTool 内部已做 UnlockSet 硬门控(tools 包移植件),双保险;
- 延迟工具提示块(`tools.RenderDeferredToolsBlock`)由内核追加在 SystemPrompt 尾段;
- C2:宿主在 Resume 后调用 `seedUnlockFromHistory`(扫历史 Skill 调用重放解锁)——留在 agent 包(现有代码迁移)。

## 8. 压缩中间件

- `BeforeModelRewriteState`:以 `compaction.Compactor.Pre(dto, lastInputTokens)` 处理 DTO;若产出 boundary → transcript.RecordBoundary + summary 消息记录;之后投影 state.Messages;
- `WrapModel`:捕获内层错误,`IsOverflow(err)` → `Reactive(dto)` 强制压缩 → 重试一次(最多 norma 的 3 连败上限),全败→ prompt_too_long;
- lastInputTokens 从上一轮 Usage 取(KindUsage 已捕获);
- Noa 启用时:Noa Compactor 接管本节(noaadapter 移植件,接口同形),两者互斥(现状语义)。

## 9. 明确不做

- 不用 eino toolsearch/summarization/checkpoint 中间件(闸门 V5/V6 定案自研);
- 不用 ADK sub-agent/transfer(多 agent 协调仍在 engine 层);
- 不做 Interrupt/ResumeParams(审批用同步阻塞包装器,暂停用 transcript 恢复);
- DynamicBoundary 提示缓存边界放弃。

## 10. 测试契约

- 内核级:scriptChatModel 驱动(spike 已有)覆盖——单轮文本、工具调用+审批阻塞+deny、空轮次 nudge、结算触发、413 反应式压缩、deferred 解锁前后 schema 可见性、resume 重建(含 C2);
- 金标准:同场景下 KindResult/Terminal.Usage/Turns 与 norma 行为对齐(engine 状态机不变量)。
