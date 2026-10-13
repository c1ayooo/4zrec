package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/acllm"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/transcript"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type taskAgentBundle struct {
	runtime        *taskLLMRuntime // goal decomposition runtime
	plannerRuntime *taskLLMRuntime
	workerRuntime  *taskLLMRuntime
	mainRuntime    *taskLLMRuntime
	pl             *agent.Planner
	wk             *agent.Worker
	main           *agent.MainAgent
}

type llmAuditProfile struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Format string `json:"format"`
	Model  string `json:"model"`
}

type llmTransitionAudit struct {
	Mode     string           `json:"mode"` // automatic | manual | exhausted
	Reason   string           `json:"reason"`
	Previous *llmAuditProfile `json:"previous,omitempty"`
	Next     *llmAuditProfile `json:"next,omitempty"`
}

type llmActivityMetadata struct {
	LLMTransition llmTransitionAudit `json:"llm_transition"`
}

// taskLLMRuntime is the per-task LLM seam. It implements eino's
// model.ToolCallingChatModel, resolving WHICH provider serves a call at call
// time (agent binding → task chain with CAS revisions → global), so failover can
// swap providers underneath a stable runtime.
type taskLLMRuntime struct {
	s        *Server
	taskID   string
	agentKey string
	// tools, when non-nil, marks this as a WithTools-derived view: the tool set
	// is bound to the resolved provider lazily (per selection), never mutating
	// the shared provider instances.
	tools []*schema.ToolInfo
}

var _ model.ToolCallingChatModel = (*taskLLMRuntime)(nil)

type taskLLMError struct {
	taskID         string
	chainExhausted bool
	cause          error
}

func (e *taskLLMError) Error() string {
	if e.chainExhausted {
		return fmt.Sprintf("task %s LLM profile chain exhausted: %v", e.taskID, e.cause)
	}
	return e.cause.Error()
}

func (e *taskLLMError) Unwrap() error { return e.cause }

func isTaskLLMRuntimeError(err error) bool {
	var target *taskLLMError
	return errors.As(err, &target)
}

func isTaskLLMChainExhausted(err error) bool {
	var target *taskLLMError
	return errors.As(err, &target) && target.chainExhausted
}

// isQuotaExhaustedError is intentionally strict. A generic 429, auth error,
// network failure, or 5xx does not rotate providers; the response must explicitly
// identify quota, credits, billing balance, or payment exhaustion.
//
// The eino seam adds one typed fast path: acllm.StatusError carries the HTTP
// status structurally, so 402 (the code agent/quotaAwareTransport rewrites
// quota-429 responses into) is quota by definition; 401/403/5xx never are, even
// when the body echoes a quota phrase. Everything else — including a StatusError
// with any other status — falls through to agent.IsQuotaExhaustedMessage's
// text classification (which applies its own 401/403/5xx and transient
// rate-limit wording guards).
func isQuotaExhaustedError(err error) bool {
	if err == nil {
		return false
	}
	var se *acllm.StatusError
	if errors.As(err, &se) {
		switch {
		case se.StatusCode == http.StatusPaymentRequired:
			return true
		case se.StatusCode == http.StatusUnauthorized,
			se.StatusCode == http.StatusForbidden,
			se.StatusCode >= 500:
			return false
		default:
			return agent.IsQuotaExhaustedMessage(se.Body)
		}
	}
	return agent.IsQuotaExhaustedMessage(err.Error())
}

type taskLLMSelection struct {
	task      *Task
	profileID int64
	revision  int64
	provider  model.ToolCallingChatModel
	// retry 是这次选中的配置解析出来的重试参数(profile 覆盖 → 全局策略 → 内置默认)。
	// 同 provider 安全窗口重试按它走,所以换了 profile 就换一套重试节奏。
	retry agent.RetryConfig
}

type taskLLMStreamHooks struct {
	current    func() (taskLLMSelection, error)
	exhaust    func(taskLLMSelection, error) (db.TaskLLMTransition, error)
	transition func(taskLLMSelection, db.TaskLLMTransition, error)
}

// current resolves the provider this role runs on, by precedence:
// Agent 绑定 → 任务 LLM 配置链 → 全局/环境配置。
// 绑定优先于任务链：某个角色被显式指定了模型，就一直跑在那个模型上；绑定不存在或
// 构建失败时才降级到任务链，任务链为空时再降级到全局配置。
// 返回的 profile id 只有走任务链时才非零 —— streamTaskLLM 以此判断额度错误是否
// 应该推进任务的故障转移状态（绑定/全局路径不改任务链状态，沿用既有语义）。
func (r *taskLLMRuntime) current() (taskLLMSelection, error) {
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return taskLLMSelection{}, err
	}
	pt, err := r.s.m.pg.GetTask(taskNum)
	if err != nil {
		return taskLLMSelection{}, err
	}
	if pt == nil {
		return taskLLMSelection{}, fmt.Errorf("task %s not found", r.taskID)
	}
	r.s.syncTaskLLMState(pt)
	t, _ := r.s.m.Task(r.taskID)
	sel := taskLLMSelection{task: t, revision: pt.LLMChainRevision}
	if prov, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		sel.provider, sel.retry = prov, cfg.Retry
		return sel, nil
	}
	if len(pt.LLMProfileIDs) > 0 {
		if pt.ActiveLLMProfileID == nil {
			return sel, &taskLLMError{taskID: r.taskID, chainExhausted: true, cause: errors.New("all selected profiles are quota exhausted")}
		}
		sel.profileID = *pt.ActiveLLMProfileID
		prov, cfg, ok := r.s.providerForProfile(sel.profileID)
		if !ok {
			return sel, fmt.Errorf("LLM profile #%d is missing or invalid", sel.profileID)
		}
		sel.provider, sel.retry = prov, cfg.Retry
		return sel, nil
	}
	prov, cfg, ok := r.s.globalProvider()
	if !ok {
		return sel, fmt.Errorf("task %s has no available fallback LLM provider", r.taskID)
	}
	sel.provider, sel.retry = prov, cfg.Retry
	return sel, nil
}

// activeCfg resolves the task's currently-active LLM config, mirroring current()'s
// source precedence (agent binding → active chain profile → global). Read-only and
// best-effort: ok=false when nothing resolves, leaving the per-setting fallback to
// the caller. If failover switches profiles, the change takes effect on the next
// agent run (a fresh Session is built per run in captureRun).
func (r *taskLLMRuntime) activeCfg() (agent.Config, bool) {
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return agent.Config{}, false
	}
	pt, err := r.s.m.pg.GetTask(taskNum)
	if err != nil || pt == nil {
		return agent.Config{}, false
	}
	if _, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		return cfg, true
	}
	if len(pt.LLMProfileIDs) > 0 && pt.ActiveLLMProfileID != nil {
		if _, cfg, ok := r.s.providerForProfile(*pt.ActiveLLMProfileID); ok {
			return cfg, true
		}
	}
	if _, cfg, ok := r.s.globalProvider(); ok {
		return cfg, true
	}
	return agent.Config{}, false
}

// nonStreaming reports whether the task's currently-active LLM source is set to
// non-streaming. Unresolvable → streaming (false), the safe default.
func (r *taskLLMRuntime) nonStreaming() bool {
	cfg, ok := r.activeCfg()
	return ok && !cfg.Stream
}

// maxTokens returns the currently-active source's per-reply output cap.
// Unresolvable → 0, i.e. send no cap, matching the pre-setting behaviour.
func (r *taskLLMRuntime) maxTokens() int {
	cfg, _ := r.activeCfg() // 未解析出配置时是零值 0
	return cfg.MaxTokens
}

func parseTaskID(id string) (int64, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid task id %q", id)
	}
	return n, nil
}

// streamHooks builds the failover/exhaustion callbacks shared by Stream and
// Generate: how to read the current profile selection, how to mark it quota
// exhausted, and how to emit a failover transition.
func (r *taskLLMRuntime) streamHooks() taskLLMStreamHooks {
	return taskLLMStreamHooks{
		current: r.current,
		exhaust: func(selection taskLLMSelection, cause error) (db.TaskLLMTransition, error) {
			taskNum, _ := parseTaskID(r.taskID)
			transition, err := r.s.m.pg.MarkTaskLLMProfileQuotaExhaustedAtRevision(taskNum, selection.profileID, selection.revision, cause.Error())
			if err != nil {
				return transition, err
			}
			if pt, getErr := r.s.m.pg.GetTask(taskNum); getErr == nil && pt != nil {
				r.s.syncTaskLLMState(pt)
			}
			return transition, nil
		},
		transition: func(selection taskLLMSelection, transition db.TaskLLMTransition, cause error) {
			r.s.emitTaskLLMTransition(selection.task, transition, cause)
		},
	}
}

// Generate implements model.ToolCallingChatModel: the non-streaming task call.
// A non-streaming call is atomic — it never delivers partial output — so every
// failure is safe to retry on the same provider or advance the chain on quota,
// without risking duplicated model output or tool execution (the "committed"
// bookkeeping the streaming path needs is unnecessary here).
func (r *taskLLMRuntime) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	ctx = llmrec.WithTaskID(ctx, r.taskID)
	return completeTaskLLM(ctx, r.taskID, input, r.tools, r.streamHooks(), opts...)
}

// Stream implements model.ToolCallingChatModel: the streaming task call, with
// the per-task failover/quota-advance semantics of streamTaskLLM.
func (r *taskLLMRuntime) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	ctx = llmrec.WithTaskID(ctx, r.taskID)
	return streamTaskLLM(ctx, r.taskID, input, r.tools, r.streamHooks(), opts...)
}

// WithTools implements model.ToolCallingChatModel by returning a runtime view
// that binds the tool set to whichever provider the next calls resolve to. The
// receiver is not mutated, so sibling runtimes (other roles, other tasks) keep
// using the providers unbound.
func (r *taskLLMRuntime) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	c := *r
	c.tools = tools
	return &c, nil
}

// bindSelection binds the view's tool set (if any) to the resolved provider.
// A binding failure is local and deterministic — nothing was sent — so it
// surfaces instead of burning retries or failover state.
func bindSelection(p model.ToolCallingChatModel, tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	if len(tools) == 0 {
		return p, nil
	}
	return p.WithTools(tools)
}

func completeTaskLLM(ctx context.Context, taskID string, input []*schema.Message, tools []*schema.ToolInfo, hooks taskLLMStreamHooks, opts ...model.Option) (*schema.Message, error) {
	for {
		selection, err := hooks.current()
		if err != nil {
			return nil, err
		}
		prov, err := bindSelection(selection.provider, tools)
		if err != nil {
			return nil, err
		}
		var callErr error
		var msg *schema.Message
		// 同 provider 安全窗口重试:非流式调用要么整体成功、要么整体失败,没有
		// 中途已交付输出的问题,所以任何瞬时失败都可原样重试。
		retries, backoffOf := sameProviderRetryPolicy(selection.retry)
		for attempt := 0; ; attempt++ {
			msg, callErr = prov.Generate(ctx, input, opts...)
			if callErr != nil && ctx.Err() == nil &&
				attempt < retries && isRetryableStreamError(callErr) {
				backoff := backoffOf(attempt)
				log.Printf("[task-llm] task %s 非流式调用失败,%v 后同 provider 重试 (%d/%d): %v",
					taskID, backoff, attempt+1, retries, callErr)
				if sleepCtx(ctx, backoff) {
					break // 退避期间 ctx 取消 → 停止重试
				}
				continue
			}
			break
		}
		if callErr == nil {
			return msg, nil
		}
		// profileID=0: 显式链已被清空;非额度错误:透传。二者都不改任务 failover 状态。
		if selection.profileID == 0 || !isQuotaExhaustedError(callErr) {
			return nil, callErr
		}
		transition, markErr := hooks.exhaust(selection, callErr)
		if markErr != nil {
			return nil, fmt.Errorf("mark profile quota exhausted after %v: %w", callErr, markErr)
		}
		if transition.Advanced && !transition.Stale && hooks.transition != nil {
			hooks.transition(selection, transition, callErr)
		}
		if !transition.Stale && transition.NextProfileID == nil {
			return nil, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: callErr}
		}
		// 没有任何输出交付给调用方,换下一个 profile 重放同一逻辑请求是安全的。
	}
}

// streamTaskLLM runs the task router over an eino stream: resolve the selection,
// establish the stream with same-provider safe-window retries, and hand out a
// reader only once a COMMITTING chunk exists (llmpool.MessageCommitsOutput).
// Everything before that point is the safe window — a failure there may retry on
// the same provider (transient), advance the task chain (quota), or surface
// as-is (ctx cancel / deterministic 4xx) without anything having been delivered.
// A mid-stream failure (after the committing chunk) is surfaced as-is — except
// that a quota exhaustion still advances the chain so the NEXT call starts on
// the fallback profile, and is re-wrapped as a taskLLMError so the worker does
// not replay the intent and duplicate whatever the partial output drove.
//
// Norma-era note: the old iter.Seq2 version flushed buffered non-committing
// events (message-start frames) before a terminal error, because a sequence has
// no dedicated error channel. eino's (reader, error) contract is "err != nil ⇒
// nothing was delivered"; non-committing frames carry no output, so dropping
// them when surfacing an error is lossless.
func streamTaskLLM(ctx context.Context, taskID string, input []*schema.Message, tools []*schema.ToolInfo, hooks taskLLMStreamHooks, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	for {
		selection, err := hooks.current()
		if err != nil {
			return nil, err
		}
		prov, err := bindSelection(selection.provider, tools)
		if err != nil {
			return nil, err
		}
		retries, backoffOf := sameProviderRetryPolicy(selection.retry)
		var (
			pending []*schema.Message // non-committing chunks of the failed attempt
			first   *schema.Message   // the committing chunk
			sr      *schema.StreamReader[*schema.Message]
			callErr error
		)
		// 同 provider 安全窗口重试:提交之前(还没向调用方交付任何输出)的瞬时失败
		// 可以原样重放,不会重复模型输出或工具执行。ctx 取消、或确定性/额度错误则
		// 跳出,交给下方原有的透传/故障转移逻辑。
		for attempt := 0; ; attempt++ {
			pending, first, callErr = nil, nil, nil
			sr, callErr = prov.Stream(ctx, input, opts...)
			if callErr == nil {
				// Establish through the safe window: skip non-committing frames.
				for {
					var chunk *schema.Message
					chunk, callErr = sr.Recv()
					if callErr != nil {
						break
					}
					if llmpool.MessageCommitsOutput(chunk) {
						first = chunk
						break
					}
					pending = append(pending, chunk)
				}
				if callErr == nil {
					// Committed: this selection serves the caller. From here a
					// failure is mid-stream and never replayed on this or any
					// other provider (see taskReplayReader).
					return taskReplayReader(taskID, selection, pending, first, sr, hooks), nil
				}
				sr.Close()
				if errors.Is(callErr, io.EOF) {
					// Clean completion before any committing chunk: an empty
					// (usage-only) reply. Flush what was buffered; nothing to
					// retry or fail over.
					return schema.StreamReaderFromArray(pending), nil
				}
			}
			if ctx.Err() == nil && attempt < retries && isRetryableStreamError(callErr) {
				backoff := backoffOf(attempt)
				log.Printf("[task-llm] task %s 提交前流失败,%v 后同 provider 重试 (%d/%d): %v",
					taskID, backoff, attempt+1, retries, callErr)
				if sleepCtx(ctx, backoff) {
					break // 退避期间 ctx 取消 → 停止重试
				}
				continue
			}
			break
		}
		// profileID=0 means the explicit chain was cleared while this stable task
		// bundle was still in use. Agent/global fallback errors follow the legacy
		// behavior and never mutate task failover state.
		if selection.profileID == 0 || !isQuotaExhaustedError(callErr) {
			return nil, callErr
		}
		transition, markErr := hooks.exhaust(selection, callErr)
		if markErr != nil {
			return nil, fmt.Errorf("mark profile quota exhausted after %v: %w", callErr, markErr)
		}
		if transition.Advanced && !transition.Stale && hooks.transition != nil {
			hooks.transition(selection, transition, callErr)
		}
		if !transition.Stale && transition.NextProfileID == nil {
			return nil, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: callErr}
		}
		// No chunk reached the caller, so replaying the same logical request on
		// the next profile cannot duplicate model output or tool execution.
	}
}

// taskReplayReader pumps the committed member's stream to the caller: the
// buffered non-committing chunks and the committing chunk first
// (buffer-and-prepend), then everything the provider still produces.
//
// A mid-stream failure after this point is never replayed — the partial output
// may already have driven tool execution. A quota exhaustion STILL advances the
// task chain (so the next call starts on the fallback profile) and is surfaced
// as a taskLLMError, which the worker treats as router-handled instead of
// replaying the intent; every other failure surfaces as-is.
func taskReplayReader(taskID string, selection taskLLMSelection, pending []*schema.Message, first *schema.Message, rest *schema.StreamReader[*schema.Message], hooks taskLLMStreamHooks) *schema.StreamReader[*schema.Message] {
	out, sw := schema.Pipe[*schema.Message](len(pending) + 1 + 8)
	out.SetAutomaticClose() // an abandoned reader must not leak the pump goroutine
	go func() {
		defer sw.Close()
		defer rest.Close()
		for _, c := range pending {
			if sw.Send(c, nil) {
				return // caller stopped consuming
			}
		}
		if sw.Send(first, nil) {
			return
		}
		for {
			chunk, err := rest.Recv()
			if err == nil {
				if sw.Send(chunk, nil) {
					return
				}
				continue
			}
			if errors.Is(err, io.EOF) {
				return
			}
			surfaced := err
			if selection.profileID != 0 && isQuotaExhaustedError(err) {
				transition, markErr := hooks.exhaust(selection, err)
				if markErr != nil {
					// Output may already have driven tool execution. Report the
					// persistence failure, but classify it as router-handled so
					// the worker does not replay the entire intent and duplicate
					// those side effects.
					surfaced = &taskLLMError{
						taskID: taskID,
						cause:  fmt.Errorf("mark profile quota exhausted after %v: %w", err, markErr),
					}
				} else {
					if transition.Advanced && !transition.Stale && hooks.transition != nil {
						hooks.transition(selection, transition, err)
					}
					surfaced = &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: err}
				}
			}
			sw.Send(nil, surfaced)
			return
		}
	}()
	return out
}

// 提交前安全窗口内、对同一 provider 的【默认】重试次数。SDK 的建连重试只覆盖
// Stream() 调用本身;拿到 200 之后的首个提交块之前断流 / overloaded / 流内 429 等
// 瞬时故障会直接冒泡,零重试。只要一个 token 都还没交给调用方(没有提交块),重放
// 完全相同的请求就不会重复模型输出或工具副作用,因此这里补一层同 provider 退避重试,
// 把这类抖动挡在意图整体重跑之前。可被 LLM 配置的重试覆盖/全局重试策略改写。
const sameProviderStreamRetries = 2

// sameProviderRetryBackoff 是第 attempt 次重试前的【默认】退避(0.5s、1s…,上限 4s),
// 与 SDK 的指数梯度同风格但封顶更小,避免拖住 worker 的收尾/取消响应。
// 以变量形式暴露,便于测试将退避置零。
var sameProviderRetryBackoff = func(attempt int) time.Duration {
	return min(500*time.Millisecond*(1<<attempt), 4*time.Second)
}

// sameProviderRetryPolicy 解析这次调用用哪套同 provider 重试参数:配置里设了次数就
// 用配置的(负数 = 关掉这层重试),设了间隔就把指数退避换成固定间隔,两者都没设时
// 与改可配之前逐字节一致。
func sameProviderRetryPolicy(r agent.RetryConfig) (retries int, backoff func(int) time.Duration) {
	retries, backoff = sameProviderStreamRetries, sameProviderRetryBackoff
	if r.StreamAttempts != 0 {
		retries = max(r.StreamAttempts, 0)
	}
	if r.StreamInterval > 0 {
		d := r.StreamInterval
		backoff = func(int) time.Duration { return d }
	}
	return retries, backoff
}

// isRetryableStreamError 判断「提交前的流失败」是否值得在同一 provider 上重放。
// 瞬时的传输中断 / 供应商过载 / 限流会自行恢复,可安全重试;而以下三类不重试:
//   - 额度耗尽:交给 profile 故障转移处理,别在这里白烧重试
//   - 上下文过长:相同请求重放也没用,交给 harness 的 reactive 压缩兜底
//   - 4xx 确定性拒绝(400/401/403/404/422):到哪个 provider 都一样会失败
func isRetryableStreamError(err error) bool {
	if err == nil {
		return false
	}
	if isQuotaExhaustedError(err) {
		return false
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "too long") || strings.Contains(s, "context length") ||
		strings.Contains(s, "context_length") || strings.Contains(s, "maximum context") {
		return false
	}
	// 状态码用 llmpool 的统一提取(识别 acllm.StatusError 类型与各家 SDK 的
	// "status 400" / "status code: 400" 两种文本形态),与故障转移的判定同源。
	switch llmpool.StatusOf(err) {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return false
	}
	// 其余(传输 reset/EOF/timeout、408/429/5xx、流内 error 事件如 anthropic
	// overloaded_error 等)一律视为瞬时,允许重试。
	return true
}

// CompactionWindow mirrors current()'s precedence so the context window always
// matches the provider the role will actually stream on.
func (r *taskLLMRuntime) CompactionWindow() int {
	if _, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		return cfg.CompactionWindow()
	}
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return (agent.Config{}).CompactionWindow()
	}
	chain, err := r.s.m.pg.TaskLLMProfiles(taskNum)
	if err != nil {
		return (agent.Config{}).CompactionWindow()
	}
	if len(chain) == 0 {
		if _, cfg, ok := r.s.globalProvider(); ok {
			return cfg.CompactionWindow()
		}
		return (agent.Config{}).CompactionWindow()
	}
	minimum := 0
	for _, entry := range chain {
		if cfg, ok := r.s.loadProfileConfig(entry.ProfileID); ok {
			window := cfg.CompactionWindow()
			if minimum == 0 || window < minimum {
				minimum = window
			}
		}
	}
	if minimum == 0 {
		return (agent.Config{}).CompactionWindow()
	}
	return minimum
}

// agentBindingProvider resolves the profile a role is explicitly bound to
// (agents.llm_profile_id) — the highest-precedence level for task agents. ok=false
// when the role has no binding or the bound profile no longer builds, so callers
// fall through to the task chain. A bound profile stays exclusive unless
// llm_pool_bind_fallback is on, which is what poolForBinding encodes.
func (s *Server) agentBindingProvider(agentKey string) (model.ToolCallingChatModel, agent.Config, bool) {
	id := s.effectiveProfileForAgent(agentKey, nil)
	if id == nil {
		return nil, agent.Config{}, false
	}
	prov, cfg, ok := s.providerForProfile(*id)
	if !ok {
		return nil, agent.Config{}, false
	}
	return s.poolForBinding(*id, prov, cfg), cfg, true
}

// globalProvider returns the process-wide provider (persisted active profile or
// environment config) — the last resort once a role has neither a binding nor a
// task chain.
func (s *Server) globalProvider() (model.ToolCallingChatModel, agent.Config, bool) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if !s.llmOn || s.llmProv == nil {
		return nil, agent.Config{}, false
	}
	return s.llmProv, s.llmCfg, true
}

// taskRuntimeAvailable reports whether every listed role can resolve a provider
// under the runtime precedence in current(): the role's own binding first, then
// the task chain, then global. An exhausted chain is a hard stop for unbound
// roles rather than a silent fall through to global — same as current().
func (s *Server) taskRuntimeAvailable(t *Task, agentKeys ...string) bool {
	if t == nil || len(agentKeys) == 0 {
		return false
	}
	state := t.llmStateSnapshot()
	unboundReady := false
	if len(state.ProfileIDs) > 0 {
		if state.ActiveID != nil {
			_, _, unboundReady = s.providerForProfile(*state.ActiveID)
		}
	} else {
		_, _, unboundReady = s.globalProvider()
	}
	for _, key := range agentKeys {
		if _, _, ok := s.agentBindingProvider(key); ok {
			continue
		}
		if !unboundReady {
			return false
		}
	}
	return true
}

func (s *Server) invalidateTaskAgents() {
	s.taskAgentMu.Lock()
	s.taskAgents = map[string]*taskAgentBundle{}
	s.taskAgentMu.Unlock()
}

func (s *Server) agentsForTask(t *Task) *taskAgentBundle {
	s.taskAgentMu.Lock()
	defer s.taskAgentMu.Unlock()
	if bundle := s.taskAgents[t.ID]; bundle != nil {
		return bundle
	}
	goalRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "goals"}
	plannerRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "planner"}
	workerRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "worker"}
	mainRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "mainagent"}
	tx := transcript.NewStore(filepath.Join(s.m.dir, "transcripts"))
	window := workerRuntime.CompactionWindow()
	wk := agent.NewWorker(workerRuntime, "task-router", s.m.dir, tx, window, s.agentMaxTurns("worker"))
	wk.SetFindingRecorder(s.evidenceStore())
	wk.SetCompactionWindowResolver(workerRuntime.CompactionWindow)
	wk.SetNonStreaming(workerRuntime.nonStreaming) // 按任务当前激活 profile 的流式开关(每轮读)
	wk.SetMaxTokens(workerRuntime.maxTokens)       // 同上,输出上限也跟随当前激活 profile
	wk.SetNoaEnabled(s.m.NoaCompactionEnabled)     // 实验功能:noa 上下文压缩(平台级开关,每 run 读)
	wk.SetRunTimeout(time.Duration(s.agentRunSeconds("worker")) * time.Second)
	wk.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	wk.SetWebSearch(s.webSearchFor("worker"))
	wk.SetConstraintInject(s.constraintInjectWorker) // 操作约束注入 worker(可配置,默认开)
	pl := agent.NewPlanner(plannerRuntime, "task-router", s.m.dir, tx, plannerRuntime.CompactionWindow(), s.agentMaxTurns("planner"))
	pl.SetFindingRecorder(s.evidenceStore())
	pl.SetCompactionWindowResolver(plannerRuntime.CompactionWindow)
	pl.SetNonStreaming(plannerRuntime.nonStreaming)
	pl.SetMaxTokens(plannerRuntime.maxTokens)
	pl.SetNoaEnabled(s.m.NoaCompactionEnabled) // 实验功能:noa 上下文压缩(平台级开关,每 run 读)
	pl.SetKillWork(s.engine.KillWork)
	pl.SetSteerWork(s.engine.SteerWork)
	pl.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	pl.SetWebSearch(s.webSearchFor("planner"))
	pl.SetConstraintInject(s.constraintInjectPlanner) // 操作约束注入 planner(可配置,默认开)
	// cold-digest §7: 冷节点后台压缩。引擎经权威解析器实际驱动的就是这套 per-task planner
	// (agentsForTask),Compactor 必须接在这里。走任务路由的 planner provider(§4:与 agent
	// 同模型,随任务 LLM 链解析),压缩用 Generate 一次性生成 body。
	pl.SetCompactor(agent.NewCompactor(plannerRuntime, "task-router"))
	main := agent.NewMainAgent(mainRuntime, "task-router", s.m.dir, tx, mainRuntime.CompactionWindow(), s.agentMaxTurns("mainagent"))
	main.SetFindingRecorder(s.evidenceStore())
	main.SetCompactionWindowResolver(mainRuntime.CompactionWindow)
	main.SetNonStreaming(mainRuntime.nonStreaming)
	main.SetMaxTokens(mainRuntime.maxTokens)
	main.SetNoaEnabled(s.m.NoaCompactionEnabled) // 实验功能:noa 上下文压缩(平台级开关,每 run 读)
	main.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	main.SetWebSearch(s.webSearchFor("mainagent"))
	main.SetSteerWork(s.engine.SteerWork) // steer_work：人对运行中 work 实时纠偏
	bundle := &taskAgentBundle{
		runtime: goalRuntime, plannerRuntime: plannerRuntime, workerRuntime: workerRuntime,
		mainRuntime: mainRuntime, pl: pl, wk: wk, main: main,
	}
	s.taskAgents[t.ID] = bundle
	return bundle
}

func (s *Server) syncTaskLLMState(pt *db.Task) {
	if pt == nil {
		return
	}
	id := fmt.Sprintf("%d", pt.ID)
	s.m.mu.Lock()
	if task := s.m.tasks[id]; task != nil {
		task.setLLMState(pt.LLMProfileID, pt.ActiveLLMProfileID, pt.LLMProfileIDs, pt.LLMChainRevision, pt.LLMFailoverState, pt.LLMFailoverReason)
	}
	s.m.mu.Unlock()
}

func (s *Server) emitTaskLLMTransition(t *Task, transition db.TaskLLMTransition, cause error) {
	if t == nil {
		return
	}
	previous := s.llmAuditProfile(transition.PreviousProfileID)
	var next *llmAuditProfile
	if transition.NextProfileID != nil {
		next = s.llmAuditProfile(*transition.NextProfileID)
	}
	mode := "automatic"
	kind := "llm_switch"
	summary := fmt.Sprintf("%s 额度不足", llmAuditProfileLabel(previous))
	if transition.NextProfileID != nil {
		summary += fmt.Sprintf("，后续调用切换到 %s", llmAuditProfileLabel(next))
	} else {
		mode = "exhausted"
		kind = "llm_failover"
		summary += "，配置链已耗尽"
	}
	metadata, _ := json.Marshal(llmActivityMetadata{LLMTransition: llmTransitionAudit{
		Mode: mode, Reason: cause.Error(), Previous: previous, Next: next,
	}})
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: kind, IsError: transition.ChainExhausted, Summary: summary, Detail: cause.Error(), Metadata: metadata})
	log.Printf("[llm-failover] task %s: %s", t.ID, summary)
}

func (s *Server) llmAuditProfile(id int64) *llmAuditProfile {
	if id <= 0 || s.m == nil || s.m.pg == nil {
		return nil
	}
	p, err := s.m.pg.ProfileByID(id)
	if err != nil || p == nil {
		return &llmAuditProfile{ID: id, Name: fmt.Sprintf("配置 #%d", id)}
	}
	return &llmAuditProfile{ID: p.ID, Name: p.Name, Format: p.Format, Model: p.Model}
}

func llmAuditProfileLabel(profile *llmAuditProfile) string {
	if profile == nil {
		return "默认配置"
	}
	name := profile.Name
	if name == "" {
		name = fmt.Sprintf("配置 #%d", profile.ID)
	}
	detail := []string{}
	if profile.Format != "" {
		detail = append(detail, profile.Format)
	}
	if profile.Model != "" {
		detail = append(detail, profile.Model)
	}
	if len(detail) == 0 {
		return name
	}
	return fmt.Sprintf("%s（%s）", name, strings.Join(detail, " / "))
}

func sameOptionalID(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (s *Server) emitManualTaskLLMSwitch(t *Task, previousID, nextID *int64) db.Activity {
	previous := (*llmAuditProfile)(nil)
	next := (*llmAuditProfile)(nil)
	if previousID != nil {
		previous = s.llmAuditProfile(*previousID)
	}
	if nextID != nil {
		next = s.llmAuditProfile(*nextID)
	}
	summary := fmt.Sprintf("用户手动将任务 LLM 从 %s 切换到 %s", llmAuditProfileLabel(previous), llmAuditProfileLabel(next))
	metadata, _ := json.Marshal(llmActivityMetadata{LLMTransition: llmTransitionAudit{
		Mode: "manual", Reason: "用户手动切换任务 LLM", Previous: previous, Next: next,
	}})
	return s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "llm_switch", Summary: summary, Detail: summary, Metadata: metadata})
}
