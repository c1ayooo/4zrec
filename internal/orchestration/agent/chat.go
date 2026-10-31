package agent

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/kernel/askernel"
	"github.com/c1ayooo/4zrec/internal/kernel/transcript"
	"github.com/c1ayooo/4zrec/internal/toolface/guard"
	"github.com/c1ayooo/4zrec/internal/toolface/intercept"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
	"github.com/cloudwego/eino/components/model"
)

// ChatAgent is the generic, task-independent conversational runner behind the chat
// page. It generalizes MainAgent.Chat: any agent (built-in OR a custom one, by
// key) can be chatted with, multi-turn history resumed from the transcript. It is
// a PURE ASSISTANT — base tools are the kernel DefaultTools (Bash/Read/Write/Edit/
// LS/Glob/Grep) plus whatever skills/MCP the key is made visible; NO pentest
// graph/task context is injected (that stays exclusive to MainAgent).
type ChatAgent struct {
	prov           model.ToolCallingChatModel // the run's chat model (shared instance)
	model          string
	workDir        string
	tx             *transcript.Store
	window         int
	proxyAddr      string
	targetsEnvFn   targetsEnvResolver // 会话级目标变量(ZREC_TARGETS)解析器;nil=不注入
	proxyCACert    string
	webSearch      WebSearchOpts
	guard          *guard.Guard // optional; nil disables intercept hooks for chat
	nonStreamingFn func() bool  // resolver: use non-streaming model path? (nil = streaming)
	noaEnabledFn   func() bool  // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn    func() int   // resolver: per-reply output cap (nil/0 = send no cap)
	// platformToolsFn/bindingSpecFn 由宿主（server）按会话注入：平台操作工具
	// （列项目/列任务/绑定，sessionID 形如 conv-<id>）与 system prompt 的绑定说明。
	// nil = 不注入。
	platformToolsFn func(sessionID string) []actool.CoreTool
	bindingSpecFn   func(sessionID string) string
}

func NewChatAgent(prov model.ToolCallingChatModel, model, workDir string, tx *transcript.Store, window int) *ChatAgent {
	return &ChatAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window}
}

// SetNonStreaming wires a resolver deciding whether chat runs use the
// non-streaming model path (true = non-streaming). nil/unset = streaming.
func (c *ChatAgent) SetNonStreaming(fn func() bool) { c.nonStreamingFn = fn }

func (c *ChatAgent) nonStreaming() bool { return c.nonStreamingFn != nil && c.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether chat runs use the experimental
// noa context-compression mechanism. nil/unset = off (built-in compaction). Read
// per run so the settings toggle takes effect without rebuilding the agent.
func (c *ChatAgent) SetNoaEnabled(fn func() bool) { c.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (c *ChatAgent) SetMaxTokens(fn func() int) { c.maxTokensFn = fn }

func (c *ChatAgent) maxTokens() int {
	if c.maxTokensFn == nil {
		return 0
	}
	return c.maxTokensFn()
}

// SetProxy points the chat agent's WebFetch/Bash at the recording proxy plus the
// CA cert it trusts (empty addr = direct). Kept for parity with the other agents.
func (c *ChatAgent) SetProxy(addr, caCert string) { c.proxyAddr, c.proxyCACert = addr, caCert }

// SetTargetsEnv 注入会话级目标环境变量解析器(ZREC_TARGETS,见 targets_env.go)。nil=不注入。
func (c *ChatAgent) SetTargetsEnv(fn func(sessionID string) []string) { c.targetsEnvFn = fn }

func (c *ChatAgent) targetsEnv(sessionID string) []string {
	return targetsEnv(c.targetsEnvFn, sessionID)
}

// SetWebSearch selects the web_search backend for the chat agent (off by default).
func (c *ChatAgent) SetWebSearch(o WebSearchOpts) { c.webSearch = o }

// SetGuard attaches a guard (with user-configured intercept rules) to this chat
// agent. Must be called before Chat; safe to call multiple times.
func (c *ChatAgent) SetGuard(g *guard.Guard) { c.guard = g }

// SetPlatformTools 注入按会话解析的平台工具（list_projects/list_tasks/
// bind_conversation/get_binding）。返回 nil 表示该会话不注入。
func (c *ChatAgent) SetPlatformTools(fn func(sessionID string) []actool.CoreTool) { c.platformToolsFn = fn }

// SetBindingSpec 注入每轮重读的会话绑定说明（拼进 system prompt 末尾）。
func (c *ChatAgent) SetBindingSpec(fn func(sessionID string) string) { c.bindingSpecFn = fn }

func (c *ChatAgent) bindingBlock(sessionID string) string {
	if c.bindingSpecFn == nil {
		return ""
	}
	return c.bindingSpecFn(sessionID)
}

// chatWorkDirSpec returns a working-directory notice appended to every chat
// agent's system prompt. Mirrors artifactSpec but without pentest-specific
// wording ("payload", "抓响应体") that would be odd in a general assistant.
func chatWorkDirSpec(workDir string) string {
	return "\n\n**文件输出规约**：需要写文件时，一律写到工作目录 " + workDir + "（这是默认 CWD，相对路径即落在这里，也可用该绝对路径）——不要写 /tmp 或其他绝对路径。"
}

// chatSystem renders the DB-managed prompt body for agentKey. Custom agents have
// no per-key in-code default, so DefaultAssistantPrompt is the render fallback.
// 渗透类 chat agent(pentest/recon/auto)额外注入代码固定的 HTTP 工具优先级,
// 页面改提示词也删不掉。
func chatSystem(agentKey, dataDir, workDir string) string {
	body := renderSystem(agentKey, DefaultAssistantPrompt, chatVars{DataDir: dataDir, Now: nowStr()}) + chatWorkDirSpec(workDir)
	if httpProbePriorityAgents[agentKey] {
		body += httpToolPolicyBlock() + targetEnvPolicyBlock()
	}
	if diffProbeAgents[agentKey] {
		body += diffProbePolicyBlock()
	}
	return body
}

// chatVars carries the runtime variables a custom agent's prompt may reference.
// DataDir (server data root) + Now (server wall-clock, refreshed each turn) are the
// universal ones; any other {{.X}} fails to render and falls back to
// DefaultAssistantPrompt.
type chatVars struct{ DataDir, Now string }

// Chat runs ONE turn of a conversation with the agent identified by agentKey,
// resuming prior history keyed by sessionID. maxTurns is the per-turn agent step
// budget (0 = unlimited). maxDuration is the wall-clock run budget per turn
// (0 = unlimited); the timer resets each time Chat is called, so a new user
// message always starts a fresh countdown. webSearch gates network search for
// THIS agent (the global backend/key still come from the chat agent's config,
// but each agent decides on/off). emit receives each execution step (thinking /
// tool_use / tool_result / text / result), tagged with the agent key as the
// worker lane.
func (c *ChatAgent) Chat(ctx context.Context, agentKey, sessionID, message string, maxTurns int, maxDuration time.Duration, webSearch bool, emit func(db.Activity)) (string, error) {
	// gate the global web-search opts by this agent's own flag.
	ws := c.webSearch
	if !webSearch {
		ws.Enabled = false
	}

	// Per-session working directory: <workDir>/sessions/<sessionID>/
	// Isolates file writes across conversations, mirroring how workers use i<intentID>/.
	sessionWorkDir := filepath.Join(c.workDir, "sessions", sessionID)
	_ = os.MkdirAll(sessionWorkDir, 0o755)
	ctx = intercept.WithReviewWorkingDirectory(ctx, sessionWorkDir)

	// Pure assistant: DefaultTools as the base; AugmentTools layers in the key's
	// visible skills/MCP and lets the DB tools table filter/override. DefaultTools
	// have no tools-table rows, so they always pass through.
	base := actool.DefaultTools()
	if c.platformToolsFn != nil {
		if pt := c.platformToolsFn(sessionID); len(pt) > 0 {
			base = append(base, pt...) // 同为无行宿主工具，ToolResolve 原样放行
		}
	}
	ctx = WithRunInfo(ctx, RunInfo{SessionID: sessionID})
	tools, def, cleanup := AugmentTools(ctx, agentKey, base)
	defer cleanup()

	system := deferredSystem(chatSystem(agentKey, c.workDir, sessionWorkDir)+c.bindingBlock(sessionID), def)
	// 会话级临时待办（TodoWrite）+ 后台任务工具：norma 内核自动注入的两类会话工具，
	// askernel 交给宿主装配（sessionTools）。
	todos := actool.NewTodoStore()
	opts := askernel.Options{
		Model:          c.prov,
		SystemPrompt:   system,
		Tools:          sessionTools(tools, todos, true),
		DeferredTools:  def.Deferred,
		Unlock:         def.Unlock,
		PermissionMode: actool.ModeBypass,
		EnableWebFetch: true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetch:       actool.WebFetchConfig{Proxy: c.proxyAddr, CACert: c.proxyCACert},
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// Proxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch: ws.Enabled,
		WebSearch: actool.WebSearchConfig{
			Backend:         ws.Backend,
			BraveAPIKey:     ws.BraveKey,
			TavilyAPIKey:    ws.TavilyKey,
			DeepSeekBaseURL: ws.DeepSeekBaseURL,
			DeepSeekAPIKey:  ws.DeepSeekAPIKey,
			DeepSeekModel:   ws.DeepSeekModel,
			Proxy:           ws.Proxy,
		},
		BashEnv:     append(proxyEnv(c.proxyAddr, c.proxyCACert), c.targetsEnv(sessionID)...), // Bash 子命令默认走代理+信任 CA + ZREC_TARGETS
		WorkingDir:  sessionWorkDir,
		MaxTurns:    maxTurns,
		MaxDuration: maxDuration,
		Compaction:  compactionConfig(c.window),
		Todos:       todos,
		// large tool output spills to cmd-output/ under the session dir.
		// 截断上限用默认(30000 字符)。
		ToolOutputDir: filepath.Join(sessionWorkDir, "cmd-output"),
		// 命中预算(步数)→ 内核跑收尾:输出一句总结。Prompt 与收尾轮数按本 agent key 后台可编辑
		// (自定义 agent 各自一份;留空/0 用通用默认:10 轮)。
		Settlement:   wrapupSettlement(agentKey, nil),
		NonStreaming: c.nonStreaming(), // 该 profile 选非流式时按整发收发
		MaxTokens:    c.maxTokens(),    // 0 = 不发上限,由服务端默认值决定
	}
	if c.guard != nil {
		// guard's registry is askernel-native: it implements HookRunner directly.
		opts.Hooks = c.guard.Hooks()
	}
	runRef := &sessionRef{}
	withRunTrace(&opts, runRef) // correlate tool calls into the intercept trace pre-review
	if c.tx != nil {            // persist raw human↔AI conversation; one accumulating file per thread
		opts.Transcript = c.tx
		opts.SessionID = sessionID
	}
	// 实验功能:开启后由 noa 接管上下文压缩(归档集中在 <workDir>/noa/<SessionID> 下,持久)。
	enableNoa(&opts, c.noaEnabledFn, c.workDir, "chat-"+sessionID, noaWarn("chat-"+sessionID))
	ctx = attachSideCapture(ctx, &opts)
	s := askernel.NewSession(opts)
	defer s.Close()
	// reload prior conversation so the agent has context across turns (each Chat is
	// a fresh session). First turn: no file yet → Resume loads nothing and proceeds.
	if c.tx != nil {
		_ = s.Resume(sessionID)
	}
	// re-unlock skill-gated MCPs from prior Skill() calls in the reloaded history so
	// revealed tools stay callable across the fresh session.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = agentKey
			emit(r)
		}
	}, runRef)
	return text, err
}
