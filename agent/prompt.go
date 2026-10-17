package agent

import (
	"bytes"
	"text/template"
	"time"
)

// PromptOverride, if set, returns the stored system-prompt template for an agent
// key and whether one exists. The server wires it to the PG agent_prompts table.
// When nil or no override exists, agents use their built-in default prompt — so
// behavior is identical until a user edits a prompt in the UI.
var PromptOverride func(agentKey string) (string, bool)

// Prompt-variable structs — fields mirror each agent's catalog (docs §5a) so a
// user template referencing a catalog variable renders; referencing anything else
// fails template execution and falls back to the built-in default.
type PlannerVars struct{ Goal, Scope, AssetSummary, DataDir, Now string }
type WorkerVars struct{ ProxyAddr, WorkerName, DataDir, Now string }
type MainVars struct{ Goal, AssetSummary, FindingsSummary, DataDir, Now string }
type GoalsVars struct{ EngagementDescription, DataDir, Now string }

// nowStr is the server-local wall-clock string exposed as the universal {{.Now}}
// prompt variable. renderSystem runs on every agent turn/round, so this is fresh
// each run — a prompt can subtract it from a fixed start stamp to reason about
// elapsed time (e.g. a timed benchmark's "last N hours" window).
func nowStr() string { return time.Now().Format("2006-01-02 15:04:05 MST") }

// renderSystem returns the rendered system-prompt BODY (段 [A]) for agentKey.
// Precedence: the DB-stored template (if any) over the built-in default template
// (def). BOTH are Go templates now — the built-in default is seeded into the DB
// verbatim, so the two paths render identically until a user edits the prompt.
// Rendering always runs (def used to be pre-substituted plain text; it is now a
// {{.Var}} template like the DB one). On any render error we fall back to the
// default template, then to the raw default string — an agent never starts with a
// half-rendered prompt. Callers append the code-owned tail (trafficTool / 中间产物
// 输出规约) AFTER this, so those can't be edited away via the DB body.
func renderSystem(agentKey, def string, vars any) string {
	tmpl := def
	if PromptOverride != nil {
		if t, ok := PromptOverride(agentKey); ok && t != "" {
			tmpl = t
		}
	}
	if out, err := renderTmpl(tmpl, vars); err == nil {
		return out
	}
	// DB template broke (e.g. references an out-of-catalog var) → code default.
	if out, err := renderTmpl(def, vars); err == nil {
		return out
	}
	return def
}

func renderTmpl(tmpl string, vars any) (string, error) {
	t, err := template.New("p").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, vars); err != nil {
		return "", err
	}
	return b.String(), nil
}

// httpToolPolicyBlock 是代码固定注入的尾巴(不入库、不可编辑):HTTP 请求必须
// 优先走平台结构化 http_probe;curl/wget 只是有明确理由时的降级手段。由
// worker/planner/pentest/recon/auto 的系统提示共用,页面改提示词也删不掉。
func httpToolPolicyBlock() string {
	return "\n\n**HTTP 工具优先级（硬规则）**：\n" +
		"- 一切 HTTP/HTTPS 请求**先走 http_probe**：单发、requests 批量、template+matrix/range 差分、`extract`（从响应提取登录 token/CSRF/Set-Cookie 等变量回填后续请求）、`cookie_jar`（批量内自动传递 Cookie）、`save_to_file`（大响应/二进制落盘）都在覆盖范围内；能一次完成的探测，禁止先写 curl 脚本。\n" +
		"- 只有以下明确覆盖不了的场景才允许 curl/wget，并且必须**在 record_fact 的 detail（或本轮总结）里写明原因**：\n" +
		"  ① 需要流式/长连接/原始报文（SSE、WebSocket、请求走私/畸形请求、TLS/证书细节）；\n" +
		"  ② 需要任意本地脚本处理（复杂解码、多步算法、非正则可表达的逻辑）；\n" +
		"  ③ 需要客户端证书（mTLS）等本工具没有的传输层参数；\n" +
		"  ④ 非 HTTP 协议（TCP/UDP/DNS 等，本就不该用 curl，按协议选工具）。\n" +
		"- 跨 http_probe 调用的会话：把上一包的 Set-Cookie 值显式放进下一次的 cookie/headers，不要因此退回 curl。\n" +
		"- 不要把“写脚本更顺手/更自由”当理由；没有写明例外原因就用 curl，视为违规操作。"
}

// httpProbePriorityAgents 是拿到 httpToolPolicyBlock 的 chat agent key
// (task 侧 worker/planner 在各自 system 里注入)。
var httpProbePriorityAgents = map[string]bool{
	"pentest": true, "recon": true, "auto": true,
}
