// 情报分析层(AI analyzer):把一条抓取来的漏洞通告整理成结构化的中文分析
// —— 中文标题/简介、漏洞原理、攻击范围、可运行的 Python PoC。移植自 ai_bobao
// 的 analyzer(「AI 根据公开思路补全漏洞情报」),但落在 Postgres 而非目录文件,
// 且沿用 report 子系统的注入式补全接缝(能力包不感知 agent/provider 细节)。
//
// 铁律(与 ai_bobao 一致):只依据给定情报与公开漏洞原理作答,不臆造厂商/版本/
// 接口等具体信息;CVE、组件名、函数名、路径保留原文;PoC 只做无损的验证性请求。
package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// Completer 是宿主注入的「system+user → text」单次补全。server 侧把它适配到
// 平台激活的 LLM profile(低温、有界输出)。为 nil 时整条分析链跳过,与
// report.CompleteFunc 缺席时的降级语义一致。
type Completer func(ctx context.Context, system, user string, maxTokens int) (string, error)

// LLM 汇总分析用到的模型能力。Model 可为 nil,仅用于在产物里记录来源模型。
type LLM struct {
	Complete Completer
	Model    func() string
}

// PoC 归属取值(poc_origin)。
const (
	pocOriginAI       = "ai"       // 模型生成的可运行 PoC
	pocOriginUpstream = "upstream" // 上游仓库已有 PoC,但只有链接没有代码
	pocOriginNone     = "none"     // 无 PoC
)

const (
	analysisMaxTokens = 3000
	analysisTimeout   = 3 * time.Minute
)

const sysAnalysis = `你是资深漏洞分析专家，熟悉漏洞披露通告、CVE 与可利用性验证。把一条漏洞情报整理成结构化的中文分析，严格只输出 JSON，不要 markdown 代码块，不要任何额外解释。

铁律：
- 只依据给定情报与公开的漏洞原理作答。**不要臆造**厂商、版本号、接口路径、参数名等具体信息；无法确定的字段留空字符串，不要编造。
- CVE 编号、组件名、函数名、接口路径一律保留原文，不要翻译、不要改写大小写。
- PoC 必须是可直接运行的 Python 3 脚本：目标地址用顶部占位变量（如 TARGET），依赖仅限标准库或 requests，只做无损的验证性请求（判断漏洞是否存在），**不得包含破坏性、持久化或横向移动操作**。无法可靠构造时 poc 字段置 null。
- 输出字段：title_zh(中文标题，简短)、description_zh(中文简介，2-4 句)、principle(漏洞原理，说明成因与触发条件)、attack_scope(攻击范围，说明影响的产品/版本/前置条件)、poc(对象 {"language","code"} 或 null)。`

const userAnalysis = `请分析以下漏洞情报。

标题：%s
来源：%s
严重等级：%s
CVE：%s
披露时间：%s
所属标签/受影响组件：%s
描述：%s
处置建议：%s
已知 PoC 仓库（若为空表示暂无公开 PoC）：%s

只输出如下 JSON：
{"title_zh":"","description_zh":"","principle":"","attack_scope":"","poc":{"language":"python","code":""}}`

// intelAnalysisOut 是模型返回的分析结果。
type intelAnalysisOut struct {
	TitleZh       string `json:"title_zh"`
	DescriptionZh string `json:"description_zh"`
	Principle     string `json:"principle"`
	AttackScope   string `json:"attack_scope"`
	Poc           *struct {
		Language string `json:"language"`
		Code     string `json:"code"`
	} `json:"poc"`
}

// analyzeItem 对一条情报跑完整分析并落库。失败返回错误由调用方记录(单条
// 失败不阻断批)。
func (m *Manager) analyzeItem(ctx context.Context, v db.EnrichedVulnIntel) error {
	llm := m.llmConfig()
	if llm.Complete == nil {
		return fmt.Errorf("未配置 LLM，无法分析")
	}
	ctx, cancel := context.WithTimeout(ctx, analysisTimeout)
	defer cancel()

	user := fmt.Sprintf(userAnalysis,
		v.Title, v.Source, v.Severity, v.CVE, v.Disclosure,
		joinJSONList(v.Tags, v.Affected), firstNonEmpty(v.Description, "（无）"),
		firstNonEmpty(v.Solutions, "（无）"), pocRepoSummary(v.GithubPoc),
	)
	raw, err := llm.Complete(ctx, sysAnalysis, user, analysisMaxTokens)
	if err != nil {
		return fmt.Errorf("调用模型失败: %w", err)
	}
	var out intelAnalysisOut
	if err := unmarshalLoose(raw, &out); err != nil {
		return fmt.Errorf("解析模型输出失败: %w", err)
	}
	if strings.TrimSpace(out.Principle) == "" && strings.TrimSpace(out.DescriptionZh) == "" {
		return fmt.Errorf("模型未返回有效内容")
	}

	st := db.VulnIntelAnalysisStage{
		VulnIntelID:   v.ID,
		TitleZh:       strings.TrimSpace(out.TitleZh),
		DescriptionZh: strings.TrimSpace(out.DescriptionZh),
		Principle:     strings.TrimSpace(out.Principle),
		AttackScope:   strings.TrimSpace(out.AttackScope),
		Analyzed:      true,
	}
	if llm.Model != nil {
		st.Model = llm.Model()
	}
	// PoC 归属:模型生成 > 上游仓库(只有链接,无代码) > 无。
	switch {
	case out.Poc != nil && strings.TrimSpace(out.Poc.Code) != "":
		st.PocCode = strings.TrimSpace(out.Poc.Code)
		st.PocLang = strings.TrimSpace(out.Poc.Language)
		if st.PocLang == "" {
			st.PocLang = "python"
		}
		st.PocOrigin = pocOriginAI
	case hasUpstreamPoc(v.GithubPoc):
		st.PocOrigin = pocOriginUpstream
	default:
		st.PocOrigin = pocOriginNone
	}
	return m.pg.SaveIntelAnalysisStage(st)
}

// hasUpstreamPoc 判断富化阶段是否已找到公开 PoC 仓库(github_poc 非空数组)。
func hasUpstreamPoc(githubPocJSON string) bool {
	var repos []db.VulnIntelPOC
	if err := json.Unmarshal([]byte(githubPocJSON), &repos); err != nil {
		return false
	}
	return len(repos) > 0
}

// pocRepoSummary 把 PoC 仓库压成一行提示,喂给模型判断「是否已有公开 PoC」。
func pocRepoSummary(githubPocJSON string) string {
	var repos []db.VulnIntelPOC
	if err := json.Unmarshal([]byte(githubPocJSON), &repos); err != nil || len(repos) == 0 {
		return ""
	}
	parts := make([]string, 0, len(repos))
	for i, r := range repos {
		if i >= 3 {
			break
		}
		parts = append(parts, r.FullName)
	}
	return strings.Join(parts, "、")
}

// analyzeOne 是一条情报的完整处理链:分析 → 中文化兜底 → (可选)模板化。
// 各阶段互不阻断:模板化失败不影响已落库的分析产物。
func (m *Manager) analyzeOne(ctx context.Context, v db.EnrichedVulnIntel) error {
	if err := m.analyzeItem(ctx, v); err != nil {
		return err
	}
	// 分析已产出中文标题;若模型没给(例如原文本身是中文),仍走一次轻量中文化兜底。
	if m.autoTranslate() && v.TitleZh == "" {
		if err := m.localizeItem(ctx, v); err != nil {
			log.Printf("[vulnintel] 中文化 %d: %v", v.ID, err)
		}
	}
	if m.autoNuclei() {
		if _, err := m.SaveIntelTemplate(ctx, v); err != nil {
			log.Printf("[vulnintel] 模板生成 %d: %v", v.ID, err)
		}
	}
	return nil
}

func (m *Manager) llmConfig() LLM {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.llm
}

// ---- 文本/JSON 工具 ----

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// joinJSONList 把两段 JSON 数组文本(标签、受影响包)拼成一行标签,去重。
func joinJSONList(lists ...string) string {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range lists {
		var arr []string
		if err := json.Unmarshal([]byte(raw), &arr); err != nil {
			continue
		}
		for _, s := range arr {
			s = strings.TrimSpace(s)
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return strings.Join(out, ", ")
}

// unmarshalLoose 容忍模型把 JSON 裹在 markdown 代码块或前后附言里。
func unmarshalLoose(raw string, out any) error {
	obj := extractJSONObject(raw)
	if obj == "" {
		return fmt.Errorf("响应中未找到 JSON 对象")
	}
	return json.Unmarshal([]byte(obj), out)
}

// extractJSONObject 取第一段花括号平衡的 JSON 对象,正确跳过字符串内的括号与
// 转义(模型常在 JSON 里塞 PoC 代码,里面满是 {} 和引号)。
func extractJSONObject(s string) string {
	s = strings.ReplaceAll(s, "```json", "")
	s = strings.ReplaceAll(s, "```", "")
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return ""
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
			// 字符串内的括号不计入深度
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}
