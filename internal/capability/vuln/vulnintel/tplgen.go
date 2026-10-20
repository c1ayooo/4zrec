// 情报 → nuclei v3 模板(tplgen):把一条已分析的漏洞情报转成可被平台的
// nuclei 扫描链路直接使用的检测模板,落到 data/nuclei/custom-templates/。
// 对齐 ai_bobao 的 nuclei_tpl 分支,但复用 4zrec 已有的模板索引/热加载/校验,
// 不复刻它的目录约定。
//
// 设计取向是「确定性优先」:模板骨架由代码生成,LLM 只提供请求路径与匹配词这
// 类指标,先生成后校验(nuclei.ParseTemplateYAML),校验不过就回落。情报缺少
// 可用于匹配的特征时**直接报错**——宁可不出模板,也不生成匹配任意响应的噪音
// 模板去污染扫描结果。
package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/nuclei"
	"github.com/c1ayooo/4zrec/internal/domain/db"
	"gopkg.in/yaml.v3"
)

// TemplateSink 由宿主注入:把生成的模板落盘到项目自定义模板库。返回错误表示
// 未落盘(此时不记录模板 id)。能力包不直接持有 nuclei 管理器。
type TemplateSink func(id, yamlText string) error

// templateAuthor 是自动生成模板的统一作者标记(平台要求 info.author 非空)。
const templateAuthor = "4zrec"

const (
	tplMaxTokens = 800
	tplTimeout   = 60 * time.Second
)

var reCVE = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// tplDoc / 下列类型是 nuclei v3 模板的确定性骨架。字段顺序即 YAML 输出顺序。
type tplDoc struct {
	ID   string    `yaml:"id"`
	Info tplInfo   `yaml:"info"`
	HTTP []tplHTTP `yaml:"http"`
}

type tplInfo struct {
	Name           string    `yaml:"name"`
	Author         string    `yaml:"author"`
	Severity       string    `yaml:"severity"`
	Description    string    `yaml:"description,omitempty"`
	Tags           []string  `yaml:"tags,omitempty"`
	Classification *tplClass `yaml:"classification,omitempty"`
}

type tplClass struct {
	CVEID string `yaml:"cve-id,omitempty"`
}

type tplHTTP struct {
	Method            string       `yaml:"method"`
	Path              []string     `yaml:"path"`
	MatchersCondition string       `yaml:"matchers-condition,omitempty"`
	Matchers          []tplMatcher `yaml:"matchers"`
}

type tplMatcher struct {
	Type    string   `yaml:"type"`
	Part    string   `yaml:"part,omitempty"`
	Words   []string `yaml:"words,omitempty"`
	Regex   []string `yaml:"regex,omitempty"`
	Status  []int    `yaml:"status,omitempty"`
	Condition string `yaml:"condition,omitempty"`
}

// GenerateNucleiTemplate 生成模板 YAML(不落盘)。返回模板 id 与 YAML 文本。
func (m *Manager) GenerateNucleiTemplate(ctx context.Context, v db.EnrichedVulnIntel) (string, string, error) {
	analysis := v.Analysis
	if analysis == nil {
		if a, err := m.pg.GetIntelAnalysis(v.ID); err == nil {
			analysis = a
		}
	}

	cve := normalizeCVE(v.CVE, v.Title, v.Description, v.Tags)
	words := matchWords(v, cve)
	if len(words) == 0 {
		return "", "", fmt.Errorf("情报缺少可用于匹配的特征（CVE / 组件名 / 路径），无法生成可靠模板")
	}

	// LLM 只补充「请求路径」这类代码推断不出的指标;失败不影响确定性骨架。
	method, path := "GET", "/"
	if ind, err := m.suggestIndicators(ctx, v, analysis); err == nil && ind != nil {
		if p := strings.TrimSpace(ind.Path); strings.HasPrefix(p, "/") {
			path = p
		}
		if mm := strings.ToUpper(strings.TrimSpace(ind.Method)); mm == "GET" || mm == "POST" {
			method = mm
		}
	}

	doc := tplDoc{
		ID: templateID(v.ID, cve),
		Info: tplInfo{
			Name:     templateName(v),
			Author:   templateAuthor,
			Severity: nucleiSeverity(v.Severity),
			Tags:     templateTags(cve),
			Description: templateDescription(v, analysis),
		},
		HTTP: []tplHTTP{{
			Method:            method,
			Path:              []string{path},
			MatchersCondition: "or",
			Matchers: []tplMatcher{{
				Type:  "word",
				Part:  "body",
				Words: words,
			}},
		}},
	}
	if cve != "" {
		doc.Info.Classification = &tplClass{CVEID: cve}
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", "", fmt.Errorf("序列化模板失败: %w", err)
	}
	// 用平台的解析器做契约校验:生成的东西必须能被模板索引接受。
	if _, err := nuclei.ParseTemplateYAML(out); err != nil {
		return "", "", fmt.Errorf("生成的模板未通过校验: %w", err)
	}
	return doc.ID, string(out), nil
}

// SaveIntelTemplate 生成并落盘一条情报的模板(手动触发路径)。落盘成功才记录
// 模板 id;落盘失败时仍保留 YAML 产物,便于人工排查。
func (m *Manager) SaveIntelTemplate(ctx context.Context, v db.EnrichedVulnIntel) (string, error) {
	id, yamlText, err := m.GenerateNucleiTemplate(ctx, v)
	if err != nil {
		return "", err
	}
	sink := m.templateSink()
	if sink == nil {
		return "", fmt.Errorf("模板库未就绪，无法保存")
	}
	if err := sink(id, yamlText); err != nil {
		return "", fmt.Errorf("写入模板库失败: %w", err)
	}
	if err := m.pg.SaveIntelAnalysisStage(db.VulnIntelAnalysisStage{
		VulnIntelID: v.ID, NucleiTemplate: yamlText, Templated: true,
	}); err != nil {
		return "", err
	}
	return id, nil
}

// suggestIndicators 让模型给出最小可用的 http 探测指标。返回 nil 表示无建议。
func (m *Manager) suggestIndicators(ctx context.Context, v db.EnrichedVulnIntel, a *db.IntelAnalysis) (*tplIndicators, error) {
	llm := m.llmConfig()
	if llm.Complete == nil {
		return nil, fmt.Errorf("未配置 LLM")
	}
	ctx, cancel := context.WithTimeout(ctx, tplTimeout)
	defer cancel()

	principle := ""
	if a != nil {
		principle = a.Principle
	}
	raw, err := llm.Complete(ctx, sysTemplate,
		fmt.Sprintf(userTemplate, v.Title, v.CVE, joinJSONList(v.Tags, v.Affected),
			firstNonEmpty(principle, v.Description, "（无）")), tplMaxTokens)
	if err != nil {
		return nil, err
	}
	var ind tplIndicators
	if err := unmarshalLoose(raw, &ind); err != nil {
		return nil, err
	}
	return &ind, nil
}

type tplIndicators struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Words  []string `json:"words"`
	Regex  []string `json:"regex"`
}

const sysTemplate = `你是 nuclei 模板工程师。根据漏洞情报给出「判断目标是否存在该漏洞」所需的最小 HTTP 探测指标，严格只输出 JSON，不要 markdown 代码块。

铁律：
- path 是该漏洞的典型入口路径（以 / 开头）；无法确定时给 "/"。
- words 是响应中能佐证命中该漏洞的特征字符串，必须具体（版本号、特征文件名、报错关键字等），**不要**用 "error"、"success"、"true" 这类在任何响应里都会出现的泛词。
- 只做无害的探测，不要给出破坏性请求。
- 输出字段：method(GET 或 POST)、path、words(字符串数组)、regex(字符串数组，可为空)。`

const userTemplate = `漏洞标题：%s
CVE：%s
组件/标签：%s
漏洞原理：%s

只输出 JSON：{"method":"GET","path":"/","words":[],"regex":[]}`

// ---- 确定性骨架的构件 ----

// templateID 生成合法模板 id(仅 [a-zA-Z0-9._-])。带 CVE 时用 CVE 编号,否则
// 用情报主键,保证可读且唯一。
func templateID(intelID int64, cve string) string {
	if cve != "" {
		return "4zrec-" + strings.ToLower(cve)
	}
	return fmt.Sprintf("4zrec-intel-%d", intelID)
}

func templateName(v db.EnrichedVulnIntel) string {
	title := firstNonEmpty(v.TitleZh, v.Title)
	title = strings.TrimSpace(title)
	if title == "" {
		title = v.CVE
	}
	if len([]rune(title)) > 90 {
		title = string([]rune(title)[:90]) + "…"
	}
	return "[4zrec] " + title
}

// templateDescription 把分析产物归拢成模板描述,并明确标注「自动生成、需复核」。
func templateDescription(v db.EnrichedVulnIntel, a *db.IntelAnalysis) string {
	var b strings.Builder
	writeBlock := func(label, s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(label)
		b.WriteString(s)
	}
	if a != nil {
		writeBlock("", a.DescriptionZh)
		writeBlock("漏洞原理：", a.Principle)
		writeBlock("攻击范围：", a.AttackScope)
	} else {
		writeBlock("", v.Description)
	}
	if s := strings.TrimSpace(v.Solutions); s != "" {
		writeBlock("处置建议：", s)
	}
	if b.Len() > 0 {
		b.WriteString("\n\n")
	}
	b.WriteString("由 4zrec 情报流水线自动生成，matcher 需人工复核后再用于正式扫描。")
	return b.String()
}

// matchWords 汇总可用于 body 匹配的具体特征:CVE 编号、受影响包名、非通用的
// 标签。泛化标签(rce/xss/ssrf 等)会匹配到无关响应,直接排除。
func matchWords(v db.EnrichedVulnIntel, cve string) []string {
	generic := map[string]bool{
		"rce": true, "xss": true, "ssrf": true, "sqli": true, "csrf": true,
		"lfi": true, "rfi": true, "xxe": true, "dos": true, "poc": true,
		"cve": true, "vuln": true, "exploit": true, "unauth": true, "bypass": true,
	}
	seen := map[string]bool{}
	out := []string{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || len([]rune(s)) < 3 || seen[strings.ToLower(s)] {
			return
		}
		if generic[strings.ToLower(s)] {
			return
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	if cve != "" {
		add(cve)
	}
	// 受影响包名(GHSA 形如 ecosystem/name)取末段作为组件名。
	for _, pkg := range parseList(v.Affected) {
		parts := strings.Split(pkg, "/")
		add(parts[len(parts)-1])
	}
	for _, tag := range parseList(v.Tags) {
		add(tag)
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

func templateTags(cve string) []string {
	tags := []string{templateAuthor, "auto"}
	if cve != "" {
		tags = append(tags, "cve", "cve"+cve[4:8])
	}
	return tags
}

// nucleiSeverity 把情报等级(中文/英文)映射到 nuclei 的 severity 取值。
func nucleiSeverity(s string) string {
	switch {
	case strings.Contains(s, "严重") || strings.EqualFold(s, "critical"):
		return "critical"
	case strings.Contains(s, "高") || strings.EqualFold(s, "high"):
		return "high"
	case strings.Contains(s, "中") || strings.EqualFold(s, "medium"):
		return "medium"
	case strings.Contains(s, "低") || strings.EqualFold(s, "low"):
		return "low"
	default:
		return "unknown"
	}
}

// normalizeCVE 取情报的 CVE:优先字段,其次从标题/描述/标签里抽标准编号。
func normalizeCVE(fields ...string) string {
	for _, f := range fields {
		if m := reCVE.FindString(f); m != "" {
			return m
		}
	}
	return ""
}

func parseList(raw string) []string {
	var arr []string
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		return nil
	}
	return arr
}

func (m *Manager) templateSink() TemplateSink {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tplSink
}
