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
	"unicode"

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
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part,omitempty"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
}

// GenerateNucleiTemplate 生成模板 YAML(不落盘)。返回模板 id 与 YAML 文本。
//
// matcher 必须能在目标的真实响应里出现:模型给的 words/regex 是主来源,情报
// 自带的组件名是兜底。**CVE 编号不能当 matcher** —— 目标页面不会把 CVE 编号
// 打印出来,以它为唯一 matcher 的模板永远匹配不到东西。凑不出可核验特征时
// 直接报错,不产出空转模板。
func (m *Manager) GenerateNucleiTemplate(ctx context.Context, v db.EnrichedVulnIntel) (string, string, error) {
	analysis := v.Analysis
	if analysis == nil && m.pg != nil {
		if a, err := m.pg.GetIntelAnalysis(v.ID); err == nil {
			analysis = a
		}
	}

	cve := normalizeCVE(v.CVE, v.Title, v.Description, v.Tags)

	// LLM 补请求路径与响应特征;失败不影响后续判定,但会成为报错原因的一部分。
	ind, indErr := m.suggestIndicators(ctx, v, analysis)
	method, path := "GET", "/"
	if ind != nil {
		if p := strings.TrimSpace(ind.Path); strings.HasPrefix(p, "/") && len(p) > 1 {
			path = p
		}
		if mm := strings.ToUpper(strings.TrimSpace(ind.Method)); mm == "GET" || mm == "POST" {
			method = mm
		}
	}

	corpus := intelCorpus(v, analysis)
	var words, regexes []string
	if ind != nil {
		for _, w := range ind.Words {
			if usableMatcherWord(corpus, w) {
				words = appendUnique(words, strings.TrimSpace(w))
			}
		}
		for _, p := range ind.Regex {
			if usableMatcherRegex(corpus, p) {
				regexes = appendUnique(regexes, strings.TrimSpace(p))
			}
		}
	}
	// 兜底:情报自带的组件名/受影响包(模型没给或给的都不可用时)。
	for _, w := range intelMarkers(v) {
		if len(words)+len(regexes) >= 4 {
			break
		}
		if usableMatcherWord(corpus, w) {
			words = appendUnique(words, w)
		}
	}
	if len(words) == 0 && len(regexes) == 0 {
		reason := "情报里没有能在目标响应中核验的特征（具体路径/版本号/页面标记）"
		if indErr != nil {
			reason = fmt.Sprintf("模型未给出可核验的响应特征（%v）", indErr)
		}
		return "", "", fmt.Errorf("无法生成可用模板：%s。只有 CVE 编号的 matcher 永远匹配不到目标", reason)
	}
	if len(words) > 6 {
		words = words[:6]
	}

	matchers := []tplMatcher{}
	if len(words) > 0 {
		matchers = append(matchers, tplMatcher{Type: "word", Part: "body", Words: words})
	}
	if len(regexes) > 0 {
		matchers = append(matchers, tplMatcher{Type: "regex", Part: "body", Regex: regexes})
	}

	doc := tplDoc{
		ID: templateID(v.ID, cve),
		Info: tplInfo{
			Name:        templateName(v),
			Author:      templateAuthor,
			Severity:    nucleiSeverity(v.Severity),
			Tags:        templateTags(cve),
			Description: templateDescription(v, analysis),
		},
		HTTP: []tplHTTP{{
			Method:            method,
			Path:              []string{path},
			MatchersCondition: "or",
			Matchers:          matchers,
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
	if err := CheckNucleiTemplate(string(out)); err != nil {
		return "", "", err
	}
	return doc.ID, string(out), nil
}

// CheckNucleiTemplate 判断一份模板是否有「能在响应里出现」的 matcher。历史草稿
// 里有一批只拿 CVE 编号当 body word 的模板(语法合法但永远匹配不到),确认入库
// 前用这个把它们拦下来重新生成。
func CheckNucleiTemplate(yamlText string) error {
	var doc tplDoc
	if err := yaml.Unmarshal([]byte(yamlText), &doc); err != nil {
		return fmt.Errorf("模板解析失败: %w", err)
	}
	for _, req := range doc.HTTP {
		for _, mt := range req.Matchers {
			switch mt.Type {
			case "word":
				for _, w := range mt.Words {
					if usableMatcherWordNoGrounding(w) {
						return nil
					}
				}
			case "regex":
				for _, p := range mt.Regex {
					if usableMatcherRegexNoGrounding(p) {
						return nil
					}
				}
			}
		}
	}
	return fmt.Errorf("模板没有能在目标响应中核验的 matcher（只有 CVE 编号或泛词），请重新生成")
}

// GenerateTemplateDraft 为一条情报生成 nuclei 模板**草稿**并落库,但不写进
// 项目模板库。matcher 由模型补全,是否入库由人决定 —— 自动入库会直接污染
// 扫描结果。返回模板 id 与 YAML 文本。
func (m *Manager) GenerateTemplateDraft(ctx context.Context, v db.EnrichedVulnIntel) (string, string, error) {
	id, yamlText, err := m.GenerateNucleiTemplate(ctx, v)
	if err != nil {
		return "", "", err
	}
	if err := m.pg.SaveIntelAnalysisStage(db.VulnIntelAnalysisStage{
		VulnIntelID: v.ID, NucleiTemplate: yamlText, Templated: true,
	}); err != nil {
		return "", "", err
	}
	return id, yamlText, nil
}

// ConfirmTemplate 把一条情报的模板草稿写入项目模板库(人工确认这一步),
// 并记下模板 id。草稿不存在时先生成一份再入库。
func (m *Manager) ConfirmTemplate(ctx context.Context, v db.EnrichedVulnIntel) (string, error) {
	yamlText, id := "", ""
	if a, err := m.pg.GetIntelAnalysis(v.ID); err == nil && a != nil {
		yamlText = a.NucleiTemplate
	}
	if yamlText != "" {
		// 草稿里的 id 是生成时定下的,解析出来复用,保证入库的 id 与草稿一致。
		if meta, err := nuclei.ParseTemplateYAML([]byte(yamlText)); err == nil {
			id = meta.ID
		}
	}
	if id == "" {
		genID, genYAML, err := m.GenerateNucleiTemplate(ctx, v)
		if err != nil {
			return "", err
		}
		id, yamlText = genID, genYAML
	}

	sink := m.templateSink()
	if sink == nil {
		return "", fmt.Errorf("模板库未就绪，无法保存")
	}
	if err := sink(id, yamlText); err != nil {
		return "", fmt.Errorf("写入模板库失败: %w", err)
	}
	if err := m.pg.SaveIntelAnalysisStage(db.VulnIntelAnalysisStage{
		VulnIntelID: v.ID, NucleiTemplate: yamlText, NucleiTplID: id, Templated: true,
	}); err != nil {
		return "", err
	}
	return id, nil
}

// DiscardTemplate 丢弃一条未入库的模板草稿。已入库的模板不在这里撤销——
// 撤下模板要走模板库的删除接口,否则索引热加载与扫描链路会不同步。
func (m *Manager) DiscardTemplate(id int64) error {
	v, err := m.pg.GetVulnIntel(id)
	if err != nil {
		return err
	}
	if v.NucleiTplID != "" {
		return fmt.Errorf("模板 %s 已入库，请到 nuclei 模板页删除", v.NucleiTplID)
	}
	return m.pg.ClearIntelNucleiDraft(id)
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

// intelMarkers 从情报自带字段里取可用的组件名:受影响包末段与非泛化标签。
// 故意**不包含 CVE 编号** —— 编号不是响应特征,拿它当 matcher 永远命中不了。
func intelMarkers(v db.EnrichedVulnIntel) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || len([]rune(s)) < 3 || seen[strings.ToLower(s)] {
			return
		}
		if genericMatcherWord[strings.ToLower(s)] {
			return // 泛化标签(rce/poc/xss)当 matcher 只会误报
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
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

// genericMatcherWord 是在任何响应里都可能出现的词:泛化漏洞类型、状态词、
// 情报站自己的标记(如「有Poc」)。这些当 matcher 只会制造误报。
var genericMatcherWord = map[string]bool{
	"rce": true, "xss": true, "ssrf": true, "sqli": true, "csrf": true,
	"lfi": true, "rfi": true, "xxe": true, "dos": true, "poc": true,
	"cve": true, "vuln": true, "exploit": true, "unauth": true, "bypass": true,
	"html": true, "error": true, "success": true, "true": true, "false": true,
	"index": true, "admin": true, "login": true, "welcome": true, "ok": true,
	"有poc": true, "有修复方案": true, "修复方案": true, "漏洞": true, "情报": true,
}

var reCVEWord = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// intelCorpus 汇总可用于「接地校验」的情报正文:模型建议的特征必须能在这里
// 找到至少一个词元,才算情报里真实出现过,而不是模型编的。
func intelCorpus(v db.EnrichedVulnIntel, a *db.IntelAnalysis) string {
	parts := []string{v.Title, v.Description, v.Solutions, v.CVE, v.Tags, v.Affected}
	if a != nil {
		parts = append(parts, a.DescriptionZh, a.Principle, a.AttackScope)
	}
	return strings.ToLower(strings.Join(parts, "\n"))
}

// usableMatcherWord 判断一个词能不能当 body matcher:长度够、不是泛词、不是
// CVE 编号、且至少一个词元在情报正文里出现过。
func usableMatcherWord(corpus, s string) bool {
	s = strings.TrimSpace(s)
	if !usableMatcherWordNoGrounding(s) {
		return false
	}
	return grounded(corpus, s)
}

func usableMatcherWordNoGrounding(s string) bool {
	s = strings.TrimSpace(s)
	if len([]rune(s)) < 4 {
		return false
	}
	if reCVEWord.MatchString(s) || genericMatcherWord[strings.ToLower(s)] {
		return false
	}
	if isDigits(s) {
		return false
	}
	return true
}

// usableMatcherRegex 判断正则能不能当 matcher:能编译、不匹配空串(太宽)、
// 且含有一段在情报正文里出现过的字面量。
func usableMatcherRegex(corpus, p string) bool {
	p = strings.TrimSpace(p)
	if !usableMatcherRegexNoGrounding(p) {
		return false
	}
	return patternGrounded(corpus, p)
}

func usableMatcherRegexNoGrounding(p string) bool {
	p = strings.TrimSpace(p)
	if len(p) < 6 {
		return false
	}
	re, err := regexp.Compile("(?i)" + p)
	if err != nil || re.MatchString("") {
		return false
	}
	return true
}

// grounded 判断 s 中至少一个 ≥3 字符的词元出现在 corpus 里。
func grounded(corpus, s string) bool {
	for _, tok := range textTokens(s) {
		if strings.Contains(corpus, tok) {
			return true
		}
	}
	return false
}

// patternGrounded 对正则做同样的接地校验:取正则里的字面量片段(≥4 字符的
// 字母数字串),至少一个要出现在情报正文里。
func patternGrounded(corpus, pattern string) bool {
	var cur []rune
	flush := func() bool {
		if len(cur) < 4 {
			cur = cur[:0]
			return false
		}
		tok := strings.ToLower(string(cur))
		cur = cur[:0]
		return strings.Contains(corpus, tok)
	}
	for _, r := range pattern {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur = append(cur, r)
			continue
		}
		if flush() {
			return true
		}
	}
	return flush()
}

// textTokens 按非字母数字切分,返回小写词元。
func textTokens(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) >= 3 {
			out = append(out, strings.ToLower(string(cur)))
		}
		cur = cur[:0]
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur = append(cur, r)
			continue
		}
		flush()
	}
	flush()
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func appendUnique(list []string, s string) []string {
	s = strings.TrimSpace(s)
	for _, e := range list {
		if strings.EqualFold(e, s) {
			return list
		}
	}
	return append(list, s)
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
