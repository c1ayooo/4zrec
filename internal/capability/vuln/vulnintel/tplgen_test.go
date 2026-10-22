package vulnintel

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/nuclei"
	"github.com/c1ayooo/4zrec/internal/domain/db"
)

func intelFixture() db.EnrichedVulnIntel {
	return db.EnrichedVulnIntel{
		VulnIntel: db.VulnIntel{
			ID:          42,
			Title:       "Apache Struts2 RCE via OGNL injection (CVE-2024-53677)",
			Description: "A vulnerability in Apache Struts2 allows remote code execution.",
			Severity:    "严重",
			CVE:         "CVE-2024-53677",
			Source:      "阿里云漏洞库",
			SourceURL:   "https://avd.aliyun.com/detail?id=AVD-2024-53677",
			Tags:        `["Struts2","OGNL"]`,
		},
		Affected: `["maven/org.apache.struts:struts2-core"]`,
	}
}

func TestNucleiSeverity(t *testing.T) {
	cases := map[string]string{
		"严重": "critical", "critical": "critical", "CRITICAL": "critical",
		"高危": "high", "high": "high",
		"中危": "medium", "medium": "medium",
		"低危": "low", "low": "low",
		"": "unknown", "未知": "unknown",
	}
	for in, want := range cases {
		if got := nucleiSeverity(in); got != want {
			t.Errorf("nucleiSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeCVE(t *testing.T) {
	if got := normalizeCVE("no cve here", "title CVE-2021-44228 tail"); got != "CVE-2021-44228" {
		t.Fatalf("normalizeCVE = %q", got)
	}
	if got := normalizeCVE("CVE-24-1", "nothing"); got != "" {
		t.Fatalf("非法编号应返回空,得到 %q", got)
	}
}

func TestTemplateIDAndName(t *testing.T) {
	if got := templateID(42, "CVE-2024-53677"); got != "4zrec-cve-2024-53677" {
		t.Fatalf("templateID = %q", got)
	}
	if got := templateID(42, ""); got != "4zrec-intel-42" {
		t.Fatalf("templateID(no cve) = %q", got)
	}
	// 模板 id 必须满足 nuclei 的字符集限制,否则 SaveCustomTemplate 会拒绝。
	if _, err := nuclei.ParseTemplateYAML(nil); err == nil {
		t.Fatal("空模板应报错")
	}
	name := templateName(intelFixture())
	if !strings.HasPrefix(name, "[4zrec] ") {
		t.Fatalf("模板名缺前缀: %q", name)
	}
}

// TestIntelMarkersExcludesCVE 是这次修复的核心断言:CVE 编号绝不能进
// matcher —— 目标响应里不会出现 CVE 编号,拿它当 body word 的模板永远匹配不到。
func TestIntelMarkersExcludesCVE(t *testing.T) {
	words := intelMarkers(intelFixture())
	joined := strings.Join(words, "|")
	for _, want := range []string{"struts2-core", "Struts2", "OGNL"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("匹配词缺少 %q: %v", want, words)
		}
	}
	if strings.Contains(joined, "CVE-2024-53677") {
		t.Fatalf("CVE 编号不应进入匹配词: %v", words)
	}
	// 泛化标签会匹配任意响应,必须排除。
	for _, bad := range []string{"rce", "poc", "cve", "exploit"} {
		for _, w := range words {
			if strings.EqualFold(w, bad) {
				t.Fatalf("泛化标签 %q 不应进入匹配词", bad)
			}
		}
	}
}

func TestIntelMarkersRejectsGenericOnly(t *testing.T) {
	v := db.EnrichedVulnIntel{
		VulnIntel: db.VulnIntel{ID: 7, Title: "某漏洞", Tags: `["rce","poc","xss"]`},
	}
	if got := intelMarkers(v); len(got) != 0 {
		t.Fatalf("只有泛化标签时应无匹配词,得到 %v", got)
	}
}

// TestUsableMatcherWordRejectsCVEFlag 保证 CVE 编号这类"永不可能出现在响应里"
// 的串不会被当成 matcher。
func TestUsableMatcherWordRejectsCVEFlag(t *testing.T) {
	corpus := intelCorpus(intelFixture(), nil)
	if usableMatcherWord(corpus, "CVE-2024-53677") {
		t.Fatal("CVE 编号不应被接受为 matcher")
	}
	if !usableMatcherWord(corpus, "Struts2") {
		t.Fatal("组件名应被接受为 matcher")
	}
	if usableMatcherWord(corpus, "totally-fabricated-marker") {
		t.Fatal("情报里没有出处的特征不应被接受")
	}
}

// TestCheckNucleiTemplateRejectsCVEMatcher 覆盖历史草稿:只拿 CVE 编号当
// matcher 的模板必须在确认入库前被拦下。
func TestCheckNucleiTemplateRejectsCVEMatcher(t *testing.T) {
	bad := `id: 4zrec-cve-2024-53677
info:
    name: '[4zrec] CVE-2024-53677'
    author: 4zrec
    severity: critical
http:
    - method: GET
      path:
        - /
      matchers:
        - type: word
          part: body
          words:
            - CVE-2024-53677
`
	if err := CheckNucleiTemplate(bad); err == nil {
		t.Fatal("只有 CVE 编号的 matcher 应被判定为不可用")
	}
	good := strings.Replace(bad, "- CVE-2024-53677", "- Struts2", 1)
	if err := CheckNucleiTemplate(good); err != nil {
		t.Fatalf("含具体特征的模板应通过: %v", err)
	}
}

func TestGenerateNucleiTemplatePassesParser(t *testing.T) {
	m := &Manager{} // 无 LLM:走确定性骨架,LLM 指标缺失
	id, yamlText, err := m.GenerateNucleiTemplate(context.Background(), intelFixture())
	if err != nil {
		t.Fatalf("GenerateNucleiTemplate: %v", err)
	}
	if id != "4zrec-cve-2024-53677" {
		t.Fatalf("模板 id = %q", id)
	}
	// 关键契约:产物必须能被平台的模板解析器接受(否则无法进模板库)。
	meta, err := nuclei.ParseTemplateYAML([]byte(yamlText))
	if err != nil {
		t.Fatalf("模板未通过平台校验: %v\n%s", err, yamlText)
	}
	if meta.Author != templateAuthor {
		t.Fatalf("info.author = %q, 必须非空(平台强制)", meta.Author)
	}
	if meta.Severity != "critical" {
		t.Fatalf("severity = %q", meta.Severity)
	}
	if len(meta.CVE) != 1 || meta.CVE[0] != "CVE-2024-53677" {
		t.Fatalf("classification.cve-id = %v", meta.CVE)
	}
	if meta.Type != "http" {
		t.Fatalf("协议段 = %q", meta.Type)
	}
	if !strings.Contains(yamlText, "matchers:") || !strings.Contains(yamlText, "words:") {
		t.Fatalf("模板缺 matcher 段:\n%s", yamlText)
	}
}

func TestGenerateNucleiTemplateWithoutMatchableFeatures(t *testing.T) {
	v := db.EnrichedVulnIntel{
		VulnIntel: db.VulnIntel{ID: 8, Title: "某处注入", Tags: `["rce"]`},
	}
	if _, _, err := m0().GenerateNucleiTemplate(context.Background(), v); err == nil {
		t.Fatal("无可匹配特征时应拒绝生成,避免产出匹配任意响应的噪音模板")
	}
}

// fakeCompleter 返回固定 JSON 的假 LLM,用于验证 LLM 指标被吸收进模板。
func TestGenerateNucleiTemplateUsesLLMIndicators(t *testing.T) {
	m := &Manager{}
	m.SetLLM(LLM{Complete: func(_ context.Context, system, user string, maxTokens int) (string, error) {
		if strings.Contains(system, "nuclei 模板工程师") {
			return `{"method":"GET","path":"/upload.action","words":["OGNL"],"regex":[]}`, nil
		}
		return "{}", nil
	}})
	_, yamlText, err := m.GenerateNucleiTemplate(context.Background(), intelFixture())
	if err != nil {
		t.Fatalf("GenerateNucleiTemplate: %v", err)
	}
	if !strings.Contains(yamlText, "/upload.action") {
		t.Fatalf("LLM 建议的路径未被采用:\n%s", yamlText)
	}
	if _, err := nuclei.ParseTemplateYAML([]byte(yamlText)); err != nil {
		t.Fatalf("带 LLM 指标的模板未通过校验: %v\n%s", err, yamlText)
	}
}

// TestGenerateNucleiTemplateIgnoresBadLLMPath 保证模型给出的相对路径/注入
// 不会破坏 YAML 结构 —— 路径不以 / 开头就丢弃,回落到 "/"。
func TestGenerateNucleiTemplateIgnoresBadLLMPath(t *testing.T) {
	m := &Manager{}
	m.SetLLM(LLM{Complete: func(_ context.Context, system, user string, maxTokens int) (string, error) {
		if strings.Contains(system, "nuclei 模板工程师") {
			return `{"method":"GET","path":"not-a-path","words":[],"regex":[]}`, nil
		}
		return "{}", nil
	}})
	_, yamlText, err := m.GenerateNucleiTemplate(context.Background(), intelFixture())
	if err != nil {
		t.Fatalf("GenerateNucleiTemplate: %v", err)
	}
	if !strings.Contains(yamlText, "- /") {
		t.Fatalf("非法路径未回落:\n%s", yamlText)
	}
	if _, err := nuclei.ParseTemplateYAML([]byte(yamlText)); err != nil {
		t.Fatalf("回落路径后模板仍应合法: %v", err)
	}
}

func TestTemplateDescriptionIncludesAnalysis(t *testing.T) {
	a := &db.IntelAnalysis{DescriptionZh: "中文简介", Principle: "原理", AttackScope: "范围"}
	desc := templateDescription(intelFixture(), a)
	for _, want := range []string{"中文简介", "漏洞原理：原理", "攻击范围：范围", "需人工复核"} {
		if !strings.Contains(desc, want) {
			t.Fatalf("描述缺少 %q: %s", want, desc)
		}
	}
}

// m0 是一个干净的 Manager(零 DB/零钩子)。
func m0() *Manager { return &Manager{} }

func TestTemplateTags(t *testing.T) {
	got := fmt.Sprint(templateTags("CVE-2024-53677"))
	if got != "[4zrec auto cve cve2024]" {
		t.Fatalf("templateTags = %s", got)
	}
}
