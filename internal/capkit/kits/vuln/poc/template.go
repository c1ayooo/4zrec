package poc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---- nuclei template draft ----

// templateAuthor marks every generated template. The host's catalog policy
// uses it to tell generated templates from curated ones.
const templateAuthor = "capkit"

// TemplateDraft is a nuclei template that has NOT been published yet. The
// caller (or a human) reviews MatcherSummary before confirming it.
type TemplateDraft struct {
	ID             string   `json:"template_id"`
	YAML           string   `json:"yaml"`
	MatcherSummary string   `json:"matcher_summary"`
	Notes          []string `json:"notes,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

type templateDoc struct {
	ID   string      `yaml:"id"`
	Info templateM   `yaml:"info"`
	HTTP []templateH `yaml:"http"`
}

type templateM struct {
	Name           string        `yaml:"name"`
	Author         string        `yaml:"author"`
	Severity       string        `yaml:"severity"`
	Description    string        `yaml:"description,omitempty"`
	Tags           []string      `yaml:"tags,omitempty"`
	Classification *templateMeta `yaml:"classification,omitempty"`
}

type templateMeta struct {
	CVEID string `yaml:"cve-id,omitempty"`
}

type templateH struct {
	Method            string      `yaml:"method"`
	Path              []string    `yaml:"path"`
	MatchersCondition string      `yaml:"matchers-condition,omitempty"`
	Matchers          []templateX `yaml:"matchers"`
}

type templateX struct {
	Type   string   `yaml:"type"`
	Part   string   `yaml:"part,omitempty"`
	Words  []string `yaml:"words,omitempty"`
	Regex  []string `yaml:"regex,omitempty"`
	Status []int    `yaml:"status,omitempty"`
}

var (
	reTemplateID = regexp.MustCompile(`^[a-z0-9._-]+$`)
	reCVE        = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	reNonIDChar  = regexp.MustCompile(`[^a-z0-9._-]+`)
)

// matcherWords collects the concrete strings a matcher may key on: the CVE,
// the affected package names and the non-generic tags.
//
// A matcher built from generic words ("rce", "error", "success") matches
// unrelated responses, so those are dropped. If nothing specific survives, the
// caller must not emit a template at all: an always-matching template is worse
// than no template, because it poisons every scan that adds it.
func matcherWords(item IntelInput, cve string) []string {
	generic := map[string]bool{
		"rce": true, "xss": true, "ssrf": true, "sqli": true, "csrf": true,
		"lfi": true, "rfi": true, "xxe": true, "dos": true, "poc": true,
		"cve": true, "vuln": true, "vulnerability": true, "exploit": true,
		"bypass": true, "unauth": true, "login": true, "admin": true,
	}
	seen := map[string]bool{}
	out := []string{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len([]rune(s)) < 3 || seen[strings.ToLower(s)] || generic[strings.ToLower(s)] {
			return
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	if cve != "" {
		add(cve)
	}
	for _, pkg := range item.Affected {
		parts := strings.Split(strings.TrimSpace(pkg), "/")
		add(parts[len(parts)-1])
	}
	for _, tag := range item.Tags {
		add(tag)
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

// normalizeCVE prefers the explicit field and falls back to any CVE mentioned
// in the text, so a source that puts the id in the title still gets a proper
// classification block.
func normalizeCVE(fields ...string) string {
	for _, f := range fields {
		if m := reCVE.FindString(f); m != "" {
			return m
		}
	}
	return ""
}

// nucleiSeverity maps a severity label onto nuclei's severity vocabulary.
func nucleiSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "严重", "极危":
		return "critical"
	case "high", "高危":
		return "high"
	case "medium", "中危":
		return "medium"
	case "low", "低危":
		return "low"
	default:
		return "unknown"
	}
}

// templateID builds a catalog-safe id. With a CVE it is stable across runs;
// without one it falls back to the title, so re-generating the same advisory
// overwrites rather than accumulating duplicates.
func templateID(cve, title string) string {
	if cve != "" {
		return "capkit-" + strings.ToLower(cve)
	}
	slug := reNonIDChar.ReplaceAllString(strings.ToLower(strings.TrimSpace(title)), "-")
	slug = strings.Trim(slug, "-")
	if len(slug) > 60 {
		slug = slug[:60]
	}
	if slug == "" {
		return "capkit-generated"
	}
	return "capkit-" + slug
}

// buildTemplate renders the deterministic template skeleton. Only method and
// path come from the model; the structure, id, severity mapping and matcher
// shape are code-owned so a hallucinating model cannot produce a malformed
// or over-broad template.
func buildTemplate(item IntelInput, cve, method, path string, words []string, description string) (TemplateDraft, error) {
	id := templateID(cve, item.Title)
	if !reTemplateID.MatchString(id) {
		return TemplateDraft{}, fmt.Errorf("生成的模板 id 非法: %s", id)
	}
	doc := templateDoc{
		ID: id,
		Info: templateM{
			Name:        templateName(item, cve),
			Author:      templateAuthor,
			Severity:    nucleiSeverity(item.Severity),
			Tags:        templateTags(cve),
			Description: description,
		},
		HTTP: []templateH{{
			Method:            method,
			Path:              []string{path},
			MatchersCondition: "or",
			Matchers: []templateX{{
				Type:  "word",
				Part:  "body",
				Words: words,
			}},
		}},
	}
	if cve != "" {
		doc.Info.Classification = &templateMeta{CVEID: cve}
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return TemplateDraft{}, fmt.Errorf("序列化模板失败: %w", err)
	}
	draft := TemplateDraft{
		ID:             id,
		YAML:           string(out),
		MatcherSummary: fmt.Sprintf("%s %s，body 命中任一关键词即判定", method, path),
		Warnings: []string{
			"matcher 由关键词拼接，只做无损探测；用于正式扫描前请人工复核关键词的区分度",
			"模板不会自动入库：确认后再由调用方写入模板库",
		},
	}
	if err := ValidateTemplateYAML(draft.YAML); err != nil {
		return TemplateDraft{}, err
	}
	return draft, nil
}

func templateName(item IntelInput, cve string) string {
	title := strings.TrimSpace(item.Title)
	if title == "" {
		title = cve
	}
	if len([]rune(title)) > 90 {
		title = string([]rune(title)[:90]) + "…"
	}
	return "[capkit] " + title
}

func templateTags(cve string) []string {
	tags := []string{templateAuthor, "auto"}
	if cve != "" {
		tags = append(tags, "cve", "cve"+cve[4:8])
	}
	return tags
}

// ValidateTemplateYAML checks the draft against the contract the catalog and
// the nuclei engine both rely on: a catalog-safe id, a real severity, at
// least one http block with at least one matcher carrying a non-empty word or
// regex list. It is deliberately structural — capkit runs no nuclei parser.
func ValidateTemplateYAML(text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return fmt.Errorf("模板内容为空")
	}
	var doc templateDoc
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return fmt.Errorf("模板不是合法 YAML: %w", err)
	}
	if !reTemplateID.MatchString(doc.ID) {
		return fmt.Errorf("模板 id 非法: %q", doc.ID)
	}
	switch doc.Info.Severity {
	case "critical", "high", "medium", "low", "unknown", "info":
	default:
		return fmt.Errorf("模板 severity 非法: %q", doc.Info.Severity)
	}
	if len(doc.Info.Tags) == 0 && doc.Info.Description == "" {
		return fmt.Errorf("模板缺少 info 描述")
	}
	if len(doc.HTTP) == 0 {
		return fmt.Errorf("模板没有 http 块")
	}
	for _, h := range doc.HTTP {
		if len(h.Path) == 0 {
			return fmt.Errorf("模板 http 块缺少 path")
		}
		if len(h.Matchers) == 0 {
			return fmt.Errorf("模板 http 块缺少 matcher")
		}
		for _, m := range h.Matchers {
			if len(m.Words) == 0 && len(m.Regex) == 0 && len(m.Status) == 0 {
				return fmt.Errorf("模板 matcher 没有可匹配内容")
			}
		}
	}
	return nil
}

// MarshalFingerprint encodes a fingerprint draft the way the host stores it:
// as the JSON form of the fingerprint rule, so the host can hand it to
// fingerprintkit's RuleSet without translation.
func MarshalFingerprint(d FingerprintDraft) ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// yamlUnmarshal decodes YAML. Kept as a tiny wrapper so the template and
// publish paths share one dependency point.
func yamlUnmarshal(data []byte, out any) error {
	return yaml.Unmarshal(data, out)
}
