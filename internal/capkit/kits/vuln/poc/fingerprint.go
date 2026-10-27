package poc

import (
	"fmt"
	"regexp"
	"strings"
)

// FingerprintPattern mirrors the fingerprint engine's match primitive. It is
// declared here rather than imported so this kit stays independent of
// fingerprintkit (capkit forbids kit-to-kit imports); the JSON shape is the
// contract between them.
type FingerprintPattern struct {
	Type  string `json:"type"`            // body | header | cookie | url | title | script | meta | favicon
	Part  string `json:"part,omitempty"`  // header/cookie/meta key
	Value string `json:"value"`           // literal substring or regex
	Regex bool   `json:"regex,omitempty"` // value is a regular expression
}

// FingerprintDraft is a proposed asset fingerprint, NOT yet published.
type FingerprintDraft struct {
	Name     string               `json:"name"`
	Product  string               `json:"product,omitempty"`
	Category string               `json:"category,omitempty"`
	Patterns []FingerprintPattern `json:"patterns"`
	Reason   string               `json:"reason,omitempty"`
}

var distinctivePatternTypes = map[string]bool{
	"body": true, "title": true, "header": true, "cookie": true, "url": true,
}

var knownPatternTypes = map[string]bool{
	"body": true, "title": true, "header": true, "cookie": true, "url": true,
	"script": true, "meta": true, "favicon": true,
}

// genericFingerprintValues are values that match nearly every site. A rule
// built on one turns every target into a hit, which is worse than no rule.
var genericFingerprintValues = map[string]bool{
	"html": true, "text/html": true, "utf-8": true, "utf8": true,
	"ok": true, "index": true, "admin": true, "login": true, "http": true,
	"https": true, "www": true, "error": true, "welcome": true, "success": true,
	"首页": true, "登录": true, "系统": true,
}

var reFingerprintID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// ValidateFingerprintDraft rejects a draft that would either fail to load or
// match everything.
//
// The rule the whole check turns on: at least one pattern must sit on a
// content/path field (body/title/header/cookie/url) with a value at least
// five characters long that is not a generic word. Status-code and port
// patterns are allowed as supporting evidence but can never be the only
// evidence.
func ValidateFingerprintDraft(d FingerprintDraft) error {
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("指纹规则缺少名称")
	}
	if len(d.Patterns) == 0 {
		return fmt.Errorf("指纹规则没有任何匹配项")
	}
	distinctive := 0
	for i, p := range d.Patterns {
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		if !knownPatternTypes[typ] {
			return fmt.Errorf("第 %d 个匹配项的 type 非法: %q", i+1, p.Type)
		}
		value := strings.TrimSpace(p.Value)
		if value == "" {
			return fmt.Errorf("第 %d 个匹配项(%s)的 value 为空", i+1, typ)
		}
		if p.Regex {
			if _, err := regexp.Compile(value); err != nil {
				return fmt.Errorf("第 %d 个匹配项的正则无效: %w", i+1, err)
			}
		}
		if !distinctivePatternTypes[typ] {
			continue
		}
		if len([]rune(value)) < 5 {
			continue
		}
		if genericFingerprintValues[strings.ToLower(value)] {
			continue
		}
		distinctive++
	}
	if distinctive == 0 {
		return fmt.Errorf("指纹规则缺少有区分度的匹配项（需要至少一个落在 body/title/header/cookie/url 上、值长度 ≥5 的非通用条件）")
	}
	return nil
}

// fingerprintID derives a stable rule id from the rule name so re-generating
// the same product's rule replaces it instead of piling up duplicates.
func fingerprintID(name string) string {
	slug := reNonIDChar.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "generated"
	}
	if len(slug) > 60 {
		slug = slug[:60]
	}
	if !reFingerprintID.MatchString(slug) {
		slug = "generated-" + slug
	}
	return slug
}
