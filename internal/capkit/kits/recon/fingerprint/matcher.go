package fingerprint

import (
	"fmt"
	"regexp"
	"strings"
)

type compiledPattern struct {
	Pattern
	re *regexp.Regexp
}

type compiledRule struct {
	Rule
	patterns []compiledPattern
}

// RuleSet is an immutable, compiled set of fingerprint rules. Match is safe for
// concurrent use.
type RuleSet struct {
	rules []compiledRule
}

func NewRuleSet(rules []Rule) (*RuleSet, error) {
	s := &RuleSet{}
	if err := s.append(rules); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *RuleSet) append(rules []Rule) error {
	for _, r := range rules {
		if strings.TrimSpace(r.Name) == "" && strings.TrimSpace(r.Product) == "" {
			return fmt.Errorf("fingerprint rule has no name/product")
		}
		cr := compiledRule{Rule: r}
		for _, p := range r.Patterns {
			if strings.TrimSpace(p.Type) == "" {
				return fmt.Errorf("%s: pattern type is required", r.Name)
			}
			if strings.TrimSpace(p.Value) == "" && !strings.EqualFold(p.Type, "cookie") {
				return fmt.Errorf("%s: pattern value is required", r.Name)
			}
			cp := compiledPattern{Pattern: p}
			if p.Regex {
				re, err := regexp.Compile(p.Value)
				if err != nil {
					return fmt.Errorf("%s: %w", r.Name, err)
				}
				cp.re = re
			}
			cr.patterns = append(cr.patterns, cp)
		}
		s.rules = append(s.rules, cr)
	}
	return nil
}

// Merge adds more rules after construction.
func (s *RuleSet) Merge(rules []Rule) error { return s.append(rules) }

func (s *RuleSet) Len() int { return len(s.rules) }

// Match returns detected technologies, deduped by product+source.
func (s *RuleSet) Match(resp Response) []Tech {
	if resp.FaviconHash == "" && len(resp.Favicon) > 0 {
		resp.FaviconHash = FaviconHash(resp.Favicon)
	}
	best := map[string]Tech{}
	var order []string
	for _, r := range s.rules {
		matched := 0
		for _, p := range r.patterns {
			if matchPattern(p, resp) {
				matched++
			}
		}
		if matched == 0 {
			continue
		}
		product := r.Product
		if product == "" {
			product = r.Name
		}
		tech := Tech{
			Product: product, Category: r.Category, Source: r.Source,
			Confidence: minInt(100, 50+matched*10),
		}
		key := strings.ToLower(product) + "\x00" + strings.ToLower(r.Source)
		if prev, ok := best[key]; !ok || tech.Confidence > prev.Confidence {
			if !ok {
				order = append(order, key)
			}
			best[key] = tech
		}
	}
	out := make([]Tech, 0, len(order))
	for _, key := range order {
		out = append(out, best[key])
	}
	return out
}

func matchPattern(p compiledPattern, resp Response) bool {
	switch strings.ToLower(p.Type) {
	case "body":
		return matchText(string(resp.Body), p)
	case "title":
		return matchText(extractTitle(resp.Body), p)
	case "script", "meta":
		if p.Part != "" && !strings.Contains(strings.ToLower(string(resp.Body)), strings.ToLower(p.Part)) {
			return false
		}
		return matchText(string(resp.Body), p)
	case "header":
		if p.Part != "" {
			return matchText(strings.Join(headerValues(resp.Headers, p.Part), "\n"), p)
		}
		var all []string
		for _, vs := range resp.Headers {
			all = append(all, vs...)
		}
		return matchText(strings.Join(all, "\n"), p)
	case "cookie":
		if p.Part != "" {
			v := cookieValue(resp, p.Part)
			if p.Value == "" {
				return v != ""
			}
			return matchText(v, p)
		}
		var all []string
		for _, v := range resp.Cookies {
			all = append(all, v)
		}
		for _, v := range headerValues(resp.Headers, "Set-Cookie") {
			all = append(all, v)
		}
		if p.Value == "" {
			return len(all) > 0
		}
		return matchText(strings.Join(all, "\n"), p)
	case "url":
		return matchText(resp.URL, p)
	case "favicon":
		return strings.TrimSpace(resp.FaviconHash) == strings.TrimSpace(p.Value)
	default:
		return false
	}
}

func matchText(text string, p compiledPattern) bool {
	if p.re != nil {
		return p.re.MatchString(text)
	}
	return strings.Contains(strings.ToLower(text), strings.ToLower(p.Value))
}

func headerValues(headers map[string][]string, name string) []string {
	for k, vs := range headers {
		if strings.EqualFold(k, name) {
			return vs
		}
	}
	return nil
}

func cookieValue(resp Response, name string) string {
	if resp.Cookies != nil {
		for k, v := range resp.Cookies {
			if strings.EqualFold(k, name) {
				return v
			}
		}
	}
	for _, raw := range headerValues(resp.Headers, "Set-Cookie") {
		parts := strings.SplitN(raw, ";", 2)
		kv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), name) {
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body []byte) string {
	m := titleRE.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return string(m[1])
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
