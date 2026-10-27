package binding

import (
	"fmt"
	"strings"
	"unicode"
)

// Binding maps the product name a fingerprint engine reports onto the
// canonical product key a template library is organized by.
//
// The problem it solves is concrete: a fingerprint rule reports "AJ-Report数据大屏系统"
// while the template library files the same product under "AJ-Report". A
// substring gate happens to accept that pair and rejects the next one, so
// whether a template is reachable depends on how verbose each side's naming
// day was. A binding table makes the mapping explicit and reviewable.
type Binding struct {
	// Product is the canonical key. Everything else normalizes onto it.
	Product string `json:"product" yaml:"product"`
	// Aliases are the spellings seen in the wild (fingerprint names, vendor
	// names, English/CJK variants, abbreviations).
	Aliases []string `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	// Query terms are what to search the template catalog with. Defaults to
	// Product when empty.
	Query []string `json:"query,omitempty" yaml:"query,omitempty"`
	// CVEs are advisories already bound to this product, so a CVE-only lookup
	// can still be resolved without a fingerprint match.
	CVEs []string `json:"cves,omitempty" yaml:"cves,omitempty"`
	// Templates are template ids known to belong to this product.
	Templates []string `json:"templates,omitempty" yaml:"templates,omitempty"`
}

// Resolution is one recognized product mapped onto a binding.
type Resolution struct {
	// Detected is the raw name the fingerprint engine reported.
	Detected string `json:"detected"`
	// Product is the canonical key. Empty when nothing matched.
	Product string `json:"product,omitempty"`
	// MatchedVia records how it matched: exact | alias | contains | none.
	MatchedVia string `json:"matched_via"`
	// Confidence is 1.0 for an exact canonical hit, 0.9 for an alias and 0.6
	// for a containment fallback.
	Confidence float64 `json:"confidence"`
	// Query is the effective template search term for this product.
	Query []string `json:"query,omitempty"`
	// Templates are the template ids bound to this product.
	Templates []string `json:"templates,omitempty"`
}

// Normalize folds a product name to a comparison key: lowercase, drop spaces
// and punctuation, and drop the trailing "系统/平台/软件/漏洞" noise that
// vendors append inconsistently. It is deliberately conservative — over-
// folding ("OA" out of "泛微OA") would merge unrelated products.
func Normalize(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case unicode.IsSpace(r):
			continue
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			continue
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	for _, suffix := range []string{"漏洞", "管理系统", "管理平台", "系统", "平台"} {
		if len(out) > len(suffix) && strings.HasSuffix(out, suffix) {
			out = strings.TrimSuffix(out, suffix)
			break
		}
	}
	return out
}

// minContainsRunes bounds the containment fallback. Shorter values match too
// much: "OA" appears in dozens of unrelated product names.
const minContainsRunes = 4

// Resolve maps every detected product name onto a binding.
//
// It never guesses across products: an unmatched name stays unmatched, and
// the caller decides whether that is a denial or a gap in the table. Silently
// widening the match is how a scan ends up running templates against the
// wrong product.
func Resolve(detected []string, bindings []Binding) []Resolution {
	out := make([]Resolution, 0, len(detected))
	for _, raw := range detected {
		out = append(out, resolveOne(raw, bindings))
	}
	return out
}

func resolveOne(detected string, bindings []Binding) Resolution {
	res := Resolution{Detected: detected, MatchedVia: "none"}
	key := Normalize(detected)
	if key == "" {
		return res
	}
	// Pass 1: canonical name or declared alias, exactly.
	for _, b := range bindings {
		if Normalize(b.Product) == key {
			return fill(res, b, "exact", 1.0)
		}
		for _, alias := range b.Aliases {
			if Normalize(alias) == key {
				return fill(res, b, "alias", 0.9)
			}
		}
	}
	// Pass 2: containment, longest match wins so "AJ-Report数据大屏" prefers
	// the AJ-Report binding over any short accidental prefix. Both sides must
	// clear the minimum length: a two-character detection like "OA" would
	// otherwise match every product whose name ends in OA.
	if len([]rune(key)) < minContainsRunes {
		return res
	}
	best := -1
	bestLen := 0
	bestVia := ""
	for i, b := range bindings {
		candidates := append([]string{b.Product}, b.Aliases...)
		for _, cand := range candidates {
			ck := Normalize(cand)
			if len([]rune(ck)) < minContainsRunes {
				continue
			}
			if strings.Contains(key, ck) || strings.Contains(ck, key) {
				if len([]rune(ck)) > bestLen {
					best, bestLen, bestVia = i, len([]rune(ck)), "contains"
				}
			}
		}
	}
	if best >= 0 {
		return fill(res, bindings[best], bestVia, 0.6)
	}
	return res
}

func fill(res Resolution, b Binding, via string, confidence float64) Resolution {
	res.Product = b.Product
	res.MatchedVia = via
	res.Confidence = confidence
	res.Query = b.Query
	if len(res.Query) == 0 {
		res.Query = []string{b.Product}
	}
	res.Templates = b.Templates
	return res
}

// QueryTerms flattens the effective search terms of a resolution set, deduped
// and order-stable.
func QueryTerms(resolutions []Resolution) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range resolutions {
		for _, q := range r.Query {
			if q = strings.TrimSpace(q); q == "" || seen[strings.ToLower(q)] {
				continue
			}
			seen[strings.ToLower(q)] = true
			out = append(out, q)
		}
	}
	return out
}

// ProductForCVE resolves a CVE to its canonical product through the binding
// table. It returns ok=false when no binding claims the advisory.
func ProductForCVE(cve string, bindings []Binding) (string, [][]string, bool) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	if cve == "" {
		return "", nil, false
	}
	for _, b := range bindings {
		for _, known := range b.CVEs {
			if strings.EqualFold(strings.TrimSpace(known), cve) {
				query := b.Query
				if len(query) == 0 {
					query = []string{b.Product}
				}
				return b.Product, [][]string{query}, true
			}
		}
	}
	return "", nil, false
}

// Validate checks one binding for the mistakes that make a table useless:
// no canonical name, or an alias that collides with another binding's
// canonical name (which would make resolution order-dependent).
func Validate(bindings []Binding) error {
	owner := map[string]string{}
	for _, b := range bindings {
		name := strings.TrimSpace(b.Product)
		if name == "" {
			return fmt.Errorf("绑定记录缺少 product")
		}
		key := Normalize(name)
		if prev, ok := owner[key]; ok && prev != name {
			return fmt.Errorf("product %q 与 %q 归一化后同名", name, prev)
		}
		owner[key] = name
	}
	for _, b := range bindings {
		for _, alias := range b.Aliases {
			ak := Normalize(alias)
			if ak == "" {
				return fmt.Errorf("%s: 别名归一化后为空", b.Product)
			}
			if prev, ok := owner[ak]; ok && prev != b.Product {
				return fmt.Errorf("%s 的别名 %q 与 product %q 冲突", b.Product, alias, prev)
			}
		}
	}
	return nil
}
