package fingerprint

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/c1ayooo/capkit/kits/bindingkit"
)

// QueryMatches reports whether query looks like one of the recognized
// technologies.
//
// This gate decides whether a template may run against a target "because the
// product was fingerprinted", so a false positive here runs the wrong exploit
// against the wrong product. Matching rules, in order:
//
//  1. An explicit binding decides it: both sides resolve to the same canonical
//     product (capkit's binding table, exact → alias → bounded containment).
//     This is how "AJ-Report数据大屏系统" and "AJ-Report" are known to be the
//     same product.
//  2. Otherwise the query must match a recognized technology as a whole token
//     or as a prefix ending on a token boundary — "RuoYi 4.x" against "RuoYi",
//     "e-cology" against "泛微 e-cology".
//
// A bare substring is deliberately not enough. It used to be, which let a
// recognized "OA" approve "通达OA" and a recognized "BlueKing" approve "King":
// the gate silently widened to unrelated products.
func QueryMatches(technologies []string, query string) bool {
	q := normalizeName(cleanName(query))
	if q == "" {
		return false
	}
	queryProduct := CanonicalProduct(query)
	for _, raw := range technologies {
		tech := strings.TrimSpace(raw)
		if tech == "" {
			continue
		}
		if queryProduct != "" && CanonicalProduct(tech) == queryProduct {
			return true
		}
		if technologyMatches(tech, q) {
			return true
		}
	}
	return false
}

// technologyMatches compares one recognized technology against a normalized
// query. Matching is token-wise: a name is accepted when it is the whole other
// name, shares a token prefix ending on a token boundary, or appears as a
// separate word. Bare inner containment is not accepted — see QueryMatches.
func technologyMatches(tech, q string) bool {
	t := normalizeName(cleanName(tech))
	if t == "" {
		return false
	}
	if t == q {
		return true
	}
	// The query carries the technology plus a version or extra words:
	// "ruoyi 4.x" against "ruoyi".
	if strings.HasPrefix(q, t) && boundaryAt(q, len(t)) {
		return true
	}
	// The query names the product and the fingerprint name is more verbose:
	// "用友" against "用友NC".
	if strings.HasPrefix(t, q) && boundaryAt(t, len(q)) {
		return true
	}
	// The query is a separate word inside the technology name: "e-cology"
	// against "泛微 e-cology", "struts2" against "Apache Struts2".
	if strings.Contains(t, " "+q) {
		return true
	}
	return false
}

// CanonicalProduct maps a product name onto the binding table's canonical key,
// or returns "" when the table does not know the name. It is exported because
// the template gate and the fingerprint gate must answer "which product is
// this" the same way — two different answers would let a template through one
// door and not the other.
func CanonicalProduct(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	out := bindingkit.Resolve([]string{name}, bindingkit.DefaultBindings)
	if len(out) == 0 {
		return ""
	}
	return out[0].Product
}

// cleanName drops a parenthetical tail so the comparison is about the product,
// not the release: "Apache Shiro (1.2)" → "Apache Shiro".
func cleanName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "(（"); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// normalizeName folds case and collapses whitespace for comparison.
func normalizeName(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}

// boundaryAt reports whether position i starts a new token: end of string, or
// the next rune is a separator. The rune is decoded rather than read as a
// byte, so multi-byte names ("泛微 OA") are handled.
func boundaryAt(s string, i int) bool {
	if i < 0 {
		return false
	}
	if i == 0 || i >= len(s) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return unicode.IsSpace(r) || unicode.IsPunct(r) || unicode.IsSymbol(r)
}

// UniqueTechnologies returns a sorted, de-duplicated copy.
func UniqueTechnologies(technologies []string) []string {
	seen := make(map[string]bool, len(technologies))
	out := make([]string, 0, len(technologies))
	for _, raw := range technologies {
		tech := strings.TrimSpace(raw)
		if tech == "" || seen[tech] {
			continue
		}
		seen[tech] = true
		out = append(out, tech)
	}
	sort.Strings(out)
	return out
}
