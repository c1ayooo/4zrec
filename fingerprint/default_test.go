package fingerprint

import (
	"strings"
	"testing"
)

// TestDefaultRulesCompiles 内置快照+种子必须能编译出相当规模的规则集——
// 这是 enrich 指纹链路的可用性底线。
func TestDefaultRulesCompiles(t *testing.T) {
	rules := DefaultRules()
	if len(rules) < 5000 {
		t.Fatalf("compiled rules = %d, want >= 5000 (dddd snapshot ~7.5k)", len(rules))
	}
	info := DefaultRulesInfo()
	if !strings.Contains(info, "编译生效") {
		t.Fatalf("info = %q", info)
	}
	t.Log(info)
}

// TestDefaultRulesMatchesKnownSites 用典型观测抽查规则集真的能命中。
func TestDefaultRulesMatchesKnownSites(t *testing.T) {
	rules := DefaultRules()
	cases := []struct {
		name string
		obs  Observation
	}{
		{"nginx", Observation{Server: "nginx/1.24.0", Status: 200, Headers: map[string]string{"server": "nginx/1.24.0"}}},
		{"apache", Observation{Server: "Apache/2.4.41 (Ubuntu)", Headers: map[string]string{"server": "Apache/2.4.41"}}},
		{"shiro", Observation{Cookie: "rememberMe=deleteMe; JSESSIONID=x", HeaderText: "Set-Cookie: rememberMe=deleteMe; JSESSIONID=x\r\n", Headers: map[string]string{"set-cookie": "rememberMe=deleteMe"}}},
	}
	for _, c := range cases {
		matches := MatchObservation(rules, c.obs)
		found := false
		var names []string
		for _, m := range matches {
			names = append(names, m.Product)
			if strings.EqualFold(m.Product, c.name) || strings.Contains(strings.ToLower(m.Product), strings.ToLower(c.name)) {
				found = true
			}
		}
		if !found {
			t.Errorf("case %s: no matching rule, got %v", c.name, names)
		}
	}
}
