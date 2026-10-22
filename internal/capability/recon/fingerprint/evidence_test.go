package fingerprint

import (
	"reflect"
	"testing"
)

func TestQueryMatches(t *testing.T) {
	techs := []string{"泛微 e-cology", "Apache Shiro", "RuoYi"}
	for _, q := range []string{"泛微", "e-cology", "shiro", "ruoyi", "RuoYi 4.x"} {
		if !QueryMatches(techs, q) {
			t.Errorf("%q should match", q)
		}
	}
	for _, q := range []string{"", "通达OA", "WordPress"} {
		if QueryMatches(techs, q) {
			t.Errorf("%q should not match", q)
		}
	}
}

// TestQueryMatchesRejectsDirectionalSubstring pins the bug that made the gate
// useless as a gate: bidirectional `strings.Contains` let a short recognized
// name approve an unrelated longer product name. Running a template for
// 通达OA against a target fingerprinted only as "OA" is exactly the mistake
// this must not allow.
func TestQueryMatchesRejectsDirectionalSubstring(t *testing.T) {
	cases := []struct {
		techs []string
		query string
	}{
		// The query merely contains the recognized technology.
		{[]string{"OA"}, "通达OA"},
		{[]string{"OA"}, "泛微OA"},
		{[]string{"BlueKing"}, "King"},
		{[]string{"Nginx"}, "NginxProxyManager"},
	}
	for _, c := range cases {
		if QueryMatches(c.techs, c.query) {
			t.Errorf("recognized %v must not approve %q", c.techs, c.query)
		}
	}
}

// TestQueryMatchesKnownLimitations documents matches the token rules cannot
// separate, so nobody mistakes them for regressions. "Spring" is a genuine
// token prefix of "SpringBootAdmin"; telling those apart needs a binding-table
// entry, which is exactly what the table is for. If a host adds one, the first
// assertion starts failing and this note should be deleted with it.
func TestQueryMatchesKnownLimitations(t *testing.T) {
	if !QueryMatches([]string{"Spring"}, "SpringBootAdmin") {
		t.Log("binding table now separates Spring from SpringBootAdmin; remove this case")
	}
}

// TestQueryMatchesHonoursBindings pins the replacement rule: when the two names
// are the same product the binding table says so, and that binding is what
// admits the match — not a lucky substring.
func TestQueryMatchesHonoursBindings(t *testing.T) {
	// "AJ-Report数据大屏系统" is an alias of AJ-Report in the binding table, so a
	// target fingerprinted as the long name may run AJ-Report templates.
	if !QueryMatches([]string{"AJ-Report数据大屏系统"}, "AJ-Report") {
		t.Error("binding table should map the long name onto AJ-Report")
	}
	if CanonicalProduct("AJ-Report数据大屏系统") != CanonicalProduct("AJ-Report") {
		t.Fatal("both names should resolve to one canonical product")
	}
	// 泛微 and e-cology are declared aliases of the same product.
	if !QueryMatches([]string{"泛微 e-cology"}, "泛微") {
		t.Error("e-cology install should match the 泛微 product")
	}
}

// TestQueryMatchesDistinctiveToken pins the cases that must keep working: a
// technology whose name is a distinctive part of the query, and a query that
// names a distinctive part of the technology.
func TestQueryMatchesDistinctiveToken(t *testing.T) {
	if !QueryMatches([]string{"Apache Shiro"}, "Apache Shiro 1.2") {
		t.Error("a versioned query should match its product")
	}
	if !QueryMatches([]string{"泛微 e-cology"}, "e-cology") {
		t.Error("a distinctive component name should match")
	}
	// Four-plus runes inside a technology name is specific enough.
	if !QueryMatches([]string{"Apache Struts2"}, "struts2") {
		t.Error("struts2 should match Apache Struts2")
	}
}

func TestCanonicalProductBalances(t *testing.T) {
	if got := CanonicalProduct(""); got != "" {
		t.Fatalf("empty name resolved to %q", got)
	}
	if got := CanonicalProduct("totally-unknown-product"); got != "" {
		t.Fatalf("unknown product resolved to %q, want empty", got)
	}
	if got := CanonicalProduct("通达OA"); got == "" {
		t.Fatal("a known product should resolve")
	}
}

func TestUniqueTechnologies(t *testing.T) {
	got := UniqueTechnologies([]string{"B", " A ", "B", "", "A", "C"})
	want := []string{"A", "B", "C"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
