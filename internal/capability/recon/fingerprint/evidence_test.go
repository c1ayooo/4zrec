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

func TestUniqueTechnologies(t *testing.T) {
	got := UniqueTechnologies([]string{"B", " A ", "B", "", "A", "C"})
	want := []string{"A", "B", "C"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
