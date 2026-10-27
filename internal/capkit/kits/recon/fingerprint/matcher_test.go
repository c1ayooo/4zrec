package fingerprint

import (
	"testing"
)

func TestMatcherBasic(t *testing.T) {
	rs, err := NewRuleSet([]Rule{
		{ID: "nginx", Name: "Nginx", Product: "Nginx", Source: "test", Patterns: []Pattern{
			{Type: "header", Part: "Server", Value: "nginx"},
		}},
		{ID: "wp", Name: "WordPress", Product: "WordPress", Source: "test", Patterns: []Pattern{
			{Type: "body", Value: "wp-content"},
			{Type: "title", Value: "My WP"},
		}},
		{ID: "fav", Name: "FavProduct", Product: "FavProduct", Source: "test", Patterns: []Pattern{
			{Type: "favicon", Value: "12345"},
		}},
		{ID: "cookie", Name: "CookieProduct", Product: "CookieProduct", Source: "test", Patterns: []Pattern{
			{Type: "cookie", Part: "PHPSESSID", Value: ""},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	techs := rs.Match(Response{
		Headers:     map[string][]string{"Server": {"nginx/1.25"}, "Set-Cookie": {"PHPSESSID=abc; Path=/"}},
		Body:        []byte(`<html><title>My WP</title><link href="/wp-content/x.css"></html>`),
		FaviconHash: "12345",
	})
	got := map[string]bool{}
	for _, tech := range techs {
		got[tech.Product] = true
	}
	for _, want := range []string{"Nginx", "WordPress", "FavProduct", "CookieProduct"} {
		if !got[want] {
			t.Errorf("missing %s in %+v", want, techs)
		}
	}
}

func TestMatcherRegexAndDedupe(t *testing.T) {
	rs, err := NewRuleSet([]Rule{
		{ID: "a", Name: "Same", Product: "Same", Source: "s", Patterns: []Pattern{{Type: "body", Value: "foo"}}},
		{ID: "b", Name: "Same2", Product: "Same", Source: "s", Patterns: []Pattern{
			{Type: "body", Value: "foo"}, {Type: "body", Value: "bar"},
		}},
		{ID: "re", Name: "Regex", Product: "Regex", Source: "s", Patterns: []Pattern{
			{Type: "body", Value: `v\d+\.\d+`, Regex: true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	techs := rs.Match(Response{Body: []byte("foo bar version v1.2")})
	count := map[string]int{}
	for _, tech := range techs {
		count[tech.Product]++
	}
	if count["Same"] != 1 {
		t.Fatalf("dedupe failed: %+v", techs)
	}
	if count["Regex"] != 1 {
		t.Fatalf("regex failed: %+v", techs)
	}
	if techs[0].Product == "Same" && techs[0].Confidence < 60 {
		t.Fatalf("confidence = %d", techs[0].Confidence)
	}
}

func TestMatcherInvalidRegex(t *testing.T) {
	if _, err := NewRuleSet([]Rule{{Name: "bad", Patterns: []Pattern{{Type: "body", Value: "(", Regex: true}}}}); err == nil {
		t.Fatal("expected regex error")
	}
}
