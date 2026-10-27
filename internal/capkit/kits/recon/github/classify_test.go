package github

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		fragment string
		want     string
	}{
		{"AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP", "aws_access_key"},
		{"-----BEGIN RSA PRIVATE KEY-----", "private_key"},
		{"token = ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github_token"},
		{"password = hunter2", "generic_secret"},
		{"hello world", "unknown"},
	}
	for _, c := range cases {
		if got := Classify([]string{c.fragment}); got != c.want {
			t.Errorf("Classify(%q) = %q want %q", c.fragment, got, c.want)
		}
	}
}

func TestScoreCredibility(t *testing.T) {
	high := ScoreCredibility("acme/app", 5, false, ".env")
	if high.Level != "high" {
		t.Fatalf("high = %+v", high)
	}
	low := ScoreCredibility("awesome-secrets-collection", 0, true, "README.md")
	if low.Level != "low" {
		t.Fatalf("low = %+v", low)
	}
}

func TestTemplatesAndBuildQuery(t *testing.T) {
	if len(Templates()) == 0 {
		t.Fatal("no dork templates")
	}
	tpl, ok := TemplateByID("org-aws")
	if !ok {
		t.Fatal("org-aws missing")
	}
	if q := BuildQuery(tpl, "acme", ""); !strings.Contains(q, "org:acme") {
		t.Fatalf("query = %q", q)
	}
}
