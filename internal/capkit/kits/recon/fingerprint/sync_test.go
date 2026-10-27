package fingerprint

import (
	"context"
	"testing"
)

type fakeFetcher struct{ data []byte }

func (f fakeFetcher) Fetch(context.Context, string) ([]byte, error) { return f.data, nil }

func TestParseWappalyzer(t *testing.T) {
	data := []byte(`{"technologies":{"Nginx":{"cats":[22],"headers":{"Server":"nginx"},"html":["nginx"]},"PHP":{"headers":{"X-Powered-By":"PHP"}}}}`)
	rules, err := parseWappalyzer(data, "wappalyzergo")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %d", len(rules))
	}
	rs, err := NewRuleSet(rules)
	if err != nil {
		t.Fatal(err)
	}
	techs := rs.Match(Response{Headers: map[string][]string{"Server": {"nginx/1.25"}}})
	if len(techs) != 1 || techs[0].Product != "Nginx" {
		t.Fatalf("techs = %+v", techs)
	}
}

func TestParseDDDD(t *testing.T) {
	data := []byte(`
- name: nginx
  product: nginx
  keyword: [nginx]
  headers:
    Server: nginx
  favicon: ["12345"]
- name: empty
`)
	rules, err := parseDDDD(data, "dddd")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d", len(rules))
	}
	if len(rules[0].Patterns) != 3 {
		t.Fatalf("patterns = %+v", rules[0].Patterns)
	}
}

func TestSyncerFetchAll(t *testing.T) {
	s := &Syncer{Fetcher: fakeFetcher{data: []byte(`{"technologies":{"Nginx":{"headers":{"Server":"nginx"}}}}`)}}
	rules, err := s.FetchAll(context.Background(), []Source{
		{Name: "a", URL: "http://example/rules.json", Format: FormatWappalyzer},
		{Name: "b", URL: "http://example/rules2.json", Format: FormatWebanalyze},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Source != "a" || rules[1].Source != "b" {
		t.Fatalf("rules = %+v", rules)
	}
}
