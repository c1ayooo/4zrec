package github

import (
	"context"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type fakeSettings struct{ m map[string]string }

func (f fakeSettings) GetString(_ context.Context, key string) (string, bool) {
	v, ok := f.m[key]
	return v, ok
}
func (f fakeSettings) GetBool(context.Context, string) (bool, bool) { return false, false }
func (f fakeSettings) GetInt(context.Context, string) (int64, bool) { return 0, false }

type fakeLimiter struct{ n int }

func (f *fakeLimiter) Acquire(context.Context, string, core.RateLimitSpec) (func(), error) {
	f.n++
	return func() {}, nil
}

type fakeFetcher struct {
	resp *core.Response
	last core.Request
}

func (f *fakeFetcher) Fetch(_ context.Context, req core.Request) (*core.Response, error) {
	f.last = req
	return f.resp, nil
}

const sampleJSON = `{
  "total_count": 1,
  "incomplete_results": false,
  "items": [{
    "path": ".env",
    "html_url": "https://github.com/acme/app/blob/main/.env",
    "repository": {
      "full_name": "acme/app",
      "html_url": "https://github.com/acme/app",
      "stargazers_count": 5,
      "pushed_at": "2026-10-01T00:00:00Z",
      "fork": false,
      "owner": {"login": "acme"}
    },
    "text_matches": [{"fragment": "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"}]
  }]
}`

func TestClientSearch(t *testing.T) {
	fetcher := &fakeFetcher{resp: &core.Response{Status: 200, Body: []byte(sampleJSON)}}
	lim := &fakeLimiter{}
	c := &Client{
		Fetcher: fetcher, Limiter: lim,
		Settings: fakeSettings{m: map[string]string{"github.token": "ghp_test"}},
	}
	res, err := c.Search(context.Background(), `org:acme AKIA`, 1, 30)
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalCount != 1 || len(res.Items) != 1 {
		t.Fatalf("result = %+v", res)
	}
	item := res.Items[0]
	if item.Repo != "acme/app" || item.Path != ".env" || item.SecretType != "aws_access_key" {
		t.Fatalf("item = %+v", item)
	}
	if item.Credibility.Level != "high" {
		t.Fatalf("credibility = %+v", item.Credibility)
	}
	if !strings.Contains(fetcher.last.URL, "search/code") || !strings.Contains(fetcher.last.URL, "org%3Aacme+AKIA") {
		t.Fatalf("url = %q", fetcher.last.URL)
	}
	if fetcher.last.Headers["Authorization"] != "Bearer ghp_test" {
		t.Fatalf("headers = %+v", fetcher.last.Headers)
	}
	if lim.n != 1 {
		t.Fatalf("limiter = %d", lim.n)
	}
}

func TestClientMissingToken(t *testing.T) {
	c := &Client{Fetcher: &fakeFetcher{resp: &core.Response{Status: 200}}, Settings: fakeSettings{}}
	_, err := c.Search(context.Background(), "AKIA", 1, 10)
	if err == nil || !strings.Contains(err.Error(), core.CodeUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRejected(t *testing.T) {
	c := &Client{
		Fetcher:  &fakeFetcher{resp: &core.Response{Status: 403, Body: []byte(`{"message":"rate limited"}`)}},
		Settings: fakeSettings{m: map[string]string{"github.token": "t"}},
	}
	_, err := c.Search(context.Background(), "AKIA", 1, 10)
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("err = %v", err)
	}
}
