package fingerprint

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type fakeHTTP struct {
	resp    *core.Response
	lastURL string
}

func (f *fakeHTTP) Do(_ context.Context, req core.Request) (*core.Response, error) {
	f.lastURL = req.URL
	return f.resp, nil
}

type fakeEvidence struct{ n int }

func (f *fakeEvidence) Record(context.Context, core.Evidence) (string, error) {
	f.n++
	return "ev-1", nil
}

func TestProviderFingerprint(t *testing.T) {
	rs, err := NewRuleSet([]Rule{{
		ID: "nginx", Name: "Nginx", Product: "Nginx", Source: "test",
		Patterns: []Pattern{{Type: "header", Part: "Server", Value: "nginx"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	http := &fakeHTTP{resp: &core.Response{
		Status: 200, Headers: map[string][]string{"Server": {"nginx/1.25"}}, Body: []byte("ok"),
	}}
	ev := &fakeEvidence{}
	p := &Provider{HTTP: http, Rules: rs, Evidence: ev}
	techs, err := p.Fingerprint(context.Background(), core.Target{
		Kind: core.TargetURL, URL: "http://127.0.0.1/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(techs) != 1 || techs[0].Product != "Nginx" {
		t.Fatalf("techs = %+v", techs)
	}
	if ev.n != 1 {
		t.Fatalf("evidence = %d", ev.n)
	}
}

func TestProviderHostFallback(t *testing.T) {
	rs, _ := NewRuleSet([]Rule{{Name: "x", Product: "x", Patterns: []Pattern{{Type: "body", Value: "x"}}}})
	http := &fakeHTTP{resp: &core.Response{Status: 200, Body: []byte("x")}}
	p := &Provider{HTTP: http, Rules: rs}
	_, err := p.Fingerprint(context.Background(), core.Target{
		Kind: core.TargetHost, Host: "127.0.0.1", Port: 8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	if http.lastURL != "http://127.0.0.1:8080" {
		t.Fatalf("url = %q", http.lastURL)
	}
}
