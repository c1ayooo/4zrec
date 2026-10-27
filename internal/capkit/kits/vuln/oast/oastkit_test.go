package oast

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type fakeFetcher struct {
	responses []*core.Response
	requests  []core.Request
}

func (f *fakeFetcher) Fetch(_ context.Context, req core.Request) (*core.Response, error) {
	f.requests = append(f.requests, req)
	if len(f.responses) == 0 {
		return &core.Response{Status: 500}, nil
	}
	res := f.responses[0]
	f.responses = f.responses[1:]
	return res, nil
}

func TestOastDomainAndRecords(t *testing.T) {
	f := &fakeFetcher{responses: []*core.Response{
		{Status: 200, Body: []byte("abc.dnslog.cn"), Headers: map[string][]string{"Set-Cookie": {"PHPSESSID=1"}}},
		{Status: 200, Body: []byte(`["1.2.3.4","5.6.7.8"]`)},
	}}
	kit := New(core.Deps{Fetcher: f})
	res, err := kit.Call(context.Background(), core.Call{Tool: "oast_get_domain", Input: json.RawMessage(`{}`)})
	if err != nil || !res.OK {
		t.Fatalf("get domain: %v %+v", err, res)
	}
	var d struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(res.Data, &d); err != nil || d.Domain != "abc.dnslog.cn" {
		t.Fatalf("domain = %+v err=%v", d, err)
	}
	res, err = kit.Call(context.Background(), core.Call{
		Tool:  "oast_get_records",
		Input: json.RawMessage(`{"domain":"abc.dnslog.cn"}`),
	})
	if err != nil || !res.OK {
		t.Fatalf("get records: %v %+v", err, res)
	}
	var r struct {
		Records []string `json:"records"`
		Count   int      `json:"count"`
	}
	if err := json.Unmarshal(res.Data, &r); err != nil || r.Count != 2 {
		t.Fatalf("records = %+v err=%v", r, err)
	}
	if len(f.requests) != 2 || !strings.Contains(f.requests[1].Headers["Cookie"], "PHPSESSID=1") {
		t.Fatalf("cookie not forwarded: %+v", f.requests)
	}
}

func TestParseRecordsLines(t *testing.T) {
	got := parseRecords([]byte("1.2.3.4%\n5.6.7.8%\n"))
	if len(got) != 2 || got[0] != "1.2.3.4" {
		t.Fatalf("records = %+v", got)
	}
}

func TestOastSummaries(t *testing.T) {
	f := &fakeFetcher{responses: []*core.Response{
		{Status: 200, Body: []byte("abc.dnslog.cn")},
		{Status: 200, Body: []byte(`["1.2.3.4","5.6.7.8"]`)},
	}}
	kit := New(core.Deps{Fetcher: f})

	res, err := kit.Call(context.Background(), core.Call{Tool: "oast_get_domain", Input: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "申请到 dnslog 回连域名 abc.dnslog.cn") {
		t.Fatalf("domain summary = %q", res.Summary)
	}
	if res.Meta.Tool != "oast_get_domain" || res.Meta.Version != "0.1.0" {
		t.Fatalf("meta = %+v", res.Meta)
	}

	res, err = kit.Call(context.Background(), core.Call{
		Tool:  "oast_get_records",
		Input: json.RawMessage(`{"domain":"abc.dnslog.cn"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "查询 abc.dnslog.cn 的 DNS 交互记录，命中 2 条") {
		t.Fatalf("records summary = %q", res.Summary)
	}
	if res.Meta.Tool != "oast_get_records" {
		t.Fatalf("meta = %+v", res.Meta)
	}
}
