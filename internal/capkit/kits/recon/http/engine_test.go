package http

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type fakeDoer struct {
	resp *core.Response
	last core.Request
}

func (f *fakeDoer) Do(_ context.Context, req core.Request) (*core.Response, error) {
	f.last = req
	return f.resp, nil
}

func TestEngineExecute(t *testing.T) {
	artifact := []byte(`{
	  "request":{"method":"GET","path":"/check?x=1"},
	  "matchers":[
	    {"type":"status","status":[200]},
	    {"type":"regex","part":"body","regex":["SQL syntax"]}
	  ],
	  "extract":[{"name":"err","regex":"SQL syntax.*"}]
	}`)
	doer := &fakeDoer{resp: &core.Response{Status: 200, Body: []byte("SQL syntax error near 'x'")}}
	kit := &Kit{HTTP: doer}
	res, err := kit.Execute(context.Background(), []core.TemplateRef{{
		ID: "t1", Kind: "http", Artifact: artifact,
	}}, core.Target{Kind: core.TargetURL, URL: "http://127.0.0.1:8080"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	var data struct {
		Results []engineResult `json:"results"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Results) != 1 || !data.Results[0].Matched {
		t.Fatalf("results = %+v", data.Results)
	}
	if data.Results[0].Extracted["err"] != "SQL syntax error near 'x'" {
		t.Fatalf("extract = %+v", data.Results[0].Extracted)
	}
	if doer.last.URL != "http://127.0.0.1:8080/check?x=1" {
		t.Fatalf("url = %q", doer.last.URL)
	}
}
