package nuclei_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/harness/fakenuclei"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/nuclei"
)

func TestEngineExecute(t *testing.T) {
	runner := &fakenuclei.Runner{Stdout: []byte(
		"{\"template-id\":\"t1\",\"info\":{\"severity\":\"high\"},\"matched-at\":\"http://127.0.0.1\"}\n",
	)}
	kit := nuclei.New(core.Deps{
		Processes: runner, Binaries: &fakenuclei.Binaries{Path: "/fake/nuclei"},
	})
	res, err := kit.Execute(context.Background(), []core.TemplateRef{{
		ID: "t1", Kind: "nuclei", Artifact: []byte("id: t1\ninfo:\n  name: t1\n"),
	}}, core.Target{Kind: core.TargetURL, URL: "http://127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	var data struct {
		HitCount int `json:"hit_count"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.HitCount != 1 {
		t.Fatalf("hits = %d", data.HitCount)
	}
	call, ok := runner.LastCall()
	if !ok || !strings.Contains(strings.Join(call.Args, " "), "-u http://127.0.0.1") {
		t.Fatalf("call = %+v", call.Args)
	}
}
