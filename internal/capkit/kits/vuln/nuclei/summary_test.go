package nuclei_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/harness"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/nuclei"
)

func TestNucleiStatusSummary(t *testing.T) {
	ports := harness.NewPorts()
	ports.Binaries.State = core.BinaryStatus{Installed: true, Version: "test-1.0", Path: "/fake/nuclei"}
	kit := nuclei.New(ports.Deps())
	res, err := kit.Call(context.Background(), core.Call{Tool: "nuclei_status", Input: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"已安装", "test-1.0", "/fake/nuclei"} {
		if !strings.Contains(res.Summary, want) {
			t.Fatalf("summary %q missing %q", res.Summary, want)
		}
	}
	if res.Meta.Tool != "nuclei_status" || res.Meta.Version != "0.1.0" {
		t.Fatalf("meta = %+v", res.Meta)
	}
	if !res.OK || res.Status != core.StatusSuccess {
		t.Fatalf("result = %+v", res)
	}
}

func TestNucleiStatusNotInstalledSummary(t *testing.T) {
	ports := harness.NewPorts()
	ports.Binaries.State = core.BinaryStatus{Installed: false, Version: "0.0.0"}
	kit := nuclei.New(ports.Deps())
	res, _ := kit.Call(context.Background(), core.Call{Tool: "nuclei_status", Input: json.RawMessage(`{}`)})
	if !strings.Contains(res.Summary, "未安装") {
		t.Fatalf("summary = %q", res.Summary)
	}
}

func TestNucleiScanSummary(t *testing.T) {
	ports := harness.NewPorts()
	ports.Process.Stdout = []byte(
		`{"template-id":"CVE-1","info":{"severity":"critical"}}` + "\n" +
			`{"template-id":"CVE-2","info":{"severity":"high"}}` + "\n" +
			`{"template-id":"CVE-3","info":{"severity":"high"}}` + "\n")
	kit := nuclei.New(ports.Deps())
	input, _ := json.Marshal(map[string]any{
		"targets":   []string{"http://127.0.0.1:18080"},
		"templates": []string{"t1", "t2"},
	})
	res, err := kit.Call(context.Background(), core.Call{Tool: "nuclei_scan", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"对 http://127.0.0.1:18080 执行 2 个模板", "命中 3 项", "严重 1/高危 2"} {
		if !strings.Contains(res.Summary, want) {
			t.Fatalf("summary %q missing %q", res.Summary, want)
		}
	}
}
