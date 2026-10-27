package nuclei_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/auditlog"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/settings"
	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/harness/fakenuclei"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
)

func newNucleiRuntime(t *testing.T, runner *fakenuclei.Runner, binaries *fakenuclei.Binaries) *runtime.Runtime {
	t.Helper()
	reg := core.NewRegistry()
	if err := all.RegisterNuclei(reg); err != nil {
		t.Fatal(err)
	}
	scope := gates.StaticScope("127.0.0.1")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		Processes: runner, Binaries: binaries,
		Settings: settings.New(map[string]any{"nuclei.version": "test-1.0"}),
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func TestNucleiScanParsesJSONL(t *testing.T) {
	runner := &fakenuclei.Runner{Stdout: []byte(
		"{\"template-id\":\"CVE-2024-0001\",\"info\":{\"severity\":\"high\"},\"matched-at\":\"http://127.0.0.1:18080\"}\n" +
			"not json\n" +
			"{\"template-id\":\"CVE-2024-0002\",\"info\":{\"severity\":\"medium\"}}\n",
	)}
	binaries := &fakenuclei.Binaries{Path: "/fake/nuclei"}
	rt := newNucleiRuntime(t, runner, binaries)

	input, _ := json.Marshal(map[string]any{
		"targets": []string{"http://127.0.0.1:18080"},
		"tags":    []string{"cve"},
	})
	res, err := rt.Call(context.Background(), "nuclei_scan", input, core.CallContext{ProjectID: 1, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	var data map[string]any
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data["hit_count"].(float64) != 2 {
		t.Fatalf("hit_count = %v", data["hit_count"])
	}
	if binaries.EnsureCalls != 1 {
		t.Fatalf("ensure calls = %d", binaries.EnsureCalls)
	}
	call, ok := runner.LastCall()
	if !ok {
		t.Fatal("runner was not called")
	}
	joined := strings.Join(call.Args, " ")
	if !strings.Contains(joined, "-u http://127.0.0.1:18080") || !strings.Contains(joined, "-tags cve") {
		t.Fatalf("args = %v", call.Args)
	}
	if len(call.Targets) != 1 || call.Targets[0].Host != "127.0.0.1" {
		t.Fatalf("targets = %+v", call.Targets)
	}
}

func TestNucleiScanScopeDenied(t *testing.T) {
	runner := &fakenuclei.Runner{}
	binaries := &fakenuclei.Binaries{Path: "/fake/nuclei"}
	rt := newNucleiRuntime(t, runner, binaries)
	input, _ := json.Marshal(map[string]any{"targets": []string{"http://example.com"}})
	_, err := rt.Call(context.Background(), "nuclei_scan", input, core.CallContext{ProjectID: 1})
	if err == nil || !strings.Contains(err.Error(), core.CodeScopeDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestNucleiStatus(t *testing.T) {
	binaries := &fakenuclei.Binaries{Path: "/fake/nuclei", State: core.BinaryStatus{
		Installed: true, Version: "test-1.0", Path: "/fake/nuclei",
	}}
	rt := newNucleiRuntime(t, &fakenuclei.Runner{}, binaries)
	res, err := rt.Call(context.Background(), "nuclei_status", json.RawMessage(`{}`), core.CallContext{})
	if err != nil {
		t.Fatal(err)
	}
	var data core.BinaryStatus
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.Version != "test-1.0" {
		t.Fatalf("status = %+v", data)
	}
}
