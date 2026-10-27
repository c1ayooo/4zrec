package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/auditlog"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/sealer"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/settings"
	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime/httpapi"
)

func TestHandlerToolsAndCall(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer target.Close()

	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	scope := gates.StaticScope("127.0.0.1")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	seal, _ := sealer.New([]byte("test"))
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		HTTP: httpx.New(scope, lim, audit), Settings: settings.New(nil), Sealer: seal,
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(httpapi.New(rt))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tools")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var tools struct {
		Tools []core.ToolSpec `json:"tools"`
	}
	if err := json.Unmarshal(body, &tools); err != nil {
		t.Fatal(err)
	}
	// The runtime contributes job_status on top of the registered kits.
	names := map[string]bool{}
	for _, t2 := range tools.Tools {
		names[t2.Name] = true
	}
	if !names["http_probe"] || !names["job_status"] || len(tools.Tools) != 2 {
		t.Fatalf("tools = %+v", names)
	}

	reqBody, _ := json.Marshal(map[string]any{
		"tool":    "http_probe",
		"input":   map[string]any{"url": target.URL},
		"context": map[string]any{"project_id": 1, "actor": "tester"},
	})
	resp, err = http.Post(srv.URL+"/call", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var out struct {
		Result core.Result `json:"result"`
		Error  string      `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Error != "" || !out.Result.OK {
		t.Fatalf("out = %+v", out)
	}
}
