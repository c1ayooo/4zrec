package runtime_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// TestAsyncCallReturnsJobRefAndIsPollable covers docs §5.5.5: a call with
// "async": true must not block — it returns StatusPartial with a JobRef in Data
// and a next step pointing at job_status, which then returns the real envelope.
func TestAsyncCallReturnsJobRefAndIsPollable(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // hold the request open so the job is observably running
		_, _ = w.Write([]byte("async-body"))
	}))
	defer srv.Close()

	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, _ := newRuntime(t, reg)
	ctx := context.Background()
	cc := core.CallContext{ProjectID: 3, Actor: "async-test"}

	input, _ := json.Marshal(map[string]any{"url": srv.URL, "async": true})
	started, err := rt.Call(ctx, "http_probe", input, cc)
	if err != nil {
		t.Fatal(err)
	}
	if started.Status != core.StatusPartial {
		t.Fatalf("status = %q, want partial", started.Status)
	}
	var ref struct {
		JobID       string `json:"job_id"`
		PollAfterMS int    `json:"poll_after_ms"`
		Tool        string `json:"tool"`
	}
	if err := json.Unmarshal(started.Data, &ref); err != nil {
		t.Fatal(err)
	}
	if ref.JobID == "" || ref.PollAfterMS <= 0 || ref.Tool != "http_probe" {
		t.Fatalf("job ref = %+v", ref)
	}
	if len(started.Next) != 1 || started.Next[0].Tool != "job_status" {
		t.Fatalf("next = %+v", started.Next)
	}

	// While the underlying request is blocked, polling reports running.
	poll, _ := json.Marshal(map[string]any{"job_id": ref.JobID})
	running, err := rt.Call(ctx, "job_status", poll, cc)
	if err != nil {
		t.Fatal(err)
	}
	if running.Status != core.StatusPartial {
		t.Fatalf("running status = %q", running.Status)
	}
	if !json.Valid(running.Data) {
		t.Fatalf("running data = %s", running.Data)
	}

	// Let the request finish; the poll then returns the tool's own envelope.
	close(release)
	var done core.Result
	for i := 0; i < 100; i++ {
		done, err = rt.Call(ctx, "job_status", poll, cc)
		if err != nil {
			t.Fatal(err)
		}
		if done.Status != core.StatusPartial {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if done.Status != core.StatusSuccess {
		t.Fatalf("final status = %q (summary %q)", done.Status, done.Summary)
	}
	if done.Meta.Tool != "http_probe" {
		t.Fatalf("final meta.tool = %q, want the producing tool", done.Meta.Tool)
	}
	if done.Meta.Requests < 1 {
		t.Fatalf("final meta.requests = %d", done.Meta.Requests)
	}
	if len(done.Data) == 0 {
		t.Fatal("final result must carry the tool's Data")
	}
}

// TestAsyncStillEnforcesScopeFirst keeps the gate ordering from §5.5.5 honest:
// an out-of-scope target must fail immediately, not via a poll.
func TestAsyncStillEnforcesScopeFirst(t *testing.T) {
	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, _ := newRuntime(t, reg)
	input, _ := json.Marshal(map[string]any{"url": "http://example.com/", "async": true})
	res, err := rt.Call(context.Background(), "http_probe", input, core.CallContext{ProjectID: 1})
	if err == nil || res.Status != core.StatusBlocked || res.Error.Code != core.CodeScopeDenied {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(res.Data) != 0 {
		t.Fatalf("a blocked async call must not hand back a job: %s", res.Data)
	}
}

func TestJobStatusUnknownJob(t *testing.T) {
	reg := core.NewRegistry()
	if err := all.RegisterHTTP(reg); err != nil {
		t.Fatal(err)
	}
	rt, _ := newRuntime(t, reg)
	res, _ := rt.Call(context.Background(), "job_status", json.RawMessage(`{"job_id":"job-nope"}`), core.CallContext{})
	if res.Status != core.StatusFailed || res.Error.Code != core.CodeNotFound {
		t.Fatalf("res = %+v", res)
	}
	res, _ = rt.Call(context.Background(), "job_status", json.RawMessage(`{}`), core.CallContext{})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("res = %+v", res)
	}
}
