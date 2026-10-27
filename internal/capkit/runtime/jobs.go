package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Long-running work must not block the agent (docs §5.5.5: nuclei full scans,
// sqlmap dumps and msf runs should return StatusPartial + a JobRef and be polled
// through job_status). The runtime implements that generically: a caller sets
// "async": true on any tool input, the gate chain still runs synchronously (so a
// scope denial or a missing approval is reported immediately rather than through
// a poll), and the tool itself executes in the background while the envelope
// carries a JobRef.

// jobStatusTool is the runtime-owned polling tool.
const jobStatusTool = "job_status"

const jobStatusSchema = `{"type":"object","properties":{"job_id":{"type":"string","description":"the id a previous async call returned"}},"required":["job_id"]}`

func jobStatusSpec() core.ToolSpec {
	return core.ToolSpec{
		Name: jobStatusTool,
		Description: "查询异步任务。任何工具调用带 \"async\": true 时不会阻塞，而是立刻返回 StatusPartial 与 Data 中的 JobRef(job_id/poll_after_ms)；" +
			"之后用 job_status 轮询，running 时仍返回 partial，任务完成后返回该工具最终的完整信封（含它自己的 Status/Data/Findings/Error）。",
		Risk:         core.RiskLow,
		InputSchema:  json.RawMessage(jobStatusSchema),
		OutputSchema: json.RawMessage(`{"type":"object","properties":{"job_id":{"type":"string"},"state":{"type":"string","enum":["running","done","failed"]},"poll_after_ms":{"type":"integer"},"tool":{"type":"string"}}}`),
	}
}

// jobRecord is one accepted async call.
type jobRecord struct {
	id         string
	tool       string
	started    time.Time
	finishedAt time.Time
	done       bool
	res        core.Result
	err        error
}

// jobRegistry holds accepted jobs for the configured retention window. It is
// in-memory by design: a job is only useful to the process that started it, and
// a host that needs durable jobs keeps its own queue.
type jobRegistry struct {
	mu    sync.RWMutex
	jobs  map[string]*jobRecord
	ttl   time.Duration
	now   func() time.Time
	limit int
}

func newJobRegistry(ttl time.Duration, now func() time.Time) *jobRegistry {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &jobRegistry{jobs: map[string]*jobRecord{}, ttl: ttl, now: now, limit: 1024}
}

func (r *jobRegistry) start(id, tool string) *jobRecord {
	rec := &jobRecord{id: id, tool: tool, started: r.now()}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	// Bound memory: drop the oldest finished job when the registry is full.
	if len(r.jobs) >= r.limit {
		var oldest *jobRecord
		for _, j := range r.jobs {
			if !j.done {
				continue
			}
			if oldest == nil || j.finishedAt.Before(oldest.finishedAt) {
				oldest = j
			}
		}
		if oldest != nil {
			delete(r.jobs, oldest.id)
		}
	}
	r.jobs[id] = rec
	return rec
}

func (r *jobRegistry) finish(id string, res core.Result, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.jobs[id]; ok {
		rec.done, rec.res, rec.err, rec.finishedAt = true, res, err, r.now()
	}
}

func (r *jobRegistry) get(id string) (*jobRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	rec, ok := r.jobs[id]
	if !ok {
		return nil, false
	}
	// Copy out so a concurrent finish cannot mutate the caller's view.
	snapshot := *rec
	return &snapshot, true
}

// sweepLocked drops finished jobs past the retention window so a long-lived
// runtime does not accumulate envelopes.
func (r *jobRegistry) sweepLocked() {
	for id, rec := range r.jobs {
		if rec.done && r.now().Sub(rec.finishedAt) > r.ttl {
			delete(r.jobs, id)
		}
	}
}

// asyncRequested reports whether the caller opted into background execution.
func asyncRequested(input json.RawMessage) bool {
	if len(input) == 0 {
		return false
	}
	var probe struct {
		Async bool `json:"async"`
	}
	if err := json.Unmarshal(input, &probe); err != nil {
		return false
	}
	return probe.Async
}

// jobRefResult is the envelope an accepted async call returns: partial, with the
// JobRef in Data and a Next step pointing at job_status (§5.5.5).
func jobRefResult(tool, id string, pollMS int) core.Result {
	res := core.NewResult(core.StatusPartial, "")
	res.Summary = core.ClampSummary(fmt.Sprintf("%s 已转入后台执行（job_id=%s），请用 job_status 轮询", tool, id))
	res.Data, _ = json.Marshal(map[string]any{"job_id": id, "poll_after_ms": pollMS, "tool": tool})
	res.Next = []core.NextStep{{
		Tool: jobStatusTool, Reason: "等待后台任务完成", Risk: core.RiskLow,
		Params: json.RawMessage(fmt.Sprintf(`{"job_id":%q}`, id)),
	}}
	return res
}

// jobStatus handles the polling tool. A running job keeps returning partial; a
// finished job returns the envelope the tool itself produced, so the agent sees
// the real findings/evidence/error rather than a re-summary of them.
func (r *Runtime) jobStatus(input json.RawMessage) core.Result {
	var in struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error()))
	}
	if in.JobID == "" {
		return core.FailResult(core.InvalidInput("job_id 必填"))
	}
	rec, ok := r.jobs.get(in.JobID)
	if !ok {
		return core.FailResult(core.NotFound("任务不存在或已过期: " + in.JobID))
	}
	if !rec.done {
		res := core.NewResult(core.StatusPartial, "")
		res.Summary = core.ClampSummary(rec.tool + " 仍在后台执行（job_id=" + rec.id + "）")
		res.Data, _ = json.Marshal(map[string]any{
			"job_id": rec.id, "state": "running", "tool": rec.tool,
			"elapsed_ms": r.now().Sub(rec.started).Milliseconds(), "poll_after_ms": 2000,
		})
		res.Next = []core.NextStep{{
			Tool: jobStatusTool, Reason: "继续轮询直到任务结束", Risk: core.RiskLow,
			Params: json.RawMessage(fmt.Sprintf(`{"job_id":%q}`, rec.id)),
		}}
		return res
	}
	return rec.res
}

// runAsync executes an already-gated call off the request path. It detaches from
// the caller's cancellation (context.WithoutCancel) so an HTTP timeout does not
// kill accepted work, while keeping the call context, gate trace and request
// counter alive for the tool.
func (r *Runtime) runAsync(ctx context.Context, rec *jobRecord, cap core.Capability, tool, version string, input json.RawMessage, cc core.CallContext, finish func(core.Result, error)) {
	go func() {
		jobCtx := withRequestCounter(context.WithoutCancel(ctx))
		if r.jobTimeout > 0 {
			var cancel context.CancelFunc
			jobCtx, cancel = context.WithTimeout(jobCtx, r.jobTimeout)
			defer cancel()
		}
		res, err := cap.Call(jobCtx, core.Call{Tool: tool, Input: input, Context: cc})
		if err != nil {
			res = core.FailResult(err)
		}
		res = r.finalize(jobCtx, res, tool, version, cc, r.now())
		r.jobs.finish(rec.id, res, err)
		finish(res, err)
	}()
}
