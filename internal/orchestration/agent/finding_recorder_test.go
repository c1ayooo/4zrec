package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/domain/evidence"
)

func TestReportFindingEvidenceGateAndConfidence(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("evidence gate", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID = d.Exploration(task.ExplorationID), task.ID
	ts.worker = "fixture"
	call := func(body string) string {
		t.Helper()
		res, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten()
	}

	// 没有任何证据材料 → 服务端拒绝登记。
	got := call(`{"vulnclass":"TEST","severity":"low","summary":"no evidence"}`)
	if !strings.Contains(got, "证据门槛") {
		t.Fatalf("expected evidence gate, got: %s", got)
	}

	// 只有 evidence 却自称 verified → 降级为 partial。
	got = call(`{"vulnclass":"TEST","severity":"low","summary":"partial evidence","evidence":"command output","confidence":"verified"}`)
	lines := strings.SplitN(got, "\n", 2)
	if len(lines) != 2 {
		t.Fatalf("bad output: %s", got)
	}
	var out struct {
		Confidence     string `json:"confidence"`
		ConfidenceNote string `json:"confidence_note"`
		FindingID      int64  `json:"finding_id,string"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &out); err != nil {
		t.Fatal(err)
	}
	if out.Confidence != db.ConfidencePartial || !strings.Contains(out.ConfidenceNote, "降为 partial") {
		t.Fatalf("verified without repro/traffic should downgrade: %s", got)
	}
	f, err := d.GetFinding(out.FindingID)
	if err != nil || f == nil || f.Confidence != db.ConfidencePartial {
		t.Fatalf("stored confidence: %+v %v", f, err)
	}
}

func TestReportFindingDedupe(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("dedupe", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID = d.Exploration(task.ExplorationID), task.ID
	ts.worker = "fixture"
	body := `{"vulnclass":"SQLi","name":"布尔盲注","severity":"high","summary":"boolean blind sqli","evidence":"baseline vs true/false diff"}`
	first, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
	if err != nil || first.IsError {
		t.Fatalf("first report: %v %s", err, first.Flatten())
	}
	if dup, derr := ts.ts.FindDuplicateFinding(t.Context(), "SQLi", "布尔盲注", "boolean blind sqli", nil); derr != nil || dup == nil {
		t.Fatalf("dedupe lookup: dup=%+v err=%v", dup, derr)
	}
	second, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
	if err != nil || second.IsError {
		t.Fatalf("second report: %v %s", err, second.Flatten())
	}
	if !strings.Contains(second.Flatten(), "finding already recorded") || !strings.Contains(second.Flatten(), `"duplicate":true`) {
		t.Fatalf("expected duplicate response: %s", second.Flatten())
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("findings count = %d, want 1", count)
	}
}

type failingFindingRecorder struct{}

func (failingFindingRecorder) Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error) {
	return nil, errors.New("fixture persistence failed")
}

func TestReportFindingOptionalTrafficWithoutCapture(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("TCP evidence", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID = d.Exploration(task.ExplorationID), task.ID
	ts.SetFindingRecorder(evidence.New(d, nil, t.TempDir()))
	notices := 0
	ts.notifyFinding = func(int64, string) { notices++ }
	for i, refs := range []string{"", `,"traffic_refs":[]`, `,"traffic_refs":null`} {
		body := fmt.Sprintf(`{"vulnclass":"TCP","severity":"low","summary":"verified TCP fixture %d","evidence":"command output proves the finding"%s}`, i+1, refs)
		res, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
		if err != nil || !strings.HasPrefix(res.Flatten(), "finding recorded: ") {
			t.Fatalf("optional traffic rejected: %v %s", err, res.Flatten())
		}
		var out db.RecordedFinding
		if err := json.Unmarshal([]byte(strings.SplitN(res.Flatten(), "\n", 2)[1]), &out); err != nil {
			t.Fatal(err)
		}
		f, err := d.GetFinding(out.FindingID)
		if err != nil || f == nil || len(out.Traffic.Bindings) != 0 || f.Evidence != "command output proves the finding" {
			t.Fatalf("lost non-HTTP evidence: %+v %v", f, err)
		}
	}
	if notices != 3 {
		t.Fatalf("successful reports notified %d times", notices)
	}
}

func TestReportFindingAtomicContract(t *testing.T) {
	old := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return true }
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("report contract", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts = d.Exploration(task.ExplorationID)
	ts.taskID = task.ID
	ts.worker = "fixture"
	notices := 0
	ts.notifyFinding = func(int64, string) { notices++ }
	call := func(body string) string {
		t.Helper()
		res, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten()
	}
	ts.SetFindingRecorder(failingFindingRecorder{})
	if got := call(`{"vulnclass":"TEST","summary":"fail","severity":"low","traffic_refs":[{"traffic_id":"x"}]}`); !strings.Contains(got, "persistence failed") {
		t.Fatal(got)
	}
	if notices != 0 || ts.writes.Findings != 0 {
		t.Fatal("notified before commit")
	}
	ts.SetFindingRecorder(nil)
	got := call(`{"vulnclass":"TEST","summary":"legacy report","severity":"low","evidence":"command output proves the finding"}`)
	lines := strings.SplitN(got, "\n", 2)
	if len(lines) != 2 {
		t.Fatal(got)
	}
	var out db.RecordedFinding
	if err = json.Unmarshal([]byte(lines[1]), &out); err != nil {
		t.Fatal(err)
	}
	if lines[0] != fmt.Sprintf("finding recorded: %d", out.NodeID) || out.FindingID <= 0 || notices != 1 {
		t.Fatal(got)
	}
	f, err := d.GetFinding(out.FindingID)
	if err != nil || f == nil || f.NodeID == nil || *f.NodeID != out.NodeID {
		t.Fatalf("wrong finding/node mapping: %+v %v", f, err)
	}
	if got = call(`{"vulnclass":"TEST","summary":"no storage","severity":"low","traffic_refs":[{"traffic_id":"x"}]}`); !strings.Contains(got, "未登记") {
		t.Fatal(got)
	}
	if notices != 1 {
		t.Fatal("failed tool triggered reporter")
	}
}
