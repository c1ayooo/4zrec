package cleanup

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type fakeSession struct {
	os    string
	out   map[string]core.Output
	calls []string
	fail  bool
}

func (f *fakeSession) Exec(_ context.Context, cmd string, _ core.ExecOpts) (core.Output, error) {
	f.calls = append(f.calls, cmd)
	if f.fail {
		return core.Output{}, context.DeadlineExceeded
	}
	for k, v := range f.out {
		if strings.Contains(cmd, k) {
			v.Command = cmd
			return v, nil
		}
	}
	return core.Output{Command: cmd}, nil
}

func (f *fakeSession) Info() core.SessionInfo {
	return core.SessionInfo{ID: "s1", OS: f.os, Host: "10.0.0.5"}
}
func (f *fakeSession) Close() error { return nil }

type fakeManager struct{ sess core.Session }

func (m *fakeManager) Open(context.Context, core.SessionSpec) (core.SessionInfo, error) {
	return core.SessionInfo{}, nil
}
func (m *fakeManager) Get(string) (core.Session, bool) {
	if m.sess == nil {
		return nil, false
	}
	return m.sess, true
}
func (m *fakeManager) List() []core.SessionInfo { return nil }
func (m *fakeManager) Close(string) error       { return nil }

func newCap(t *testing.T, s core.Session) *Capability {
	t.Helper()
	c, err := NewCapability(core.Deps{Sessions: &fakeManager{sess: s}})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Capability)
}

func call(t *testing.T, c *Capability, tool string, in any) core.Result {
	t.Helper()
	raw, _ := json.Marshal(in)
	res, err := c.Call(context.Background(), core.Call{Tool: tool, Input: raw})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return res
}

func TestManifestSchemas(t *testing.T) {
	m := Manifest()
	if len(m.Tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(m.Tools))
	}
	for _, spec := range m.Tools {
		if !json.Valid(spec.InputSchema) || len(spec.InputSchema) == 0 {
			t.Errorf("%s: bad InputSchema", spec.Name)
		}
		if !json.Valid(spec.OutputSchema) || len(spec.OutputSchema) == 0 {
			t.Errorf("%s: bad OutputSchema", spec.Name)
		}
		if !spec.Risk.Valid() {
			t.Errorf("%s: invalid risk", spec.Name)
		}
	}
	if Manifest().Tools[1].Risk != core.RiskHigh {
		t.Error("cleanup_apply must be high risk")
	}
}

func TestUnknownTool(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	res := call(t, c, "cleanup_bogus", map[string]any{"session_id": "s1"})
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("%+v", res.Error)
	}
}

func TestMissingManagerFailsClosed(t *testing.T) {
	c, _ := NewCapability(core.Deps{})
	res, _ := c.(*Capability).Call(context.Background(), core.Call{Tool: "cleanup_preview", Input: json.RawMessage(`{"session_id":"x"}`)})
	if res.Status != core.StatusUnavailable || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
}

func TestPreviewReturnsPlanID(t *testing.T) {
	sess := &fakeSession{os: "linux", out: map[string]core.Output{
		"grep -c": {Stdout: "3\n"},
		"ls -la":  {Stdout: "file\n"},
	}}
	c := newCap(t, sess)
	res := call(t, c, "cleanup_preview", map[string]any{
		"session_id": "s1",
		"scope": []map[string]any{
			{"kind": "log", "path": "/var/log/auth.log", "pattern": "10.0.0.9"},
			{"kind": "file", "path": "/tmp/dropper.sh"},
		},
	})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
	var data struct {
		PlanID   string          `json:"plan_id"`
		Targets  []targetPreview `json:"targets"`
		Commands []string        `json:"commands"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.PlanID == "" {
		t.Fatal("no plan_id")
	}
	if len(data.Targets) != 2 {
		t.Fatalf("targets=%d", len(data.Targets))
	}
	if len(data.Commands) == 0 {
		t.Fatal("no commands shown")
	}
	// Preview must be read-only: no delete/rm/sed -i command was executed.
	for _, cmd := range sess.calls {
		if strings.Contains(cmd, "rm -f") || strings.Contains(cmd, "sed -i") || strings.Contains(cmd, "wevtutil cl") {
			t.Fatalf("preview executed a destructive command: %s", cmd)
		}
	}
	if len(res.Next) == 0 || res.Next[0].Tool != "cleanup_apply" {
		t.Errorf("expected cleanup_apply suggestion, got %+v", res.Next)
	}
}

func TestPreviewRejectsBlanketAndEmptyScope(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	for _, path := range []string{"/", "*", "/var/log/*", ""} {
		res := call(t, c, "cleanup_preview", map[string]any{
			"session_id": "s1", "scope": []map[string]any{{"kind": "file", "path": path}},
		})
		if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
			t.Errorf("path %q: want invalid_input, got %+v", path, res.Error)
		}
	}
	// empty scope
	res := call(t, c, "cleanup_preview", map[string]any{"session_id": "s1"})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("empty scope: %+v", res.Error)
	}
}

func TestPreviewRequiresPatternForLogKinds(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	res := call(t, c, "cleanup_preview", map[string]any{
		"session_id": "s1", "scope": []map[string]any{{"kind": "log", "path": "/var/log/auth.log"}},
	})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("log without pattern should be rejected: %+v", res.Error)
	}
}

func TestPreviewPlatformKindMismatch(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	res := call(t, c, "cleanup_preview", map[string]any{
		"session_id": "s1", "scope": []map[string]any{{"kind": "eventlog", "path": "Security"}},
	})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("eventlog on linux should be rejected: %+v", res.Error)
	}
}

func TestApplyRequiresConfirm(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	res := call(t, c, "cleanup_apply", map[string]any{
		"session_id": "s1", "plan_id": "x", "confirm": false,
		"scope": []map[string]any{{"kind": "file", "path": "/tmp/a"}},
	})
	if res.Status != core.StatusNeedHuman || res.Error.Code != core.CodeNeedHuman {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
}

func TestApplyRejectsPlanIDMismatch(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	// plan_id that does not correspond to any real plan for this scope
	res := call(t, c, "cleanup_apply", map[string]any{
		"session_id": "s1", "plan_id": "deadbeef", "confirm": true,
		"scope": []map[string]any{{"kind": "file", "path": "/tmp/a"}},
	})
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeConflict {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
}

func TestApplyRejectsScopeWideningAfterPreview(t *testing.T) {
	sess := &fakeSession{os: "linux"}
	c := newCap(t, sess)
	scope := []map[string]any{{"kind": "file", "path": "/tmp/a"}}
	prev := call(t, c, "cleanup_preview", map[string]any{"session_id": "s1", "scope": scope})
	var data struct {
		PlanID string `json:"plan_id"`
	}
	_ = json.Unmarshal(prev.Data, &data)

	// Now apply the SAME plan_id but with an extra target -> must be refused.
	widened := []map[string]any{
		{"kind": "file", "path": "/tmp/a"},
		{"kind": "file", "path": "/etc/passwd"},
	}
	res := call(t, c, "cleanup_apply", map[string]any{
		"session_id": "s1", "plan_id": data.PlanID, "confirm": true, "scope": widened,
	})
	if res.Error == nil || res.Error.Code != core.CodeConflict {
		t.Fatalf("scope widening must be refused: status=%s err=%+v", res.Status, res.Error)
	}
}

func TestApplyRunsWithMatchingPlanIDAndBacksUp(t *testing.T) {
	sess := &fakeSession{os: "linux", out: map[string]core.Output{"cp -p": {ExitCode: 0}}}
	c := newCap(t, sess)
	scope := []map[string]any{
		{"kind": "log", "path": "/var/log/auth.log", "pattern": "10.0.0.9"},
		{"kind": "file", "path": "/tmp/dropper.sh"},
	}
	prev := call(t, c, "cleanup_preview", map[string]any{"session_id": "s1", "scope": scope})
	var data struct {
		PlanID string `json:"plan_id"`
	}
	_ = json.Unmarshal(prev.Data, &data)

	sess.calls = nil
	res := call(t, c, "cleanup_apply", map[string]any{
		"session_id": "s1", "plan_id": data.PlanID, "confirm": true, "scope": scope,
	})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
	joined := strings.Join(sess.calls, "\n")
	if !strings.Contains(joined, "cp -p") {
		t.Errorf("expected backup before delete:\n%s", joined)
	}
	if !strings.Contains(joined, "sed -i") || !strings.Contains(joined, "rm -f") {
		t.Errorf("expected sed + rm:\n%s", joined)
	}
}

func TestApplyPartialOnFailure(t *testing.T) {
	sess := &fakeSession{os: "linux", out: map[string]core.Output{"rm -f": {ExitCode: 1, Stderr: "denied"}}}
	c := newCap(t, sess)
	scope := []map[string]any{{"kind": "file", "path": "/tmp/a"}}
	prev := call(t, c, "cleanup_preview", map[string]any{"session_id": "s1", "scope": scope})
	var data struct {
		PlanID string `json:"plan_id"`
	}
	_ = json.Unmarshal(prev.Data, &data)
	res := call(t, c, "cleanup_apply", map[string]any{
		"session_id": "s1", "plan_id": data.PlanID, "confirm": true, "scope": scope,
	})
	if res.Status != core.StatusPartial {
		t.Fatalf("status=%s (want partial)", res.Status)
	}
}

func TestApplyNoBackupOption(t *testing.T) {
	sess := &fakeSession{os: "linux"}
	c := newCap(t, sess)
	scope := []map[string]any{{"kind": "file", "path": "/tmp/a"}}
	prev := call(t, c, "cleanup_preview", map[string]any{"session_id": "s1", "scope": scope})
	var data struct {
		PlanID string `json:"plan_id"`
	}
	_ = json.Unmarshal(prev.Data, &data)
	sess.calls = nil
	res := call(t, c, "cleanup_apply", map[string]any{
		"session_id": "s1", "plan_id": data.PlanID, "confirm": true, "scope": scope, "backup": false,
	})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s", res.Status)
	}
	for _, cmd := range sess.calls {
		if strings.Contains(cmd, "cp -p") {
			t.Fatalf("backup ran despite backup=false: %s", cmd)
		}
	}
}

func TestPlanHashDeterministicAndOrderInsensitive(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	mk := func(scope []map[string]any) string {
		res := call(t, c, "cleanup_preview", map[string]any{"session_id": "s1", "scope": scope})
		var d struct {
			PlanID string `json:"plan_id"`
		}
		_ = json.Unmarshal(res.Data, &d)
		return d.PlanID
	}
	a := mk([]map[string]any{
		{"kind": "file", "path": "/tmp/a"},
		{"kind": "file", "path": "/tmp/b"},
	})
	b := mk([]map[string]any{
		{"kind": "file", "path": "/tmp/b"},
		{"kind": "file", "path": "/tmp/a"},
	})
	if a != b {
		t.Fatalf("plan id not order-insensitive: %s vs %s", a, b)
	}
	c2 := mk([]map[string]any{{"kind": "file", "path": "/tmp/a"}})
	if c2 == a {
		t.Fatal("different scope produced same plan id")
	}
}

func TestPathsShorthandExpandsToFileScope(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	res := call(t, c, "cleanup_preview", map[string]any{"session_id": "s1", "paths": []string{"/tmp/a", "/tmp/b"}})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
	var data struct {
		Targets []targetPreview `json:"targets"`
	}
	_ = json.Unmarshal(res.Data, &data)
	if len(data.Targets) != 2 {
		t.Fatalf("want 2 targets from paths shorthand, got %d", len(data.Targets))
	}
}

func TestWindowsEventLogPlan(t *testing.T) {
	c := newCap(t, &fakeSession{os: "windows", out: map[string]core.Output{"wevtutil": {Stdout: "100\n"}}})
	scope := []map[string]any{{"kind": "eventlog", "path": "Security"}}
	prev := call(t, c, "cleanup_preview", map[string]any{"session_id": "s1", "scope": scope})
	if prev.Status != core.StatusSuccess {
		t.Fatalf("status=%s err=%+v", prev.Status, prev.Error)
	}
	var data struct {
		PlanID   string   `json:"plan_id"`
		Commands []string `json:"commands"`
	}
	_ = json.Unmarshal(prev.Data, &data)
	if len(data.Commands) == 0 || !strings.Contains(data.Commands[0], "wevtutil cl") {
		t.Fatalf("eventlog delete command = %v", data.Commands)
	}
}

func TestParseIntFailClosed(t *testing.T) {
	if parseInt("not-a-number") != 0 {
		t.Fatal("should fail closed")
	}
	if parseInt(" 42 \n") != 42 {
		t.Fatal("should parse 42")
	}
	if parseInt("") != 0 {
		t.Fatal("empty -> 0")
	}
}

func TestIsBlanket(t *testing.T) {
	for _, p := range []string{"/", "*", "/*", "~", "/var/log/*", `C:\`} {
		if !isBlanket(p) {
			t.Errorf("%q should be blanket", p)
		}
	}
	for _, p := range []string{"/var/log/auth.log", "/tmp/x", `C:\Windows\Temp\a.exe`} {
		if isBlanket(p) {
			t.Errorf("%q should not be blanket", p)
		}
	}
}

func TestDetectPlatform(t *testing.T) {
	s := &fakeSession{os: "", out: map[string]core.Output{"uname -s": {Stdout: "Linux\n"}}}
	c := newCap(t, s)
	if got := detectPlatform(context.Background(), c, s, 0); got != "linux" {
		t.Fatalf("got %q", got)
	}
	s2 := &fakeSession{os: ""}
	c2 := newCap(t, s2)
	if got := detectPlatform(context.Background(), c2, s2, 0); got != "windows" {
		t.Fatalf("got %q", got)
	}
}
