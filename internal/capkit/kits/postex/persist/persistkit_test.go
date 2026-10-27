package persist

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// fakeSession is a scripted core.Session. Exec matches a substring of the
// command and returns the canned output; unmatched commands return exit 0 with
// empty output (read-only enumeration tolerates that).
type fakeSession struct {
	os  string
	out map[string]core.Output
	// calls records every command executed, in order.
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
	return core.Output{Command: cmd, ExitCode: 0}, nil
}

func (f *fakeSession) Info() core.SessionInfo {
	return core.SessionInfo{ID: "s1", OS: f.os, Host: "10.0.0.5"}
}
func (f *fakeSession) Close() error { return nil }

// fakeManager satisfies core.SessionManager.
type fakeManager struct {
	sess core.Session
}

func (m *fakeManager) Open(context.Context, core.SessionSpec) (core.SessionInfo, error) {
	return core.SessionInfo{}, nil
}
func (m *fakeManager) Get(id string) (core.Session, bool) {
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
		t.Fatalf("NewCapability: %v", err)
	}
	return c.(*Capability)
}

func call(t *testing.T, c *Capability, tool string, in any) core.Result {
	t.Helper()
	raw, _ := json.Marshal(in)
	res, err := c.Call(context.Background(), core.Call{Tool: tool, Input: raw})
	if err != nil {
		t.Fatalf("%s: unexpected transport error: %v", tool, err)
	}
	return res
}

func TestManifestSchemas(t *testing.T) {
	m := Manifest()
	if m.Name != "persistkit" {
		t.Fatalf("name = %q", m.Name)
	}
	want := map[string]bool{"persist_enum": true, "persist_plan": true, "persist_apply": true}
	if len(m.Tools) != len(want) {
		t.Fatalf("tool count = %d, want %d", len(m.Tools), len(want))
	}
	for _, spec := range m.Tools {
		if !want[spec.Name] {
			t.Errorf("unexpected tool %q", spec.Name)
		}
		if len(spec.InputSchema) == 0 || !json.Valid(spec.InputSchema) {
			t.Errorf("%s: bad InputSchema", spec.Name)
		}
		if len(spec.OutputSchema) == 0 || !json.Valid(spec.OutputSchema) {
			t.Errorf("%s: bad OutputSchema", spec.Name)
		}
		if !spec.Risk.Valid() {
			t.Errorf("%s: invalid risk %q", spec.Name, spec.Risk)
		}
	}
}

func TestUnknownTool(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	res := call(t, c, "persist_bogus", map[string]any{"session_id": "s1"})
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("got status=%s err=%+v", res.Status, res.Error)
	}
}

func TestMissingManagerFailsClosed(t *testing.T) {
	c, _ := NewCapability(core.Deps{})
	res, _ := c.(*Capability).Call(context.Background(), core.Call{Tool: "persist_enum", Input: json.RawMessage(`{"session_id":"x"}`)})
	if res.Status != core.StatusUnavailable || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("got status=%s err=%+v", res.Status, res.Error)
	}
}

func TestSessionNotFound(t *testing.T) {
	c, _ := NewCapability(core.Deps{Sessions: &fakeManager{}})
	res, _ := c.(*Capability).Call(context.Background(), core.Call{Tool: "persist_enum", Input: json.RawMessage(`{"session_id":"missing"}`)})
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("got %+v", res.Error)
	}
}

func TestEnumLinux(t *testing.T) {
	sess := &fakeSession{os: "linux", out: map[string]core.Output{
		"crontab":                {Stdout: "* * * * * root /tmp/x\n"},
		"ls -la /etc/cron.d/":    {Stdout: "-rw-r--r-- 1 root root 20 cron.d\n"},
		"systemctl list-unit":    {Stdout: "sshd.service enabled\n"},
		"authorized_keys":        {Stdout: "ssh-rsa AAAA attacker@host\n"},
		"cat /etc/ld.so.preload": {Stdout: "/tmp/evil.so\n"},
		"grep -Rni 'pam_exec'":   {Stdout: "/etc/pam.d/sshd:1:auth sufficient pam_exec.so\n"},
	}}
	c := newCap(t, sess)
	res := call(t, c, "persist_enum", map[string]any{"session_id": "s1"})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s summary=%s", res.Status, res.Summary)
	}
	var data struct {
		Platform string         `json:"platform"`
		Commands []enumResult   `json:"commands"`
		Signals  map[string]any `json:"signals"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.Platform != "linux" {
		t.Fatalf("platform=%s", data.Platform)
	}
	if len(data.Commands) == 0 {
		t.Fatal("no enumeration commands recorded")
	}
	if data.Signals["ld_preload_present"] != true {
		t.Errorf("ld_preload signal missing: %+v", data.Signals)
	}
}

func TestEnumWindowsSignals(t *testing.T) {
	sess := &fakeSession{os: "windows", out: map[string]core.Output{
		"schtasks":   {Stdout: "TaskName: \\CapKitUpdate\nTaskName: \\Microsoft\\Foo\n"},
		"run_hkcu":   {Stdout: "    Updater    REG_SZ    C:\\x.exe\n"},
		"wmi_events": {Stdout: "Name\nFoo\n"},
	}}
	c := newCap(t, sess)
	res := call(t, c, "persist_enum", map[string]any{"session_id": "s1"})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s", res.Status)
	}
	var data struct {
		Platform string         `json:"platform"`
		Signals  map[string]any `json:"signals"`
	}
	_ = json.Unmarshal(res.Data, &data)
	if data.Platform != "windows" {
		t.Fatalf("platform=%s", data.Platform)
	}
	if data.Signals["autorun_hkcu"] != true {
		t.Errorf("autorun signal: %+v", data.Signals)
	}
}

func TestEnumPartialWhenTransportFails(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux", fail: true})
	res := call(t, c, "persist_enum", map[string]any{"session_id": "s1"})
	if res.Status != core.StatusPartial {
		t.Fatalf("status=%s (want partial)", res.Status)
	}
}

func TestPlanLinuxCron(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	res := call(t, c, "persist_plan", map[string]any{
		"session_id": "s1", "technique": "linux-cron", "payload": "/tmp/implant",
		"name": "updater", "schedule": "*/5 * * * *",
	})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
	var pl Plan
	if err := json.Unmarshal(res.Data, &pl); err != nil {
		t.Fatal(err)
	}
	if pl.Technique != "linux-cron" || len(pl.Steps) == 0 {
		t.Fatalf("plan=%+v", pl)
	}
	if !strings.Contains(pl.Steps[0].Command, "/tmp/implant") {
		t.Errorf("cron line missing payload: %s", pl.Steps[0].Command)
	}
	if len(pl.Revert) == 0 {
		t.Error("expected a revert step")
	}
	if len(res.Next) == 0 || res.Next[0].Tool != "persist_apply" {
		t.Errorf("expected a persist_apply suggestion, got %+v", res.Next)
	}
}

func TestPlanAllTechniques(t *testing.T) {
	cases := []struct {
		tech  string
		plat  string
		extra map[string]any
	}{
		{"linux-cron", "linux", nil},
		{"linux-systemd", "linux", nil},
		{"linux-ssh-key", "linux", map[string]any{"public_key": "ssh-ed25519 AAAA x"}},
		{"linux-bashrc", "linux", nil},
		{"linux-ldpreload", "linux", nil},
		{"linux-pam", "linux", nil},
		{"windows-schtasks", "windows", nil},
		{"windows-service", "windows", nil},
		{"windows-registry-run", "windows", nil},
		{"windows-wmi-subscription", "windows", nil},
		{"windows-com-hijack", "windows", nil},
	}
	for _, tc := range cases {
		t.Run(tc.tech, func(t *testing.T) {
			c := newCap(t, &fakeSession{os: tc.plat})
			in := map[string]any{"session_id": "s1", "technique": tc.tech, "payload": "/tmp/p", "name": "x"}
			for k, v := range tc.extra {
				in[k] = v
			}
			res := call(t, c, "persist_plan", in)
			if res.Status != core.StatusSuccess {
				t.Fatalf("status=%s err=%+v", res.Status, res.Error)
			}
			var pl Plan
			if err := json.Unmarshal(res.Data, &pl); err != nil {
				t.Fatal(err)
			}
			if len(pl.Steps) == 0 || len(pl.Revert) == 0 {
				t.Fatalf("plan for %s missing steps/revert: %+v", tc.tech, pl)
			}
		})
	}
}

func TestPlanValidation(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	// unknown technique
	res := call(t, c, "persist_plan", map[string]any{"session_id": "s1", "technique": "nope"})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("unknown technique: %+v", res.Error)
	}
	// payload required
	res = call(t, c, "persist_plan", map[string]any{"session_id": "s1", "technique": "linux-cron"})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("missing payload: %+v", res.Error)
	}
	// ssh-key needs public_key
	res = call(t, c, "persist_plan", map[string]any{"session_id": "s1", "technique": "linux-ssh-key"})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("missing public_key: %+v", res.Error)
	}
	// platform mismatch
	res = call(t, c, "persist_plan", map[string]any{"session_id": "s1", "technique": "windows-service", "payload": "x", "platform": "linux"})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("platform mismatch: %+v", res.Error)
	}
	// newline injection in name
	res = call(t, c, "persist_plan", map[string]any{"session_id": "s1", "technique": "linux-cron", "payload": "x", "name": "a\nb"})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("newline name: %+v", res.Error)
	}
}

func TestApplyRequiresConfirm(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	res := call(t, c, "persist_apply", map[string]any{"session_id": "s1", "technique": "linux-cron", "payload": "/tmp/p", "confirm": false})
	if res.Status != core.StatusNeedHuman || res.Error.Code != core.CodeNeedHuman {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
}

func TestApplyRunsSteps(t *testing.T) {
	sess := &fakeSession{os: "linux"}
	c := newCap(t, sess)
	res := call(t, c, "persist_apply", map[string]any{
		"session_id": "s1", "technique": "linux-systemd", "payload": "/tmp/p", "name": "svc", "confirm": true,
	})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
	if len(sess.calls) == 0 {
		t.Fatal("no steps executed")
	}
	if len(res.Findings) == 0 || !strings.HasPrefix(res.Findings[0].Kind, "persistence:") {
		t.Errorf("expected a persistence finding, got %+v", res.Findings)
	}
}

func TestApplyPartialOnStepFailure(t *testing.T) {
	sess := &fakeSession{os: "linux", out: map[string]core.Output{
		"systemctl": {ExitCode: 1, Stderr: "not found"},
	}}
	c := newCap(t, sess)
	res := call(t, c, "persist_apply", map[string]any{
		"session_id": "s1", "technique": "linux-systemd", "payload": "/tmp/p", "confirm": true,
	})
	if res.Status != core.StatusPartial {
		t.Fatalf("status=%s (want partial)", res.Status)
	}
}

func TestDefaultNameSanitized(t *testing.T) {
	got := defaultName(planInput{Name: "a/../b;rm -rf *"}, "fb")
	if strings.ContainsAny(got, "/;* ") {
		t.Fatalf("unsanitized name: %q", got)
	}
	if defaultName(planInput{}, "fallback") != "fallback" {
		t.Fatal("expected fallback name")
	}
	long := defaultName(planInput{Name: strings.Repeat("a", 100)}, "fb")
	if len(long) > 48 {
		t.Fatalf("name not truncated: %d", len(long))
	}
}

func TestDetectPlatformProbe(t *testing.T) {
	sess := &fakeSession{os: "", out: map[string]core.Output{"uname -s": {Stdout: "Linux\n"}}}
	c := newCap(t, sess)
	if got := detectPlatform(context.Background(), c, sess, 0); got != "linux" {
		t.Fatalf("detectPlatform = %q", got)
	}
	// no OS, no output -> assume windows
	sess2 := &fakeSession{os: ""}
	c2 := newCap(t, sess2)
	if got := detectPlatform(context.Background(), c2, sess2, 0); got != "windows" {
		t.Fatalf("detectPlatform = %q", got)
	}
}

func TestEnumCommandsBothPlatforms(t *testing.T) {
	if len(enumCommands("linux")) == 0 {
		t.Fatal("no linux enum commands")
	}
	if len(enumCommands("windows")) == 0 {
		t.Fatal("no windows enum commands")
	}
}
