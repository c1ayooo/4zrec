package privesc

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// --- fakes ---------------------------------------------------------------

// fakeSession is a canned core.Session. It never touches the network or spawns
// a process: Exec matches the command against the longest output key it contains.
type fakeSession struct {
	info      core.SessionInfo
	outputs   map[string]string
	execErr   error
	execCalls int
}

func (f *fakeSession) Exec(_ context.Context, cmd string, _ core.ExecOpts) (core.Output, error) {
	f.execCalls++
	if f.execErr != nil {
		return core.Output{}, f.execErr
	}
	keys := make([]string, 0, len(f.outputs))
	for k := range f.outputs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		if strings.Contains(cmd, k) {
			return core.Output{Command: cmd, Stdout: f.outputs[k]}, nil
		}
	}
	return core.Output{Command: cmd}, nil
}

func (f *fakeSession) Info() core.SessionInfo { return f.info }
func (f *fakeSession) Close() error           { return nil }

// fakeManager is an in-memory core.SessionManager.
type fakeManager struct{ sessions map[string]core.Session }

func (m *fakeManager) Open(context.Context, core.SessionSpec) (core.SessionInfo, error) {
	return core.SessionInfo{}, nil
}
func (m *fakeManager) Get(id string) (core.Session, bool) {
	s, ok := m.sessions[id]
	return s, ok
}
func (m *fakeManager) List() []core.SessionInfo {
	out := make([]core.SessionInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s.Info())
	}
	return out
}
func (m *fakeManager) Close(string) error { return nil }

// --- sample outputs ------------------------------------------------------

func linuxOutputs() map[string]string {
	return map[string]string{
		"uname -a":            "Linux victim 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 GNU/Linux\n",
		"uname -r":            "5.15.0-91-generic\n",
		"cat /etc/os-release": "NAME=\"Ubuntu\"\nVERSION=\"20.04.6 LTS (Focal Fossa)\"\nID=ubuntu\nVERSION_ID=\"20.04\"\n",
		"sudo -n -l": `Matching Defaults entries for www-data on victim:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on victim:
    (ALL : ALL) NOPASSWD: ALL
    (root) NOPASSWD: /usr/bin/find
    (root) /usr/bin/vim
`,
		"find / -xdev -perm -4000": "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/find\n/usr/bin/mount\n/usr/bin/su\n",
		"getcap -r /":              "/usr/bin/python3.8 = cap_setuid,cap_net_raw+ep\n/usr/bin/ping = cap_net_raw+ep\n",
		"pkexec --version":         "pkexec version 0.105\n",
		"find /etc/cron.d":         "/etc/systemd/system/evil.service\n/etc/cron.d/backup\n",
		"ls -l /etc/passwd":        "-rw-r--r-- 1 root root 1234 Jan  1 00:00 /etc/passwd\n-rw-rw-r-- 1 root root  999 Jan  1 00:00 /etc/shadow\n",
	}
}

func windowsOutputs() map[string]string {
	return map[string]string{
		"whoami /priv": `PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeDebugPrivilege              Debug programs                            Enabled
`,
		"whoami /groups": `GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                 Alias            S-1-5-32-544 Group used for deny only
`,
		"systeminfo":            "Host Name:                 VICTIM\nOS Name:                   Microsoft Windows Server 2019 Standard\nOS Version:                10.0.17763 N/A Build 17763\nSystem Type:               x64-based PC\n",
		"wmic service get":      "Name              PathName                                                    StartMode\nSpooler           C:\\WINDOWS\\System32\\spoolsv.exe                             Auto\nVulnSvc           C:\\Program Files\\Vuln App\\service.exe                       Auto\n",
		"tasklist":              "Image Name                     PID Session Name        Session#    Mem Usage\n========================= ======== ================ =========== ============\nSystem                           4 Services                   0        144 K\nsvchost.exe                   1048 Services                   0     12,345 K\n",
		"AlwaysInstallElevated": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n    AlwaysInstallElevated    REG_DWORD    0x1\nHKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n    AlwaysInstallElevated    REG_DWORD    0x1\n",
		"DefaultUserName":       "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n    DefaultUserName    REG_SZ    Administrator\n    DefaultPassword    REG_SZ    P@ssw0rd!\n",
	}
}

func linuxCap() core.Capability {
	s := &fakeSession{
		info:    core.SessionInfo{ID: "s1", Kind: "ssh", Host: "10.0.0.5", OS: "linux", Arch: "amd64"},
		outputs: linuxOutputs(),
	}
	mgr := &fakeManager{sessions: map[string]core.Session{"s1": s}}
	c, _ := NewCapability(core.Deps{Sessions: mgr})
	return c
}

func windowsCap() core.Capability {
	s := &fakeSession{
		info:    core.SessionInfo{ID: "w1", Kind: "winrm", Host: "10.0.0.9", OS: "windows"},
		outputs: windowsOutputs(),
	}
	mgr := &fakeManager{sessions: map[string]core.Session{"w1": s}}
	c, _ := NewCapability(core.Deps{Sessions: mgr})
	return c
}

func do(t *testing.T, c core.Capability, tool, input string) core.Result {
	t.Helper()
	res, err := c.Call(context.Background(), core.Call{
		Tool: tool, Input: json.RawMessage(input), Context: core.CallContext{ProjectID: 7},
	})
	if err != nil {
		t.Fatalf("Call(%s) err = %v", tool, err)
	}
	return res
}

// --- manifest ------------------------------------------------------------

func TestManifestContract(t *testing.T) {
	m := Manifest()
	if m.Name != "privesckit" || m.Version != "0.1.0" || m.APIVersion != "v1" {
		t.Fatalf("manifest = %+v", m)
	}
	wantReq := []string{"scope", "limiter", "audit", "sessions"}
	if strings.Join(m.Requires, ",") != strings.Join(wantReq, ",") {
		t.Fatalf("requires = %v", m.Requires)
	}
	if len(m.Tools) != 4 {
		t.Fatalf("tools = %d, want 4", len(m.Tools))
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest invalid: %v", err)
	}
	for _, tool := range m.Tools {
		if len(tool.InputSchema) == 0 || len(tool.OutputSchema) == 0 {
			t.Fatalf("%s missing schema", tool.Name)
		}
		var v map[string]any
		if err := json.Unmarshal(tool.OutputSchema, &v); err != nil {
			t.Fatalf("%s output_schema not JSON: %v", tool.Name, err)
		}
		if !tool.Risk.Valid() {
			t.Fatalf("%s invalid risk", tool.Name)
		}
	}
	c, err := NewCapability(core.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Manifest().Name != "privesckit" {
		t.Fatal("Capability.Manifest mismatch")
	}
}

// --- privesc_enum --------------------------------------------------------

func TestEnumLinuxHappyPath(t *testing.T) {
	res := do(t, linuxCap(), "privesc_enum", `{"session_id":"s1"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q", res.Status, res.Summary)
	}
	if res.Meta.Tool != "privesc_enum" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
	var er enumResult
	if err := json.Unmarshal(res.Data, &er); err != nil {
		t.Fatal(err)
	}
	if er.Platform != platformLinux || er.SessionID != "s1" {
		t.Fatalf("enum result = %+v", er)
	}
	if er.Kernel != "5.15.0" {
		t.Fatalf("kernel = %q", er.Kernel)
	}
	if len(er.Commands) != len(linuxEnumCommands) {
		t.Fatalf("commands = %d, want %d", len(er.Commands), len(linuxEnumCommands))
	}
	if len(er.Signals.SudoRules) != 3 {
		t.Fatalf("sudo rules = %+v", er.Signals.SudoRules)
	}
	if !er.Signals.PasswdWritable {
		t.Fatal("expected passwd_writable")
	}
	if er.Signals.PolkitVersion != "0.105" {
		t.Fatalf("polkit = %q", er.Signals.PolkitVersion)
	}
	if len(er.Signals.SUIDBinaries) == 0 || len(er.Signals.Capabilities) == 0 {
		t.Fatalf("signals = %+v", er.Signals)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings")
	}
	// enum suggests the advise tool as the next step.
	if len(res.Next) != 1 || res.Next[0].Tool != "privesc_advise" {
		t.Fatalf("next = %+v", res.Next)
	}
}

func TestEnumWindowsHappyPath(t *testing.T) {
	res := do(t, windowsCap(), "privesc_windows_enum", `{"session_id":"w1"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	var er enumResult
	if err := json.Unmarshal(res.Data, &er); err != nil {
		t.Fatal(err)
	}
	if er.Platform != platformWindows {
		t.Fatalf("platform = %q", er.Platform)
	}
	if !er.Signals.AlwaysInstallElevated {
		t.Fatal("expected AlwaysInstallElevated")
	}
	if !er.Signals.AutoLogon.HasPassword {
		t.Fatalf("autologon = %+v", er.Signals.AutoLogon)
	}
	if len(er.Signals.WhoamiPrivileges) != 4 {
		t.Fatalf("privs = %+v", er.Signals.WhoamiPrivileges)
	}
	var unquoted int
	for _, s := range er.Signals.Services {
		if s.Unquoted {
			unquoted++
		}
	}
	if unquoted != 1 {
		t.Fatalf("unquoted services = %d", unquoted)
	}
}

func TestEnumPinnedOverridesAutoDetection(t *testing.T) {
	// Empty OS: auto would fail, but the pinned Linux tool must run.
	s := &fakeSession{info: core.SessionInfo{ID: "s2", Kind: "cli"}, outputs: linuxOutputs()}
	mgr := &fakeManager{sessions: map[string]core.Session{"s2": s}}
	c, _ := NewCapability(core.Deps{Sessions: mgr})

	res := do(t, c, "privesc_linux_enum", `{"session_id":"s2"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("pinned status = %q summary=%q", res.Status, res.Summary)
	}
	var er enumResult
	_ = json.Unmarshal(res.Data, &er)
	if er.Platform != platformLinux {
		t.Fatalf("platform = %q", er.Platform)
	}
}

func TestEnumAutoUnknownPlatformFailsClosed(t *testing.T) {
	s := &fakeSession{info: core.SessionInfo{ID: "s3", Kind: "cli"}}
	mgr := &fakeManager{sessions: map[string]core.Session{"s3": s}}
	c, _ := NewCapability(core.Deps{Sessions: mgr})

	res := do(t, c, "privesc_enum", `{"session_id":"s3","platform":"auto"}`)
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("expected invalid_input, got %q %+v", res.Status, res.Error)
	}
}

func TestEnumBadPlatformValue(t *testing.T) {
	res := do(t, linuxCap(), "privesc_enum", `{"session_id":"s1","platform":"solaris"}`)
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("expected invalid_input, got %+v", res.Error)
	}
}

func TestEnumSessionNotFound(t *testing.T) {
	res := do(t, linuxCap(), "privesc_enum", `{"session_id":"nope"}`)
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("expected not_found, got %q %+v", res.Status, res.Error)
	}
}

func TestEnumMissingSessionID(t *testing.T) {
	res := do(t, linuxCap(), "privesc_enum", `{}`)
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("expected invalid_input, got %+v", res.Error)
	}
}

func TestEnumInvalidJSON(t *testing.T) {
	res := do(t, linuxCap(), "privesc_enum", `{bad`)
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("expected invalid_input, got %+v", res.Error)
	}
}

func TestEnumMissingManagerToolMissing(t *testing.T) {
	c, _ := NewCapability(core.Deps{})
	res := do(t, c, "privesc_enum", `{"session_id":"s1"}`)
	if res.Status != core.StatusUnavailable || res.Error == nil || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("expected tool_missing, got %q %+v", res.Status, res.Error)
	}
}

func TestEnumExecErrorFailsClosed(t *testing.T) {
	// A session that accepts the interface but cannot run commands.
	s := &fakeSession{info: core.SessionInfo{ID: "s4", OS: "linux"}, execErr: errors.New("exec not supported")}
	mgr := &fakeManager{sessions: map[string]core.Session{"s4": s}}
	c, _ := NewCapability(core.Deps{Sessions: mgr})

	res := do(t, c, "privesc_enum", `{"session_id":"s4"}`)
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeUpstreamError {
		t.Fatalf("expected upstream_error, got %q %+v", res.Status, res.Error)
	}
}

func TestEnumPartialCommandFailure(t *testing.T) {
	// Noisy outputs: an unknown command returns empty stdout but no error, so it
	// must be recorded without aborting the run.
	s := &fakeSession{info: core.SessionInfo{ID: "s5", OS: "linux"}, outputs: map[string]string{}}
	mgr := &fakeManager{sessions: map[string]core.Session{"s5": s}}
	c, _ := NewCapability(core.Deps{Sessions: mgr})

	res := do(t, c, "privesc_enum", `{"session_id":"s5"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	var er enumResult
	_ = json.Unmarshal(res.Data, &er)
	if len(er.Commands) != len(linuxEnumCommands) {
		t.Fatalf("commands = %d", len(er.Commands))
	}
	if signalCount(er.Signals) != 0 {
		t.Fatalf("expected no signals from empty output, got %d", signalCount(er.Signals))
	}
}

// --- privesc_advise ------------------------------------------------------

func TestAdviseLinuxRankedCandidates(t *testing.T) {
	res := do(t, linuxCap(), "privesc_advise", `{"session_id":"s1"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	var data struct {
		Count      int             `json:"count"`
		Candidates []core.NextStep `json:"candidates"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.Count == 0 || data.Count != len(data.Candidates) {
		t.Fatalf("count = %d candidates = %d", data.Count, len(data.Candidates))
	}
	// Top candidate must be the full passwordless sudo rule.
	var top map[string]any
	_ = json.Unmarshal(data.Candidates[0].Params, &top)
	if top["candidate"] != "sudo-all-nopasswd" {
		t.Fatalf("top candidate = %v", top)
	}
	reasons := make([]string, 0, len(data.Candidates))
	for _, c := range data.Candidates {
		reasons = append(reasons, c.Reason)
		if c.Tool != toolSessionExec {
			t.Fatalf("candidate tool = %q", c.Tool)
		}
		if c.Risk != core.RiskHigh {
			t.Fatalf("candidate risk = %q", c.Risk)
		}
	}
	joined := strings.Join(reasons, " | ")
	for _, want := range []string{"CVE-2021-4034", "CVE-2022-0847", "GTFOBins"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("candidates missing %q: %s", want, joined)
		}
	}
	if len(res.Next) == 0 || len(res.Findings) == 0 {
		t.Fatalf("expected next and findings, got next=%d findings=%d", len(res.Next), len(res.Findings))
	}
	for _, f := range res.Findings {
		if f.Confirmed {
			t.Fatalf("advise findings must not be confirmed: %+v", f)
		}
	}
}

func TestAdviseWindowsRankedCandidates(t *testing.T) {
	res := do(t, windowsCap(), "privesc_advise", `{"session_id":"w1"}`)
	var data struct {
		Candidates []core.NextStep `json:"candidates"`
	}
	_ = json.Unmarshal(res.Data, &data)
	var joined []string
	for _, c := range data.Candidates {
		joined = append(joined, c.Reason)
	}
	all := strings.Join(joined, " | ")
	for _, want := range []string{"Potato", "MSI", "DefaultPassword", "未加引号"} {
		if !strings.Contains(all, want) {
			t.Fatalf("windows candidates missing %q: %s", want, all)
		}
	}
}

func TestAdviseFromEnumResultNoSession(t *testing.T) {
	// Passing enum_result must work with no session manager at all.
	er := enumResult{
		Platform: platformLinux,
		Signals: Signals{
			Platform:      platformLinux,
			Kernel:        "5.15.0",
			PolkitVersion: "0.105",
			SudoRules:     []SudoRule{{RunAs: "ALL", NoPassword: true, Command: "ALL"}},
		},
	}
	raw, _ := json.Marshal(er)
	c, _ := NewCapability(core.Deps{})
	res := do(t, c, "privesc_advise", `{"enum_result":`+string(raw)+`}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q", res.Status, res.Summary)
	}
	var data struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(res.Data, &data)
	if data.Count < 3 {
		t.Fatalf("count = %d, want >=3", data.Count)
	}
}

func TestAdviseRequiresInput(t *testing.T) {
	res := do(t, linuxCap(), "privesc_advise", `{}`)
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("expected invalid_input, got %+v", res.Error)
	}
}

func TestAdviseSessionNotFound(t *testing.T) {
	res := do(t, linuxCap(), "privesc_advise", `{"session_id":"nope"}`)
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("expected not_found, got %+v", res.Error)
	}
}

func TestAdviseMissingManager(t *testing.T) {
	c, _ := NewCapability(core.Deps{})
	res := do(t, c, "privesc_advise", `{"session_id":"s1"}`)
	if res.Status != core.StatusUnavailable || res.Error == nil || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("expected tool_missing, got %q %+v", res.Status, res.Error)
	}
}

func TestAdviseNoCandidates(t *testing.T) {
	s := &fakeSession{info: core.SessionInfo{ID: "s6", OS: "linux"}, outputs: map[string]string{}}
	mgr := &fakeManager{sessions: map[string]core.Session{"s6": s}}
	c, _ := NewCapability(core.Deps{Sessions: mgr})
	res := do(t, c, "privesc_advise", `{"session_id":"s6"}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	var data struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(res.Data, &data)
	if data.Count != 0 {
		t.Fatalf("count = %d, want 0", data.Count)
	}
	if len(res.Next) != 0 {
		t.Fatalf("next = %+v", res.Next)
	}
}

func TestAdviseDefaultsPlatformWhenSignalsBlank(t *testing.T) {
	// enum_result without an explicit platform defaults to linux and still
	// yields a proper envelope.
	er := enumResult{Signals: Signals{PasswdWritable: true}}
	raw, _ := json.Marshal(er)
	c, _ := NewCapability(core.Deps{})
	res := do(t, c, "privesc_advise", `{"enum_result":`+string(raw)+`}`)
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
}

// --- dispatch ------------------------------------------------------------

func TestUnknownTool(t *testing.T) {
	res := do(t, linuxCap(), "privesc_nope", `{}`)
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("expected not_found, got %q %+v", res.Status, res.Error)
	}
}

// --- advise internals ----------------------------------------------------

func TestAdviseWindowsPrivilegeMapping(t *testing.T) {
	steps := advise(Signals{
		Platform: platformWindows,
		WhoamiPrivileges: []Privilege{
			{Name: "SeImpersonatePrivilege", State: "Enabled"},
			{Name: "SeDebugPrivilege", State: "Disabled"},
			{Name: "SeBackupPrivilege", State: "Enabled"},
		},
	})
	// Disabled privileges must not produce candidates.
	var got []string
	for _, s := range steps {
		var p map[string]any
		_ = json.Unmarshal(s.Params, &p)
		if k, _ := p["candidate"].(string); k != "" {
			got = append(got, k)
		}
	}
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "SeImpersonatePrivilege") || !strings.Contains(joined, "SeBackupPrivilege") {
		t.Fatalf("mapped = %v", got)
	}
	if strings.Contains(joined, "SeDebugPrivilege") {
		t.Fatalf("disabled privilege leaked: %v", got)
	}
}

func TestAdviseLinuxConfigOnly(t *testing.T) {
	steps := advise(Signals{
		Platform:       platformLinux,
		PasswdWritable: true,
		WritablePaths:  []string{"/etc/cron.d/x"},
		SUIDBinaries:   []string{"/usr/bin/find", "/usr/bin/unknownbin"},
		Capabilities:   []FileCapability{{Path: "/usr/bin/python3", Caps: []string{"cap_setuid+ep"}}},
	})
	if len(steps) != 4 {
		t.Fatalf("steps = %d, want 4: %+v", len(steps), steps)
	}
	// passwd-writable (rank 100) must rank above the writable path (rank 60).
	var top map[string]any
	_ = json.Unmarshal(steps[0].Params, &top)
	if top["candidate"] != "writable-passwd" {
		t.Fatalf("top = %v", top)
	}
}

func TestAdviseDefaultsToLinux(t *testing.T) {
	// Platform blank falls through the default branch (linux).
	steps := advise(Signals{SudoRules: []SudoRule{{RunAs: "root", NoPassword: true, Command: "/usr/bin/find"}}})
	if len(steps) != 1 {
		t.Fatalf("steps = %+v", steps)
	}
}

func TestSignalCount(t *testing.T) {
	if signalCount(Signals{}) != 0 {
		t.Fatal("empty signals should count 0")
	}
	full := Signals{
		Platform: platformWindows, Kernel: "10.0", SudoRules: []SudoRule{{}},
		SUIDBinaries: []string{"/a"}, Capabilities: []FileCapability{{}},
		PolkitVersion: "0.105", WritablePaths: []string{"/b"}, PasswdWritable: true,
		WhoamiPrivileges: []Privilege{{}}, Groups: []string{"g"},
		Services: []ServiceConfig{{}}, Processes: []string{"p"},
		AlwaysInstallElevated: true, AutoLogon: AutoLogon{User: "a"},
	}
	if got := signalCount(full); got != 13 {
		t.Fatalf("signalCount = %d, want 13", got)
	}
}

func TestSignalsFindings(t *testing.T) {
	target := core.Target{Kind: core.TargetHost, Host: "h"}
	findings := signalsFindings(Signals{
		Platform:              platformWindows,
		PolkitVersion:         "0.105",
		AlwaysInstallElevated: true,
		AutoLogon:             AutoLogon{HasPassword: true},
		WhoamiPrivileges:      []Privilege{{Name: "SeImpersonatePrivilege", State: "Enabled"}},
		Services:              []ServiceConfig{{Name: "s", PathName: "C:\\a b\\s.exe", Unquoted: true}},
	}, target)
	if len(findings) != 5 {
		t.Fatalf("findings = %d, want 5: %+v", len(findings), findings)
	}
	// Version-based CVE finding is a candidate, not confirmed.
	for _, f := range findings {
		if strings.Contains(f.Fingerprint, "CVE-2021-4034") && f.Confirmed {
			t.Fatalf("CVE finding must not be confirmed: %+v", f)
		}
		if f.Source != kitName || f.Kind != "privesc" {
			t.Fatalf("finding shape = %+v", f)
		}
	}
}

func TestHostOrIDAndSessionTarget(t *testing.T) {
	if got := hostOrID(core.SessionInfo{ID: "id1"}); got != "id1" {
		t.Fatalf("hostOrID = %q", got)
	}
	if got := hostOrID(core.SessionInfo{ID: "id1", Host: "Host"}); got != "Host" {
		t.Fatalf("hostOrID = %q", got)
	}
	tg := sessionTarget(core.SessionInfo{ID: "id1", Host: "H"}, 3)
	if tg.Host != "h" || tg.ProjectID != 3 {
		t.Fatalf("target = %+v", tg)
	}
}

func TestCallToolNameDefault(t *testing.T) {
	if callToolName("") != "privesc_enum" || callToolName("x") != "x" {
		t.Fatal("callToolName mismatch")
	}
}
