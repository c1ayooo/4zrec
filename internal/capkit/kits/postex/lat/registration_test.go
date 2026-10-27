package lat

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// --- fakes ---------------------------------------------------------------

// fakeRunner is a canned core.ProcessRunner. It records the last ProcessSpec
// and returns scripted stdout/stderr/exit without spawning anything.
type fakeRunner struct {
	spec   core.ProcessSpec
	stdout string
	stderr string
	exit   int
	err    error
	calls  int
}

func (f *fakeRunner) Run(_ context.Context, spec core.ProcessSpec) (*core.ProcessResult, error) {
	f.calls++
	f.spec = spec
	if f.err != nil {
		return nil, f.err
	}
	return &core.ProcessResult{
		ExitCode: f.exit,
		Stdout:   []byte(f.stdout),
		Stderr:   []byte(f.stderr),
	}, nil
}

func mustCap(t *testing.T, r core.ProcessRunner) core.Capability {
	t.Helper()
	c, err := NewCapability(core.Deps{Processes: r})
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	return c
}

func callTool(t *testing.T, c core.Capability, tool string, payload map[string]any) core.Result {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	res, err := c.Call(context.Background(), core.Call{
		Tool:    tool,
		Input:   raw,
		Context: core.CallContext{ProjectID: 7, Actor: "tester"},
	})
	if err != nil {
		t.Fatalf("Call(%s): %v", tool, err)
	}
	return res
}

// --- manifest ------------------------------------------------------------

func TestManifestDeclaresExpectedTools(t *testing.T) {
	m := Manifest()
	if m.Name != kitName || m.Version != kitVersion || m.APIVersion != apiVersion {
		t.Fatalf("identity = %s/%s/%s, want %s/%s/%s",
			m.Name, m.Version, m.APIVersion, kitName, kitVersion, apiVersion)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest must validate: %v", err)
	}
	if !slices.Contains(m.Requires, "process") {
		t.Fatalf("Requires = %v, must include process", m.Requires)
	}

	want := []string{
		"lat_psexec", "lat_wmiexec", "lat_smbexec", "lat_winrm",
		"lat_pass_the_hash", "lat_kerberoast", "lat_asrep_roast", "lat_dcsync",
	}
	got := make([]string, 0, len(m.Tools))
	for _, ts := range m.Tools {
		got = append(got, ts.Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("tools = %v, want %v", got, want)
	}
}

func TestEveryToolSpecHasSchemasRiskAndTargets(t *testing.T) {
	m := Manifest()
	for _, ts := range m.Tools {
		if strings.TrimSpace(ts.Description) == "" {
			t.Errorf("%s: empty description", ts.Name)
		}
		if !ts.Risk.Valid() {
			t.Errorf("%s: invalid risk %q", ts.Name, ts.Risk)
		}
		if ts.RateLimit.PerSecond <= 0 || ts.RateLimit.Burst <= 0 || ts.RateLimit.Concurrency <= 0 {
			t.Errorf("%s: incomplete rate limit %+v", ts.Name, ts.RateLimit)
		}
		for label, raw := range map[string]json.RawMessage{
			"input_schema":  ts.InputSchema,
			"output_schema": ts.OutputSchema,
		} {
			if len(raw) == 0 {
				t.Errorf("%s: empty %s", ts.Name, label)
				continue
			}
			var v map[string]any
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Errorf("%s: %s invalid JSON: %v", ts.Name, label, err)
				continue
			}
			if v["type"] != "object" {
				t.Errorf("%s: %s type = %v, want object", ts.Name, label, v["type"])
			}
		}
		if ts.ExtractTargets == nil {
			t.Errorf("%s: missing ExtractTargets (scope cannot be enforced)", ts.Name)
			continue
		}
		if _, err := ts.ExtractTargets(json.RawMessage(`{"target":"10.0.0.5"}`)); err != nil {
			t.Errorf("%s: ExtractTargets failed on valid target: %v", ts.Name, err)
		}
	}
}

func TestManifestMatchesCapabilityManifest(t *testing.T) {
	c := mustCap(t, &fakeRunner{})
	if len(c.Manifest().Tools) != len(Manifest().Tools) {
		t.Fatal("Capability.Manifest must return the package Manifest")
	}
}

// --- dispatch / argv -----------------------------------------------------

func TestEachToolDispatchesToItsBinary(t *testing.T) {
	cases := []struct {
		tool    string
		payload map[string]any
		wantBin string
		wantArg string
	}{
		{"lat_psexec", map[string]any{"target": "10.0.0.5", "user": "alice", "secret": "Passw0rd", "command": "whoami", "port": 445}, "psexec.py", "-target-ip"},
		{"lat_wmiexec", map[string]any{"target": "10.0.0.6", "user": "alice", "secret": "Passw0rd", "command": "whoami"}, "wmiexec.py", "-target-ip"},
		{"lat_smbexec", map[string]any{"target": "10.0.0.7", "user": "alice", "secret": "Passw0rd", "command": "whoami"}, "smbexec.py", "-target-ip"},
		{"lat_winrm", map[string]any{"target": "win01.corp", "user": "alice", "secret": "Passw0rd", "command": "whoami"}, "nxc", "winrm"},
		{"lat_pass_the_hash", map[string]any{"target": "10.0.0.8", "user": "alice", "hash": "31d6cfe0d16ae931b73c59d7e0c089c0", "command": "whoami"}, "psexec.py", "-hashes"},
		{"lat_kerberoast", map[string]any{"target": "dc01.corp", "domain": "CORP", "user": "alice", "secret": "Passw0rd"}, "GetUserSPNs.py", "-request"},
		{"lat_asrep_roast", map[string]any{"target": "dc01.corp", "domain": "CORP", "user": "alice"}, "GetNPUsers.py", "-no-pass"},
		{"lat_dcsync", map[string]any{"target": "dc01.corp", "domain": "CORP", "user": "alice", "secret": "Passw0rd"}, "secretsdump.py", "-just-dc"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			fr := &fakeRunner{stdout: "done\n"}
			c := mustCap(t, fr)
			res := callTool(t, c, tc.tool, tc.payload)
			if res.Status != core.StatusSuccess {
				t.Fatalf("status = %q, error = %+v", res.Status, res.Error)
			}
			if fr.calls != 1 {
				t.Fatalf("runner calls = %d, want 1", fr.calls)
			}
			if fr.spec.Path != tc.wantBin {
				t.Fatalf("path = %q, want %q (args=%v)", fr.spec.Path, tc.wantBin, fr.spec.Args)
			}
			if !slices.Contains(fr.spec.Args, tc.wantArg) {
				t.Fatalf("args %v missing %q", fr.spec.Args, tc.wantArg)
			}
			if fr.spec.Timeout <= 0 {
				t.Fatal("timeout must be set")
			}
			if fr.spec.RateLimit.PerSecond <= 0 {
				t.Fatal("rate limit must be set")
			}
			var data map[string]any
			if err := json.Unmarshal(res.Data, &data); err != nil {
				t.Fatalf("data is not JSON: %v", err)
			}
			for _, key := range []string{"command", "exit_code", "stdout", "stderr"} {
				if _, ok := data[key]; !ok {
					t.Fatalf("data missing %q: %v", key, data)
				}
			}
		})
	}
}

func TestPsexecArgvShape(t *testing.T) {
	fr := &fakeRunner{}
	c := mustCap(t, fr)
	_ = callTool(t, c, "lat_psexec", map[string]any{
		"target": "10.0.0.5", "domain": "CORP", "user": "alice",
		"secret": "Passw0rd", "command": "whoami", "port": 445,
	})
	args := fr.spec.Args
	if !slices.Contains(args, "-port") {
		t.Fatalf("expected -port in %v", args)
	}
	if !slices.Contains(args, "CORP/alice:Passw0rd@10.0.0.5") {
		t.Fatalf("expected credential positional in %v", args)
	}
	if args[len(args)-1] != "whoami" {
		t.Fatalf("command must be last: %v", args)
	}
}

func TestWinRMHashAndPortArgv(t *testing.T) {
	fr := &fakeRunner{}
	c := mustCap(t, fr)
	_ = callTool(t, c, "lat_winrm", map[string]any{
		"target": "win01.corp", "user": "alice",
		"hash": "31d6cfe0d16ae931b73c59d7e0c089c0", "port": 5986, "command": "whoami",
	})
	args := fr.spec.Args
	if !slices.Contains(args, "-H") {
		t.Fatalf("expected -H in %v", args)
	}
	if slices.Contains(args, ":31d6cfe0d16ae931b73c59d7e0c089c0") {
		t.Fatalf("NetExec -H wants a bare NTLM hash: %v", args)
	}
	if !slices.Contains(args, "--port") || !slices.Contains(args, "5986") {
		t.Fatalf("expected --port 5986 in %v", args)
	}
	if !slices.Contains(args, "-x") {
		t.Fatalf("expected -x in %v", args)
	}
}

func TestPassTheHashUsesHashesFlag(t *testing.T) {
	fr := &fakeRunner{}
	c := mustCap(t, fr)
	_ = callTool(t, c, "lat_pass_the_hash", map[string]any{
		"target": "10.0.0.9", "user": "alice",
		"hash": "31d6cfe0d16ae931b73c59d7e0c089c0", "command": "whoami",
	})
	if !slices.Contains(fr.spec.Args, "-hashes") {
		t.Fatalf("expected -hashes in %v", fr.spec.Args)
	}
	if !slices.Contains(fr.spec.Args, ":31d6cfe0d16ae931b73c59d7e0c089c0") {
		t.Fatalf("impacket -hashes wants :NTHASH form: %v", fr.spec.Args)
	}
}

// --- roast findings ------------------------------------------------------

func TestKerberoastPopulatesFindingsAndNext(t *testing.T) {
	hash := "$krb5tgs$23$*svc_sql$CORP$MSSQLSvc/sql01.corp:1433*$deadbeefdeadbeefdeadbeef"
	fr := &fakeRunner{stdout: "svc_sql:" + hash + "\nsvc_sql:" + hash + "\n"}
	c := mustCap(t, fr)
	res := callTool(t, c, "lat_kerberoast", map[string]any{
		"target": "dc01.corp", "domain": "CORP", "user": "alice", "secret": "Passw0rd",
	})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (dedup)", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Kind != "krb5tgs" || !f.Confirmed || f.Payload != hash || f.Source != "latkit" {
		t.Fatalf("finding = %+v", f)
	}
	if len(res.Next) == 0 || res.Next[0].Tool != "john" {
		t.Fatalf("next = %+v, want john crack suggestion", res.Next)
	}
}

func TestDCSyncPopulatesNTLMFindingAndHashReplayNext(t *testing.T) {
	fr := &fakeRunner{stdout: "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"}
	c := mustCap(t, fr)
	res := callTool(t, c, "lat_dcsync", map[string]any{
		"target": "dc01.corp", "domain": "CORP", "user": "alice", "secret": "Passw0rd",
	})
	if len(res.Findings) != 1 || res.Findings[0].Kind != "ntlm" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if res.Findings[0].Payload != "31d6cfe0d16ae931b73c59d7e0c089c0" {
		t.Fatalf("payload = %q", res.Findings[0].Payload)
	}
	if len(res.Next) == 0 || res.Next[0].Tool != "lat_pass_the_hash" {
		t.Fatalf("next = %+v, want pass-the-hash suggestion", res.Next)
	}
}

func TestAsrepRoastFinding(t *testing.T) {
	fr := &fakeRunner{stdout: "bob:$krb5asrep$23$bob@CORP:0123456789abcdef\n"}
	c := mustCap(t, fr)
	res := callTool(t, c, "lat_asrep_roast", map[string]any{
		"target": "dc01.corp", "domain": "CORP", "user": "bob",
	})
	if len(res.Findings) != 1 || res.Findings[0].Kind != "krb5as" {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestRoastWithoutHashesReportsCompletion(t *testing.T) {
	fr := &fakeRunner{stdout: "no hashes here\n"}
	c := mustCap(t, fr)
	res := callTool(t, c, "lat_kerberoast", map[string]any{
		"target": "dc01.corp", "domain": "CORP", "user": "alice", "secret": "Passw0rd",
	})
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", res.Findings)
	}
	if res.Status != core.StatusSuccess || !strings.Contains(res.Summary, "未解析到") {
		t.Fatalf("status/summary = %q/%q", res.Status, res.Summary)
	}
}

func TestRoastTruncatesLargeOutput(t *testing.T) {
	big := strings.Repeat("a", 8<<10)
	fr := &fakeRunner{stdout: big + "\nbob:$krb5asrep$23$bob@CORP:0123456789abcdef\n"}
	c := mustCap(t, fr)
	res := callTool(t, c, "lat_asrep_roast", map[string]any{
		"target": "dc01.corp", "domain": "CORP", "user": "bob",
	})
	var data map[string]any
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	out, _ := data["stdout"].(string)
	if len(out) > 4<<10 {
		t.Fatalf("stdout not pruned: %d bytes", len(out))
	}
}

// --- error paths ---------------------------------------------------------

func TestMissingRunnerIsUnavailable(t *testing.T) {
	c := mustCap(t, nil)
	res := callTool(t, c, "lat_psexec", map[string]any{
		"target": "10.0.0.5", "user": "alice", "secret": "Passw0rd", "command": "whoami",
	})
	if res.Status != core.StatusUnavailable {
		t.Fatalf("status = %q, want unavailable", res.Status)
	}
	if res.Error == nil || res.Error.Code != core.CodeUnavailable {
		t.Fatalf("error = %+v, want unavailable", res.Error)
	}
}

func TestUnknownToolIsNotFound(t *testing.T) {
	c := mustCap(t, &fakeRunner{})
	res := callTool(t, c, "lat_nope", map[string]any{"target": "10.0.0.5"})
	if res.Status == core.StatusSuccess || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("res = %+v", res)
	}
}

func TestInvalidInputIsRejected(t *testing.T) {
	c := mustCap(t, &fakeRunner{})
	// missing target (and user/secret)
	res := callTool(t, c, "lat_psexec", map[string]any{"command": "whoami"})
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("res = %+v", res)
	}
	// malformed hash
	res = callTool(t, c, "lat_pass_the_hash", map[string]any{
		"target": "10.0.0.5", "user": "alice", "hash": "not-a-hash",
	})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("res = %+v", res)
	}
	// malformed JSON payload
	raw := core.Call{Tool: "lat_psexec", Input: json.RawMessage(`{"target":`)}
	out, err := c.Call(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Error == nil || out.Error.Code != core.CodeInvalidInput {
		t.Fatalf("malformed JSON res = %+v", out)
	}
}

func TestCommandWithShellMetacharsIsRejected(t *testing.T) {
	c := mustCap(t, &fakeRunner{})
	res := callTool(t, c, "lat_psexec", map[string]any{
		"target": "10.0.0.5", "user": "alice", "secret": "Passw0rd",
		"command": "whoami; rm -rf /",
	})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("metachar command must be rejected: %+v", res)
	}
}

func TestRunnerErrorIsUpstreamError(t *testing.T) {
	fr := &fakeRunner{err: errors.New("boom")}
	c := mustCap(t, fr)
	res := callTool(t, c, "lat_wmiexec", map[string]any{
		"target": "10.0.0.5", "user": "alice", "secret": "Passw0rd", "command": "whoami",
	})
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeUpstreamError {
		t.Fatalf("res = %+v", res)
	}
}

// --- pure helpers --------------------------------------------------------

func TestBuildCommandDispatch(t *testing.T) {
	raw := json.RawMessage(`{"target":"10.0.0.5","user":"alice","secret":"Passw0rd","command":"whoami"}`)
	path, args, err := BuildCommand("lat_psexec", raw)
	if err != nil {
		t.Fatal(err)
	}
	if path != "psexec.py" || len(args) == 0 {
		t.Fatalf("path/args = %q/%v", path, args)
	}
	if _, _, err := BuildCommand("nope", raw); err == nil {
		t.Fatal("unknown tool must error")
	}
	if _, _, err := BuildCommand("lat_psexec", json.RawMessage(`{`)); err == nil {
		t.Fatal("malformed JSON must error")
	}
}

func TestOutputSchemasAreValidJSONObjects(t *testing.T) {
	for _, ts := range Manifest().Tools {
		var v map[string]any
		if err := json.Unmarshal(ts.OutputSchema, &v); err != nil {
			t.Fatalf("%s: %v", ts.Name, err)
		}
		if v["type"] != "object" {
			t.Fatalf("%s: output_schema type = %v", ts.Name, v["type"])
		}
	}
}

func TestCommonRequiredFragment(t *testing.T) {
	if got := commonRequired(); got != `"required":[]` {
		t.Fatalf("commonRequired() = %q", got)
	}
	if got := commonRequired("a", "b"); got != `"required":["a","b"]` {
		t.Fatalf("commonRequired(a,b) = %q", got)
	}
	var v map[string]any
	if err := json.Unmarshal(inputSchema("command"), &v); err != nil {
		t.Fatalf("inputSchema invalid JSON: %v", err)
	}
	req, _ := v["required"].([]any)
	if len(req) != 1 || req[0] != "command" {
		t.Fatalf("required = %v", v["required"])
	}
	props, _ := v["properties"].(map[string]any)
	for _, k := range []string{"target", "domain", "user", "secret", "hash", "command", "port"} {
		if _, ok := props[k]; !ok {
			t.Fatalf("common properties missing %q: %v", k, props)
		}
	}
}

func TestHashersAndValidation(t *testing.T) {
	if normalizeHash("abcd") != ":abcd" {
		t.Fatal("bare hash must gain LM prefix")
	}
	if normalizeHash("aaaa:bbbb") != "aaaa:bbbb" {
		t.Fatal("LM:NT pair must be preserved")
	}
	if !isIP("10.0.0.1") || isIP("host.corp") {
		t.Fatal("isIP mismatch")
	}
	if got := targetIPArg(Input{Target: "10.0.0.1"}); len(got) != 2 {
		t.Fatalf("targetIPArg ip = %v", got)
	}
	if got := targetIPArg(Input{Target: "host.corp"}); got != nil {
		t.Fatalf("targetIPArg host = %v, want nil", got)
	}
	if got := portArg(Input{Port: 445}, true); len(got) != 2 || got[1] != "445" {
		t.Fatalf("portArg = %v", got)
	}
	if got := portArg(Input{Port: 0}, true); got != nil {
		t.Fatalf("portArg 0 = %v", got)
	}
	if got := portArg(Input{Port: 445}, false); got != nil {
		t.Fatalf("portArg disallowed = %v", got)
	}
	if err := validateHost("bad host"); err == nil {
		t.Fatal("host with space must fail")
	}
	if err := validateHost("-flag"); err == nil {
		t.Fatal("leading dash must fail")
	}
	if err := validateDomain("CORP;x"); err == nil {
		t.Fatal("bad domain must fail")
	}
	if err := validateUser("a/b"); err == nil {
		t.Fatal("bad user must fail")
	}
	if err := validateSecret("a b"); err == nil {
		t.Fatal("secret with space must fail")
	}
	if err := validateSecret("a:b"); err == nil {
		t.Fatal("secret with colon must fail")
	}
	if err := validateCommand("ok --flag"); err != nil {
		t.Fatalf("benign command rejected: %v", err)
	}
	if err := validateCommand("x;y"); err == nil {
		t.Fatal("command metachar must fail")
	}
	if _, err := parseInput(json.RawMessage(`{`)); err == nil {
		t.Fatal("bad JSON must fail parseInput")
	}
	if in, err := parseInput(nil); err != nil || in.Target != "" {
		t.Fatalf("nil input = %+v/%v", in, err)
	}
}

func TestAuthArgsBranches(t *testing.T) {
	if _, _, err := authArgs(Input{Target: "h", User: "u", Hash: "abcd"}, true); err == nil {
		t.Fatal("bad hash must fail")
	}
	if _, _, err := authArgs(Input{Target: "h", User: "u"}, false); err == nil {
		t.Fatal("missing secret/hash must fail")
	}
	if _, _, err := authArgs(Input{Target: "h"}, false); err == nil {
		t.Fatal("missing user must fail")
	}
	if _, _, err := authArgs(Input{User: "u", Secret: "s"}, false); err == nil {
		t.Fatal("missing target must fail")
	}
	who, extra, err := authArgs(Input{Target: "h", Domain: "D", User: "u", Secret: "s"}, false)
	if err != nil || who != "D/u:s@h" || extra != nil {
		t.Fatalf("who/extra = %q/%v (%v)", who, extra, err)
	}
}

func TestParseHashesFormats(t *testing.T) {
	out := []byte(strings.Join([]string{
		"svc_sql:$krb5tgs$23$*svc_sql$CORP$spn*$abc",
		"bob:$krb5asrep$23$bob@CORP:deadbeef",
		"Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
		"bare $krb5pa$23$user$hashdata",
		"some random log line",
		"",
	}, "\n"))
	got := ParseHashes("lat_dcsync", out)
	if len(got) != 4 {
		t.Fatalf("parsed %d hashes, want 4: %+v", len(got), got)
	}
	kinds := map[string]bool{}
	for _, h := range got {
		kinds[h.Type] = true
		if h.Source != "lat_dcsync" {
			t.Fatalf("source = %q", h.Source)
		}
	}
	for _, k := range []string{"krb5tgs", "krb5as", "ntlm", "krb5pa"} {
		if !kinds[k] {
			t.Fatalf("missing kind %q in %+v", k, got)
		}
	}
	if res := ParseHashes("x", []byte("nothing here")); len(res) != 0 {
		t.Fatalf("junk parsed as hashes: %+v", res)
	}
}

func TestTargetFromInput(t *testing.T) {
	ts, err := targetFromInput(json.RawMessage(`{"target":"10.0.0.5"}`))
	if err != nil || len(ts) != 1 || ts[0].Kind != core.TargetIP {
		t.Fatalf("targets = %+v (%v)", ts, err)
	}
	if _, err := targetFromInput(json.RawMessage(`{}`)); err == nil {
		t.Fatal("empty target must fail")
	}
	if _, err := targetFromInput(json.RawMessage(`not json`)); err == nil {
		t.Fatal("bad JSON must fail")
	}
}

func TestPrune(t *testing.T) {
	if got := prune("short"); got != "short" {
		t.Fatalf("prune short = %q", got)
	}
	long := strings.Repeat("x", 10<<10)
	if got := prune(long); len(got) != 4<<10 {
		t.Fatalf("prune long = %d bytes", len(got))
	}
}
