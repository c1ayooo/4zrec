package internalnet

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

func linuxSurveySession(id string) *scriptedSession {
	return &scriptedSession{
		info: core.SessionInfo{ID: id, Kind: "ssh", Host: "10.0.0.10", OS: "linux"},
		rules: []rule{
			{match: "whoami", stdout: "root\n"},
			{match: "hostname", stdout: "web01\n", evidenceID: "ev_host"},
			{match: "uname -a", stdout: "Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"},
			{match: "cat /etc/os-release", stdout: sampleOSRelease},
			{match: "ip addr", stdout: sampleIPAddr},
			{match: "ip route", stdout: sampleIPRoute},
			{match: "cat /etc/passwd", stdout: samplePasswd},
			{match: "who", stdout: sampleWho},
			{match: "last -n 20", stdout: sampleLast},
			{match: "arp -a", stdout: sampleARP},
			{match: "ss -tunlp", stdout: sampleSS},
		},
	}
}

func windowsSurveySession(id string) *scriptedSession {
	return &scriptedSession{
		info: core.SessionInfo{ID: id, Kind: "winrm", Host: "10.0.0.20", OS: "windows"},
		rules: []rule{
			{match: "whoami", stdout: "corp\\admin\n"},
			{match: "hostname", stdout: "WIN-DC01\n"},
			{match: "systeminfo", stdout: sampleSysteminfo},
			{match: "ipconfig /all", stdout: sampleIpconfig},
			{match: "route print", stdout: sampleRoutePrint},
			{match: "net localgroup administrators", stdout: sampleNetLocalGroupAdmins},
			{match: "net user", stdout: sampleNetUser},
			{match: "arp -a", stdout: sampleARPWindows},
			{match: "netstat -ano", stdout: sampleNetstat},
			{match: "tasklist", stdout: sampleTasklist},
		},
	}
}

func mustJSONInput(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decode[T any](t *testing.T, res core.Result) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("decode data: %v (%s)", err, res.Data)
	}
	return out
}

// ---- manifest / dispatch ----

func TestManifestContract(t *testing.T) {
	m := Manifest()
	if m.Name != "internalnetkit" || m.Version != "0.1.0" || m.APIVersion != "v1" {
		t.Fatalf("manifest identity = %+v", m)
	}
	wantReq := []string{"scope", "limiter", "audit", "sessions"}
	if strings.Join(m.Requires, ",") != strings.Join(wantReq, ",") {
		t.Fatalf("requires = %v", m.Requires)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest invalid: %v", err)
	}
	if len(m.Tools) != 5 {
		t.Fatalf("tools = %d, want 5", len(m.Tools))
	}
	names := map[string]bool{}
	for _, tool := range m.Tools {
		if len(tool.InputSchema) == 0 || len(tool.OutputSchema) == 0 {
			t.Fatalf("%s missing schema", tool.Name)
		}
		var v any
		if err := json.Unmarshal(tool.InputSchema, &v); err != nil {
			t.Fatalf("%s input schema invalid JSON: %v", tool.Name, err)
		}
		if err := json.Unmarshal(tool.OutputSchema, &v); err != nil {
			t.Fatalf("%s output schema invalid JSON: %v", tool.Name, err)
		}
		if !tool.Risk.Valid() {
			t.Fatalf("%s invalid risk %q", tool.Name, tool.Risk)
		}
		names[tool.Name] = true
	}
	for _, n := range []string{"inet_local_info", "inet_host_discovery", "inet_portscan", "inet_domain_info", "inet_smb_shares"} {
		if !names[n] {
			t.Fatalf("missing tool %s", n)
		}
	}
}

func TestExtractTargets(t *testing.T) {
	m := Manifest()
	specs := map[string]core.ToolSpec{}
	for _, s := range m.Tools {
		specs[s.Name] = s
	}
	// host_discovery requires cidr.
	tg, err := specs["inet_host_discovery"].ExtractTargets(json.RawMessage(`{"cidr":"10.0.0.0/24"}`))
	if err != nil || len(tg) != 1 || tg[0].CIDR != "10.0.0.0/24" {
		t.Fatalf("discovery targets = %v err=%v", tg, err)
	}
	if _, err := specs["inet_host_discovery"].ExtractTargets(json.RawMessage(`{}`)); err == nil {
		t.Fatal("missing cidr should error")
	}
	// portscan accepts hosts and cidr.
	tg, err = specs["inet_portscan"].ExtractTargets(json.RawMessage(`{"hosts":["10.0.0.5"],"cidr":"10.0.0.0/30"}`))
	if err != nil || len(tg) != 2 {
		t.Fatalf("portscan targets = %v err=%v", tg, err)
	}
	// smb with no host is a valid local enumeration with no remote target.
	tg, err = specs["inet_smb_shares"].ExtractTargets(json.RawMessage(`{}`))
	if err != nil || tg != nil {
		t.Fatalf("smb local targets = %v err=%v", tg, err)
	}
	tg, _ = specs["inet_smb_shares"].ExtractTargets(json.RawMessage(`{"host":"10.0.0.9"}`))
	if len(tg) != 1 {
		t.Fatalf("smb targets = %v", tg)
	}
}

func TestUnknownTool(t *testing.T) {
	c := capWith(newFakeManager())
	res, err := c.Call(context.Background(), core.Call{Tool: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("unknown tool result = %+v", res.Error)
	}
}

func TestMissingManagerFailsClosed(t *testing.T) {
	c := capWith(nil)
	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_local_info", Input: json.RawMessage(`{"session_id":"s1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusUnavailable || res.Error == nil || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("missing manager result = %q %+v", res.Status, res.Error)
	}
}

func TestSessionNotFound(t *testing.T) {
	mgr := newFakeManager()
	c := capWith(mgr)
	tools := map[string]json.RawMessage{
		"inet_local_info":     json.RawMessage(`{"session_id":"nope"}`),
		"inet_host_discovery": json.RawMessage(`{"session_id":"nope","cidr":"10.0.0.0/30"}`),
		"inet_portscan":       json.RawMessage(`{"session_id":"nope","hosts":["10.0.0.5"],"ports":"22"}`),
		"inet_domain_info":    json.RawMessage(`{"session_id":"nope"}`),
		"inet_smb_shares":     json.RawMessage(`{"session_id":"nope"}`),
	}
	for tool, in := range tools {
		res, err := c.Call(context.Background(), core.Call{Tool: tool, Input: in})
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeNotFound {
			t.Fatalf("%s: status=%q err=%+v", tool, res.Status, res.Error)
		}
	}
}

func TestInvalidInput(t *testing.T) {
	mgr := newFakeManager()
	mgr.add(linuxSurveySession("s1"))
	c := capWith(mgr)
	ctx := context.Background()

	// empty session_id is invalid_input, not not_found.
	res, _ := c.Call(ctx, core.Call{Tool: "inet_local_info", Input: json.RawMessage(`{}`)})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("empty session = %+v", res.Error)
	}
	// malformed JSON.
	res, _ = c.Call(ctx, core.Call{Tool: "inet_local_info", Input: json.RawMessage(`{`)})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("bad json = %+v", res.Error)
	}
	// bad cidr.
	res, _ = c.Call(ctx, core.Call{Tool: "inet_host_discovery", Input: json.RawMessage(`{"session_id":"s1","cidr":"nope"}`)})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("bad cidr = %+v", res.Error)
	}
	// invalid ports.
	res, _ = c.Call(ctx, core.Call{Tool: "inet_portscan", Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5"],"ports":"abc"}`)})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("bad ports = %+v", res.Error)
	}
}

// ---- inet_local_info ----

func TestLocalInfoLinux(t *testing.T) {
	mgr := newFakeManager()
	s := linuxSurveySession("s1")
	mgr.add(s)
	c := capWith(mgr)

	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_local_info", Input: json.RawMessage(`{"session_id":"s1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q errors", res.Status, res.Summary)
	}
	info := decode[LocalInfo](t, res)
	if info.OS != "linux" || info.Hostname != "web01" || info.User != "root" {
		t.Fatalf("info = %+v", info)
	}
	if info.OSRelease != "Ubuntu 22.04.3 LTS" {
		t.Fatalf("os_release = %q", info.OSRelease)
	}
	if len(info.Interfaces) != 2 || len(info.Routes) != 3 {
		t.Fatalf("interfaces/routes = %d/%d", len(info.Interfaces), len(info.Routes))
	}
	if strings.Join(info.Users, ",") != "root,daemon,john" {
		t.Fatalf("users = %v", info.Users)
	}
	if len(info.Logins) < 4 {
		t.Fatalf("logins = %v", info.Logins)
	}
	if len(info.Listeners) != 4 || len(info.ARP) != 3 {
		t.Fatalf("listeners/arp = %d/%d", len(info.Listeners), len(info.ARP))
	}
	if len(res.Evidence) != 1 || res.Evidence[0].ID != "ev_host" {
		t.Fatalf("evidence = %+v", res.Evidence)
	}
	// Next suggests discovery on the discovered /24.
	found := false
	for _, n := range res.Next {
		if n.Tool == "inet_host_discovery" && strings.Contains(string(n.Params), "10.0.0.0/24") {
			found = true
		}
	}
	if !found {
		t.Fatalf("next = %+v", res.Next)
	}
}

func TestLocalInfoWindows(t *testing.T) {
	mgr := newFakeManager()
	mgr.add(windowsSurveySession("w1"))
	c := capWith(mgr)

	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_local_info", Input: json.RawMessage(`{"session_id":"w1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	info := decode[LocalInfo](t, res)
	if info.OS != "windows" || info.Hostname != "WIN-DC01" {
		t.Fatalf("info = %+v", info)
	}
	if len(info.Interfaces) != 1 || info.Interfaces[0].Name != "Ethernet0" {
		t.Fatalf("interfaces = %+v", info.Interfaces)
	}
	if strings.Join(info.Admins, ",") != "Administrator" {
		t.Fatalf("admins = %v", info.Admins)
	}
	if len(info.Users) != 5 || len(info.Listeners) != 4 || len(info.Processes) != 4 || len(info.ARP) != 2 {
		t.Fatalf("counts = users:%d listeners:%d procs:%d arp:%d",
			len(info.Users), len(info.Listeners), len(info.Processes), len(info.ARP))
	}
}

func TestLocalInfoPartialAndDetectOS(t *testing.T) {
	mgr := newFakeManager()
	s := linuxSurveySession("s1")
	s.info.OS = "" // force the uname -s probe
	// Fail one command so the result is partial.
	s.rules = append([]rule{{match: "ip route", err: errors.New("boom")}}, s.rules...)
	s.rules = append([]rule{{match: "uname -s", stdout: "Linux\n"}}, s.rules...)
	mgr.add(s)
	c := capWith(mgr)

	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_local_info", Input: json.RawMessage(`{"session_id":"s1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusPartial {
		t.Fatalf("status = %q, want partial", res.Status)
	}
	info := decode[LocalInfo](t, res)
	if info.OS != "linux" {
		t.Fatalf("detected os = %q", info.OS)
	}
	if len(info.Errors) != 1 {
		t.Fatalf("errors = %v", info.Errors)
	}
}

// ---- inet_host_discovery ----

func discoveryManager(id string) *fakeManager {
	mgr := newFakeManager()
	mgr.add(&scriptedSession{
		info: core.SessionInfo{ID: id, OS: "linux"},
		rules: []rule{
			{match: "ping -c 1", stdout: "UP 10.0.0.2\nUP 10.0.0.3\n", evidenceID: "ev_ping"},
			{match: "arp -a", stdout: "? (10.0.0.2) at 00:11:22:33:44:55 [ether] on eth0\n" +
				"? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0\n"},
		},
	})
	return mgr
}

func TestHostDiscoveryPing(t *testing.T) {
	c := capWith(discoveryManager("s1"))
	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_host_discovery", Input: json.RawMessage(`{"session_id":"s1","cidr":"10.0.0.0/29"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	d := decode[HostDiscovery](t, res)
	if d.Probed != 6 || d.Truncated {
		t.Fatalf("probed/truncated = %d/%v", d.Probed, d.Truncated)
	}
	if len(d.Hosts) != 2 {
		t.Fatalf("hosts = %+v", d.Hosts)
	}
	// ARP enrichment adds the MAC for 10.0.0.2; 192.168.1.1 is outside the /29.
	if d.Hosts[0].Host != "10.0.0.2" || d.Hosts[0].MAC != "00:11:22:33:44:55" {
		t.Fatalf("host0 = %+v", d.Hosts[0])
	}
	if len(res.Evidence) == 0 {
		t.Fatal("expected evidence refs")
	}
}

func TestHostDiscoveryBounded(t *testing.T) {
	c := capWith(discoveryManager("s1"))
	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_host_discovery", Input: json.RawMessage(`{"session_id":"s1","cidr":"10.0.0.0/24","max_hosts":5}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	d := decode[HostDiscovery](t, res)
	if d.Probed != 5 || !d.Truncated {
		t.Fatalf("probed/truncated = %d/%v, want 5/true", d.Probed, d.Truncated)
	}
	if !res.Truncated {
		t.Fatal("envelope Truncated should be set")
	}
}

func TestHostDiscoveryARPMethod(t *testing.T) {
	c := capWith(discoveryManager("s1"))
	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_host_discovery", Input: json.RawMessage(`{"session_id":"s1","cidr":"10.0.0.0/29","method":"arp"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	d := decode[HostDiscovery](t, res)
	if d.Method != "arp" || len(d.Hosts) != 1 || d.Hosts[0].Host != "10.0.0.2" || d.Hosts[0].MAC == "" {
		t.Fatalf("arp hosts = %+v", d.Hosts)
	}
}

// ---- inet_portscan ----

func scanManager(id string) *fakeManager {
	mgr := newFakeManager()
	mgr.add(&scriptedSession{
		info: core.SessionInfo{ID: id, OS: "linux"},
		rules: []rule{
			{match: "10.0.0.5", stdout: "OPEN 10.0.0.5 22\nOPEN 10.0.0.5 445\n", evidenceID: "ev_scan"},
			{match: "10.0.0.6", stdout: "OPEN 10.0.0.6 3389\n"},
			{match: "10.0.0.7", stdout: "OPEN 10.0.0.7 80\n"},
		},
	})
	return mgr
}

func TestPortScan(t *testing.T) {
	c := capWith(scanManager("s1"))
	res, err := c.Call(context.Background(), core.Call{
		Tool:  "inet_portscan",
		Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5","10.0.0.6"],"ports":"22,139,445,3389"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	d := decode[PortScan](t, res)
	if d.ProbedHosts != 2 || d.ProbedPorts != 4 || len(d.Open) != 3 {
		t.Fatalf("scan = %+v", d)
	}
	if d.Open[0].Host != "10.0.0.5" || d.Open[0].Port != 22 || d.Open[0].Service != "ssh" {
		t.Fatalf("open0 = %+v", d.Open[0])
	}
	if d.Open[2].Service != "rdp" {
		t.Fatalf("open2 = %+v", d.Open[2])
	}
}

func TestPortScanBoundedPorts(t *testing.T) {
	c := capWith(scanManager("s1"))
	res, err := c.Call(context.Background(), core.Call{
		Tool:  "inet_portscan",
		Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5"],"ports":"1-5000","max_ports":10}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	d := decode[PortScan](t, res)
	if d.ProbedPorts != 10 || !d.Truncated {
		t.Fatalf("bounded ports = %d trunc=%v", d.ProbedPorts, d.Truncated)
	}
}

func TestPortScanBoundedHosts(t *testing.T) {
	c := capWith(scanManager("s1"))
	res, err := c.Call(context.Background(), core.Call{
		Tool:  "inet_portscan",
		Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5","10.0.0.6","10.0.0.7"],"ports":"22","max_hosts":2}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	d := decode[PortScan](t, res)
	if d.ProbedHosts != 2 || !d.Truncated {
		t.Fatalf("bounded hosts = %d trunc=%v", d.ProbedHosts, d.Truncated)
	}
}

// ---- inet_domain_info ----

func TestDomainInfoWindows(t *testing.T) {
	mgr := newFakeManager()
	mgr.add(&scriptedSession{
		info: core.SessionInfo{ID: "d1", OS: "windows"},
		rules: []rule{
			{match: "net user /domain", stdout: sampleNetUser},
			{match: "net group /domain", stdout: sampleNetGroup},
			{match: "nltest /domain_trusts", stdout: sampleNltestTrust, evidenceID: "ev_dom"},
			{match: "nltest /dclist:corp.local", stdout: sampleNltestDC},
		},
	})
	c := capWith(mgr)
	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_domain_info", Input: json.RawMessage(`{"session_id":"d1","domain":"corp.local"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	d := decode[DomainInfo](t, res)
	if d.Domain != "corp.local" || len(d.Users) != 5 {
		t.Fatalf("domain info = %+v", d)
	}
	if strings.Join(d.Trusts, ",") != "corp.local,dev.corp.local" {
		t.Fatalf("trusts = %v", d.Trusts)
	}
	if strings.Join(d.DCs, ",") != "DC01.corp.local,DC02.corp.local" {
		t.Fatalf("dcs = %v", d.DCs)
	}
}

// ---- inet_smb_shares ----

func TestSMBSharesRemoteWindows(t *testing.T) {
	mgr := newFakeManager()
	mgr.add(&scriptedSession{
		info:  core.SessionInfo{ID: "x1", OS: "windows"},
		rules: []rule{{match: "net view", stdout: sampleNetView, evidenceID: "ev_smb"}},
	})
	c := capWith(mgr)
	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_smb_shares", Input: json.RawMessage(`{"session_id":"x1","host":"10.0.0.9"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	d := decode[SMBResult](t, res)
	if d.Target != "10.0.0.9" || d.Count != 5 || len(d.Shares) != 5 {
		t.Fatalf("smb = %+v", d)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Kind != "command_output" {
		t.Fatalf("evidence = %+v", res.Evidence)
	}
}

func TestSMBSharesLocalAndLinux(t *testing.T) {
	mgr := newFakeManager()
	mgr.add(&scriptedSession{
		info:  core.SessionInfo{ID: "x1", OS: "windows"},
		rules: []rule{{match: "net share", stdout: sampleNetView}},
	})
	c := capWith(mgr)
	res, _ := c.Call(context.Background(), core.Call{
		Tool: "inet_smb_shares", Input: json.RawMessage(`{"session_id":"x1"}`),
	})
	d := decode[SMBResult](t, res)
	if d.Target != "local" || d.Count != 5 {
		t.Fatalf("local shares = %+v", d)
	}

	mgr2 := newFakeManager()
	mgr2.add(&scriptedSession{
		info:  core.SessionInfo{ID: "l1", OS: "linux"},
		rules: []rule{{match: "smbclient", stdout: sampleSmbclient}},
	})
	c2 := capWith(mgr2)
	res2, _ := c2.Call(context.Background(), core.Call{
		Tool: "inet_smb_shares", Input: json.RawMessage(`{"session_id":"l1","host":"10.0.0.9"}`),
	})
	d2 := decode[SMBResult](t, res2)
	if d2.Count != 4 {
		t.Fatalf("linux shares = %+v", d2)
	}
}

// TestPortScanPaginates is the §5.5.4 gate for list output: a scan that opens
// more ports than one page carries must page with a usable cursor instead of
// dropping rows.
func TestPortScanPaginates(t *testing.T) {
	c := capWith(scanManager("s1"))
	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_portscan",
		Input: json.RawMessage(
			`{"session_id":"s1","hosts":["10.0.0.5","10.0.0.6","10.0.0.7"],"ports":"22,139,445,3389,80,443","page_size":2}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	d := decode[PortScan](t, res)
	if d.TotalOpen != 4 {
		t.Fatalf("total_open = %d, want 4 (the full scan)", d.TotalOpen)
	}
	if len(d.Open) != 2 || d.OpenCount != 2 {
		t.Fatalf("page = %+v", d)
	}
	if res.Page == nil || res.Page.Total != 4 || !res.Page.HasMore || res.Page.Cursor == "" {
		t.Fatalf("page meta = %+v", res.Page)
	}
	if !res.Truncated {
		t.Fatal("a partial page must set Truncated")
	}

	// The cursor addresses the second page.
	res2, err := c.Call(context.Background(), core.Call{
		Tool:  "inet_portscan",
		Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5","10.0.0.6","10.0.0.7"],"ports":"22,139,445,3389,80,443","page_size":2,"cursor":"` + res.Page.Cursor + `"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	d2 := decode[PortScan](t, res2)
	if len(d2.Open) != 2 || d2.TotalOpen != 4 {
		t.Fatalf("second page = %+v", d2)
	}
	if d2.Open[0] == d.Open[0] {
		t.Fatalf("second page repeated the first: %+v", d2.Open)
	}
	if res2.Page == nil || res2.Page.HasMore {
		t.Fatalf("second page meta = %+v", res2.Page)
	}

	// A garbled cursor is rejected, not silently restarted.
	bad, _ := c.Call(context.Background(), core.Call{
		Tool:  "inet_portscan",
		Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5"],"ports":"22","cursor":"oops"}`),
	})
	if bad.Error == nil || bad.Error.Code != core.CodeInvalidInput {
		t.Fatalf("bad cursor = %+v", bad)
	}
}
