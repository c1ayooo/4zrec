package internalnet

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

var errBoom = errors.New("boom")

// ---- inet_domain_info (linux) ----

func TestDomainInfoLinuxRealm(t *testing.T) {
	mgr := newFakeManager()
	mgr.add(&scriptedSession{
		info: core.SessionInfo{ID: "l1", OS: "linux"},
		rules: []rule{
			{match: "realm list", stdout: "realm-name: corp.local\ndomain-name: corp.local\n"},
			{match: "net ads info", stdout: "Packages: rpm\nRealm: CORP.LOCAL\nDomain: corp.local\n"},
			{match: "ldapsearch", stdout: "dn: CN=Administrator,DC=corp,DC=local\nsAMAccountName: Administrator\n"},
		},
	})
	c := capWith(mgr)
	res, err := c.Call(context.Background(), core.Call{
		Tool: "inet_domain_info", Input: json.RawMessage(`{"session_id":"l1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	d := decode[DomainInfo](t, res)
	if d.Domain != "corp.local" {
		t.Fatalf("domain = %q", d.Domain)
	}
}

// ---- inet_portscan: nc tool, session failure ----

func TestPortScanNC(t *testing.T) {
	mgr := newFakeManager()
	mgr.add(&scriptedSession{
		info: core.SessionInfo{ID: "s1", OS: "linux"},
		rules: []rule{
			{match: "10.0.0.5", stdout: "OPEN 10.0.0.5 443\n"},
		},
	})
	c := capWith(mgr)
	res, err := c.Call(context.Background(), core.Call{
		Tool:  "inet_portscan",
		Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5"],"ports":"443","tool":"nc","per_port_ms":500}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	d := decode[PortScan](t, res)
	if len(d.Open) != 1 || d.Open[0].Service != "https" {
		t.Fatalf("open = %+v", d.Open)
	}
}

func TestPortScanPartial(t *testing.T) {
	mgr := newFakeManager()
	mgr.add(&scriptedSession{
		info: core.SessionInfo{ID: "s1", OS: "linux"},
		rules: []rule{
			{match: "10.0.0.5", stdout: "OPEN 10.0.0.5 22\n"},
			{match: "10.0.0.6", err: errBoom},
		},
	})
	c := capWith(mgr)
	res, _ := c.Call(context.Background(), core.Call{
		Tool:  "inet_portscan",
		Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5","10.0.0.6"],"ports":"22"}`),
	})
	if res.Status != core.StatusPartial || !res.OK {
		t.Fatalf("status = %q ok=%v", res.Status, res.OK)
	}
}

func TestPortScanAllFail(t *testing.T) {
	mgr := newFakeManager()
	mgr.add(&scriptedSession{
		info:  core.SessionInfo{ID: "s1", OS: "linux"},
		rules: []rule{{match: "10.0.0.5", err: errBoom}},
	})
	c := capWith(mgr)
	res, _ := c.Call(context.Background(), core.Call{
		Tool:  "inet_portscan",
		Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5"],"ports":"22"}`),
	})
	if res.Status != core.StatusFailed || res.Error == nil {
		t.Fatalf("status = %q err = %+v", res.Status, res.Error)
	}
}

// ---- inet_host_discovery: tcp method, no hosts found, empty cidr ----

func TestHostDiscoveryTCPMethod(t *testing.T) {
	mgr := newFakeManager()
	mgr.add(&scriptedSession{
		info: core.SessionInfo{ID: "s1", OS: "linux"},
		rules: []rule{
			{match: "dev/tcp", stdout: "UP 10.0.0.1\n"},
			{match: "arp -a", stdout: "? (10.0.0.1) at 00:11:22:33:44:55 [ether] on eth0\n"},
		},
	})
	c := capWith(mgr)
	res, _ := c.Call(context.Background(), core.Call{
		Tool:  "inet_host_discovery",
		Input: json.RawMessage(`{"session_id":"s1","cidr":"10.0.0.0/29","method":"tcp"}`),
	})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	d := decode[HostDiscovery](t, res)
	if d.Method != "tcp" || len(d.Hosts) != 1 {
		t.Fatalf("tcp sweep = %+v", d)
	}
}

func TestHostDiscoveryBadMethod(t *testing.T) {
	c := capWith(discoveryManager("s1"))
	res, _ := c.Call(context.Background(), core.Call{
		Tool:  "inet_host_discovery",
		Input: json.RawMessage(`{"session_id":"s1","cidr":"10.0.0.0/29","method":"icmp"}`),
	})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("error = %+v", res.Error)
	}
}

// ---- small helpers ----

func TestSmallHelpers(t *testing.T) {
	if clampMax(0, 16, 256) != 16 || clampMax(999, 16, 256) != 256 || clampMax(5, 16, 256) != 5 {
		t.Fatal("clampMax")
	}
	if core.TimeoutFromMS(0, defaultTimeout, maxTimeout) != defaultTimeout || core.TimeoutFromMS(1000, defaultTimeout, maxTimeout) != 1e9 {
		t.Fatal("timeoutFromMS")
	}
	if core.TimeoutFromMS(int(maxTimeout/time.Millisecond)+5000, defaultTimeout, maxTimeout) != maxTimeout {
		t.Fatal("timeoutFromMS cap")
	}
	if firstDur(0, defaultTimeout) != defaultTimeout || firstDur(1, 0) != 1 {
		t.Fatal("firstDur")
	}
	if joinInts([]int{1, 2, 3}, ",") != "1,2,3" {
		t.Fatal("joinInts")
	}
	if chunks := chunkStrings([]string{"a", "b", "c", "d", "e"}, 2); len(chunks) != 3 {
		t.Fatalf("chunkStrings = %+v", chunks)
	}
	if firstLine("\n\n  x  \n") != "x" || firstLine("\n\n") != "" {
		t.Fatal("firstLine")
	}
	if orDash("") != "-" || orDash("z") != "z" {
		t.Fatal("orDash")
	}
	if hostList([]DiscoveredHost{{Host: "a"}, {Host: "b"}})[1] != "b" {
		t.Fatal("hostList")
	}
	if len(mustJSON(map[string]string{"k": "v"})) == 0 {
		t.Fatal("mustJSON")
	}
}

func TestDedupePortsAndCIDRs(t *testing.T) {
	in := []OpenPort{{Host: "10.0.0.2", Port: 80}, {Host: "10.0.0.2", Port: 80}, {Host: "10.0.0.1", Port: 22}}
	got := dedupePorts(in)
	if len(got) != 2 || got[0].Host != "10.0.0.1" {
		t.Fatalf("dedupePorts = %+v", got)
	}
	ifaces := []NetInterface{
		{Name: "lo", IPv4: []string{"127.0.0.1/8"}},
		{Name: "eth0", IPv4: []string{"10.0.0.5/24", "10.0.0.6/24"}},
		{Name: "eth1", IPv4: []string{"not-a-cidr"}},
	}
	if c := localCIDRs(ifaces); len(c) != 1 || c[0] != "10.0.0.0/24" {
		t.Fatalf("localCIDRs = %+v", c)
	}
	if got := adaptersToInterfaces(Ipconfig{Adapters: []Adapter{{Name: "E0", MAC: "m", IPv4: []string{"1.2.3.4"}, Mask: "255.0.0.0"}}}); len(got) != 1 || got[0].Name != "E0" || got[0].Mask != "255.0.0.0" {
		t.Fatalf("adaptersToInterfaces = %+v", got)
	}
}

func TestEvidenceRefs(t *testing.T) {
	refs := core.EvidenceRefs(core.Output{EvidenceID: "a", Stdout: "xx"}, core.Output{EvidenceID: "a"}, core.Output{})
	if len(refs) != 1 || refs[0].ID != "a" || refs[0].Size != 2 || refs[0].Kind != "command_output" {
		t.Fatalf("evidenceRefs = %+v", refs)
	}
}

func TestDetectOS(t *testing.T) {
	c := capWith(nil)
	if got := c.detectOS(context.Background(), &scriptedSession{info: core.SessionInfo{OS: "windows"}}, defaultTimeout); got != "windows" {
		t.Fatalf("windows = %q", got)
	}
	if got := c.detectOS(context.Background(), &scriptedSession{info: core.SessionInfo{OS: "Linux"}}, defaultTimeout); got != "linux" {
		t.Fatalf("linux = %q", got)
	}
	// unknown OS: uname -s probe returns output => linux
	s := &scriptedSession{info: core.SessionInfo{}, rules: []rule{{match: "uname -s", stdout: "Linux\n"}}}
	if got := c.detectOS(context.Background(), s, defaultTimeout); got != "linux" {
		t.Fatalf("probe linux = %q", got)
	}
	// unknown OS and a failing probe => windows (fail closed to the other branch)
	s2 := &scriptedSession{info: core.SessionInfo{}, rules: []rule{{match: "uname -s", err: errBoom}}}
	if got := c.detectOS(context.Background(), s2, defaultTimeout); got != "windows" {
		t.Fatalf("probe fail = %q", got)
	}
}

func TestLocalSummaryAndStatus(t *testing.T) {
	li := &LocalInfo{Hostname: "h", User: "u", Interfaces: []NetInterface{{Name: "eth0", IPv4: []string{"10.0.0.5/24"}}}}
	s := localSummary(li)
	if s == "" {
		t.Fatal("summary empty")
	}
	r := core.Result{Status: core.StatusSuccess}
	applyLocalStatus(&r, nil)
	if !r.OK || r.Status != core.StatusSuccess {
		t.Fatal("no errors should be success")
	}
	applyLocalStatus(&r, []string{"a", "b"})
	if r.Status != core.StatusPartial {
		t.Fatal("few errors should be partial")
	}
	applyLocalStatus(&r, []string{"a", "b", "c", "d"})
	if r.Status != core.StatusFailed || r.Error == nil {
		t.Fatal("many errors should be failed")
	}
	n := localNextSteps("s1", li.Interfaces)
	if len(n) != 1 || n[0].Tool != "inet_host_discovery" {
		t.Fatalf("next = %+v", n)
	}
}
