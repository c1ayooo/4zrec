package internalnet

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// emptyPhrases are the "nothing was said" summaries the contract forbids.
var emptyPhrases = map[string]bool{
	"": true, "完成": true, "成功": true, "OK": true, "失败": true, "部分完成": true,
}

func assertInformative(t *testing.T, tool, summary string) {
	t.Helper()
	s := strings.TrimSpace(summary)
	if emptyPhrases[s] {
		t.Fatalf("%s: Summary %q is an empty phrase", tool, summary)
	}
	if n := len([]rune(s)); n > core.MaxSummaryRunes {
		t.Fatalf("%s: Summary is %d runes, over the limit", tool, n)
	}
}

func assertValidData(t *testing.T, tool string, res core.Result) {
	t.Helper()
	var v any
	if err := json.Unmarshal(res.Data, &v); err != nil {
		t.Fatalf("%s: Data is not valid JSON: %v (%s)", tool, err, res.Data)
	}
}

// TestEnvelopeSummaryAllTools drives every tool through its success path and
// asserts the four hard envelope fields plus a real, target-naming Summary.
func TestEnvelopeSummaryAllTools(t *testing.T) {
	ctx := context.Background()

	discMgr := discoveryManager("s1")
	scanMgr := scanManager("s1")

	domMgr := newFakeManager()
	domMgr.add(&scriptedSession{
		info: core.SessionInfo{ID: "d1", OS: "windows"},
		rules: []rule{
			{match: "net user /domain", stdout: sampleNetUser},
			{match: "net group /domain", stdout: sampleNetGroup},
			{match: "nltest /domain_trusts", stdout: sampleNltestTrust},
			{match: "nltest /dclist:corp.local", stdout: sampleNltestDC},
		},
	})

	smbMgr := newFakeManager()
	smbMgr.add(&scriptedSession{
		info:  core.SessionInfo{ID: "x1", OS: "windows"},
		rules: []rule{{match: "net view", stdout: sampleNetView}},
	})

	localMgr := newFakeManager()
	localMgr.add(linuxSurveySession("s1"))

	cases := []struct {
		tool    string
		mgr     *fakeManager
		input   string
		wantSub []string
	}{
		{"inet_local_info", localMgr, `{"session_id":"s1"}`, []string{"root@web01", "本地信息", "网卡 2 张", "路由 3 条"}},
		{"inet_host_discovery", discMgr, `{"session_id":"s1","cidr":"10.0.0.0/29"}`, []string{"枚举内网主机", "10.0.0.0/29", "2 台存活"}},
		{"inet_portscan", scanMgr, `{"session_id":"s1","hosts":["10.0.0.5","10.0.0.6"],"ports":"22,139,445,3389"}`, []string{"的 4 个端口", "开放 3 个", "22,445,3389"}},
		{"inet_domain_info", domMgr, `{"session_id":"d1","domain":"corp.local"}`, []string{"查询域 corp.local", "用户 5 个", "域控 DC01.corp.local"}},
		{"inet_smb_shares", smbMgr, `{"session_id":"x1","host":"10.0.0.9"}`, []string{"枚举 10.0.0.9 的 SMB 共享", "5 个"}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			res, err := capWith(tc.mgr).Call(ctx, core.Call{Tool: tc.tool, Input: json.RawMessage(tc.input)})
			if err != nil {
				t.Fatalf("Call err = %v", err)
			}
			if !res.Status.Valid() {
				t.Fatalf("Status %q is not one of the six states", res.Status)
			}
			if res.Meta.Tool != tc.tool {
				t.Fatalf("Meta.Tool = %q, want %q", res.Meta.Tool, tc.tool)
			}
			if res.Meta.Version != kitVersion {
				t.Fatalf("Meta.Version = %q, want %q", res.Meta.Version, kitVersion)
			}
			assertInformative(t, tc.tool, res.Summary)
			for _, sub := range tc.wantSub {
				if !strings.Contains(res.Summary, sub) {
					t.Fatalf("%s: Summary %q missing %q", tc.tool, res.Summary, sub)
				}
			}
			assertValidData(t, tc.tool, res)
		})
	}
}

// TestEnvelopeFailurePaths pins the failing-envelope invariants: a usable
// Status, a machine-readable Error.Code, and a non-generic Summary.
func TestEnvelopeFailurePaths(t *testing.T) {
	ctx := context.Background()

	res, err := capWith(newFakeManager()).Call(ctx, core.Call{
		Tool: "inet_local_info", Input: json.RawMessage(`{"session_id":"nope"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("missing session = %q %+v", res.Status, res.Error)
	}
	if res.Meta.Tool != "inet_local_info" {
		t.Fatalf("Meta.Tool = %q", res.Meta.Tool)
	}
	assertInformative(t, "inet_local_info", res.Summary)

	res, err = capWith(nil).Call(ctx, core.Call{
		Tool: "inet_portscan", Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5"],"ports":"22"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusUnavailable || res.Error == nil || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("missing manager = %q %+v", res.Status, res.Error)
	}
	assertInformative(t, "inet_portscan", res.Summary)
}

// TestPortScanPartialAndFailureSummary covers the two non-success scan
// summaries: some hosts fail (partial) and every host fails (failed).
func TestPortScanPartialAndFailureSummary(t *testing.T) {
	ctx := context.Background()

	partial := newFakeManager()
	partial.add(&scriptedSession{
		info: core.SessionInfo{ID: "s1", OS: "linux"},
		rules: []rule{
			{match: "10.0.0.5", err: errors.New("boom")},
			{match: "10.0.0.6", stdout: "OPEN 10.0.0.6 22\n"},
		},
	})
	res, err := capWith(partial).Call(ctx, core.Call{
		Tool: "inet_portscan", Input: json.RawMessage(`{"session_id":"s1","hosts":["10.0.0.5","10.0.0.6"],"ports":"22"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusPartial {
		t.Fatalf("status = %q, want partial (%s)", res.Status, res.Summary)
	}
	if !strings.Contains(res.Summary, "1/2 台主机命令失败") {
		t.Fatalf("partial summary = %q", res.Summary)
	}

	down := newFakeManager()
	down.add(&scriptedSession{
		info:  core.SessionInfo{ID: "s2", OS: "linux"},
		rules: []rule{{match: "", err: errors.New("down")}},
	})
	res, err = capWith(down).Call(ctx, core.Call{
		Tool: "inet_portscan", Input: json.RawMessage(`{"session_id":"s2","hosts":["10.0.0.5"],"ports":"22"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != core.StatusFailed || res.Error == nil {
		t.Fatalf("status = %q err=%+v", res.Status, res.Error)
	}
	if !strings.Contains(res.Summary, "10.0.0.5") || !strings.Contains(res.Summary, "失败") {
		t.Fatalf("failure summary = %q", res.Summary)
	}
}

// TestSummaryHelpers exercises the bounded rendering helpers directly so their
// edge branches (single vs many hosts, capped ports, overflow lists) are
// covered.
func TestSummaryHelpers(t *testing.T) {
	if got := sessionLabel("root", "web01"); got != "root@web01" {
		t.Fatalf("sessionLabel = %q", got)
	}
	if got := sessionLabel("", "web01"); got != "web01" {
		t.Fatalf("sessionLabel host-only = %q", got)
	}
	if got := sessionLabel("root", ""); got != "root" {
		t.Fatalf("sessionLabel user-only = %q", got)
	}
	if got := sessionLabel("", ""); got != "-" {
		t.Fatalf("sessionLabel empty = %q", got)
	}

	if got := hostLabel([]string{"10.0.0.5"}); got != "10.0.0.5" {
		t.Fatalf("hostLabel single = %q", got)
	}
	got := hostLabel([]string{"a", "b", "c", "d"})
	if !strings.Contains(got, "4 台主机") || !strings.Contains(got, "…") {
		t.Fatalf("hostLabel many = %q", got)
	}

	many := make([]OpenPort, 0, 12)
	for i := 1; i <= 12; i++ {
		many = append(many, OpenPort{Host: "h", Port: i})
	}
	if got := openPortList(many); !strings.HasSuffix(got, ",…") || !strings.Contains(got, "10") {
		t.Fatalf("openPortList capped = %q", got)
	}
	if got := openPortList([]OpenPort{{Port: 443}, {Port: 22}, {Port: 22}}); got != "22,443" {
		t.Fatalf("openPortList distinct = %q", got)
	}

	if got := joinCapped([]string{"a", "b", "c", "d"}, 3); got != "a,b,c,…" {
		t.Fatalf("joinCapped overflow = %q", got)
	}
	if got := joinCapped([]string{"a", "b"}, 3); got != "a,b" {
		t.Fatalf("joinCapped exact = %q", got)
	}
	if got := joinCapped(nil, 3); got != "" {
		t.Fatalf("joinCapped nil = %q", got)
	}
	if got := joinCapped([]string{"a"}, 0); got != "" {
		t.Fatalf("joinCapped zero max = %q", got)
	}

	if got := shareNames([]Share{{Name: "SYSVOL"}, {Name: "NETLOGON"}}); strings.Join(got, ",") != "SYSVOL,NETLOGON" {
		t.Fatalf("shareNames = %v", got)
	}

	li := &LocalInfo{Hostname: "h", User: "u", Interfaces: []NetInterface{{Name: "eth0"}}, Routes: []Route{{}}}
	if s := localSummary(li); !strings.Contains(s, "u@h") || !strings.Contains(s, "网卡 1 张") {
		t.Fatalf("localSummary = %q", s)
	}
}
