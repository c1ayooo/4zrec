package privesc

import (
	"reflect"
	"testing"
)

func TestParseSudoL(t *testing.T) {
	out := `Matching Defaults entries for www-data on victim:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on victim:
    (ALL : ALL) NOPASSWD: ALL
    (root) NOPASSWD: /usr/bin/find
    (root) /usr/bin/vim
`
	rules := parseSudoL(out)
	if len(rules) != 3 {
		t.Fatalf("rules = %d, want 3: %+v", len(rules), rules)
	}
	if !rules[0].NoPassword || rules[0].RunAs != "ALL" || rules[0].Command != "ALL" {
		t.Fatalf("rule0 = %+v", rules[0])
	}
	if !rules[1].NoPassword || rules[1].RunAs != "root" || rules[1].Command != "/usr/bin/find" {
		t.Fatalf("rule1 = %+v", rules[1])
	}
	if rules[2].NoPassword || rules[2].Command != "/usr/bin/vim" {
		t.Fatalf("rule2 = %+v", rules[2])
	}
}

func TestParseSudoLFailClosed(t *testing.T) {
	for _, in := range []string{"", "not sudo output\njust text\n", "sudo: a password is required\n"} {
		if got := parseSudoL(in); len(got) != 0 {
			t.Fatalf("parseSudoL(%q) = %+v, want empty", in, got)
		}
	}
}

func TestParseSUID(t *testing.T) {
	out := "/usr/bin/sudo\n/usr/bin/find\n\n/usr/bin/passwd\n"
	got := parseSUID(out)
	want := []string{"/usr/bin/find", "/usr/bin/passwd", "/usr/bin/sudo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSUID = %v, want %v", got, want)
	}
}

func TestParseSUIDToleratesLSColumns(t *testing.T) {
	out := "  12345 /usr/bin/find\n10777 /usr/bin/less\n"
	got := parseSUID(out)
	if !reflect.DeepEqual(got, []string{"/usr/bin/find", "/usr/bin/less"}) {
		t.Fatalf("parseSUID -ls = %v", got)
	}
}

func TestParseSUIDFailClosed(t *testing.T) {
	if got := parseSUID("permission denied\n"); len(got) != 0 {
		t.Fatalf("parseSUID garbage = %v", got)
	}
}

func TestParseCapabilities(t *testing.T) {
	out := `/usr/bin/python3.8 = cap_setuid,cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/sbin/tcpdump cap_net_admin,cap_net_raw=ep
`
	got := parseCapabilities(out)
	if len(got) != 3 {
		t.Fatalf("caps = %d, want 3: %+v", len(got), got)
	}
	if got[0].Path != "/usr/bin/python3.8" || !reflect.DeepEqual(got[0].Caps, []string{"cap_setuid", "cap_net_raw+ep"}) {
		t.Fatalf("cap0 = %+v", got[0])
	}
	if got[2].Path != "/usr/sbin/tcpdump" {
		t.Fatalf("cap2 = %+v", got[2])
	}
}

func TestParseCapabilitiesFailClosed(t *testing.T) {
	if got := parseCapabilities("getcap: command not found\n"); len(got) != 0 {
		t.Fatalf("caps = %v", got)
	}
}

func TestParseWhoamiPriv(t *testing.T) {
	out := `PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeDebugPrivilege              Debug programs                            Disabled
`
	got := parseWhoamiPriv(out)
	if len(got) != 4 {
		t.Fatalf("privs = %d, want 4: %+v", len(got), got)
	}
	if got[1].Name != "SeImpersonatePrivilege" || got[1].State != "Enabled" {
		t.Fatalf("priv1 = %+v", got[1])
	}
	if got[0].State != "Disabled" {
		t.Fatalf("priv0 = %+v", got[0])
	}
}

func TestParseWhoamiPrivFailClosed(t *testing.T) {
	if got := parseWhoamiPriv("ERROR: Access is denied.\n"); len(got) != 0 {
		t.Fatalf("privs = %v", got)
	}
}

func TestParseWhoamiGroups(t *testing.T) {
	out := `GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                 Alias            S-1-5-32-544 Group used for deny only
`
	got := parseWhoamiGroups(out)
	if len(got) != 2 || got[0] != `BUILTIN\Users` || got[1] != `BUILTIN\Administrators` {
		t.Fatalf("groups = %v", got)
	}
}

func TestParseKernelVersion(t *testing.T) {
	if got := parseKernelVersion("5.15.0-91-generic\n"); got != "5.15.0" {
		t.Fatalf("uname -r = %q", got)
	}
	if got := parseKernelVersion("Linux victim 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"); got != "5.15.0" {
		t.Fatalf("uname -a = %q", got)
	}
	if got := parseKernelVersion(""); got != "" {
		t.Fatalf("empty = %q", got)
	}
}

func TestParseOSRelease(t *testing.T) {
	out := `NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
VERSION_ID="20.04"
`
	m := parseOSRelease(out)
	if m["ID"] != "ubuntu" || m["VERSION_ID"] != "20.04" || m["NAME"] != "Ubuntu" {
		t.Fatalf("os-release = %v", m)
	}
	if parseOSRelease("garbage without equals") != nil {
		t.Fatal("expected nil for garbage")
	}
}

func TestParsePolkitVersion(t *testing.T) {
	cases := map[string]string{
		"pkexec version 0.105\n":        "0.105",
		"0.105-31+deb11u1":              "0.105",
		"policykit-1\t0.105-31+deb11u1": "0.105",
		"no version here":               "",
		"":                              "",
	}
	for in, want := range cases {
		if got := parsePolkitVersion(in); got != want {
			t.Fatalf("parsePolkitVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSysteminfo(t *testing.T) {
	out := `Host Name:                 VICTIM
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
System Type:               x64-based PC
`
	m := parseSysteminfo(out)
	if m["OS Name"] != "Microsoft Windows Server 2019 Standard" {
		t.Fatalf("systeminfo = %v", m)
	}
	if m["OS Version"] != "10.0.17763 N/A Build 17763" {
		t.Fatalf("systeminfo = %v", m)
	}
}

func TestParseAutoLogon(t *testing.T) {
	out := `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    DefaultUserName    REG_SZ    Administrator
    DefaultPassword    REG_SZ    P@ssw0rd!
`
	got := parseAutoLogon(out)
	if got.User != "Administrator" || !got.HasPassword {
		t.Fatalf("autologon = %+v", got)
	}
}

func TestParseAlwaysInstallElevated(t *testing.T) {
	on := `HKEY_LOCAL_MACHINE\...\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
HKEY_CURRENT_USER\...\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
`
	if !parseAlwaysInstallElevated(on) {
		t.Fatal("expected true when both hives are 0x1")
	}
	off := `    AlwaysInstallElevated    REG_DWORD    0x0
`
	if parseAlwaysInstallElevated(off) {
		t.Fatal("expected false when value is 0x0")
	}
	if parseAlwaysInstallElevated("no such key") {
		t.Fatal("expected false when absent (fail closed)")
	}
}

func TestParseServicePaths(t *testing.T) {
	out := `Name              PathName                                                    StartMode
Spooler           C:\WINDOWS\System32\spoolsv.exe                             Auto
VulnSvc           C:\Program Files\Vuln App\service.exe                       Auto
Quoted            "C:\Program Files\Good App\svc.exe"                         Manual
`
	got := parseServicePaths(out)
	if len(got) != 3 {
		t.Fatalf("services = %d, want 3: %+v", len(got), got)
	}
	if got[0].Name != "Spooler" || got[0].Unquoted {
		t.Fatalf("svc0 = %+v", got[0])
	}
	if got[1].Name != "VulnSvc" || !got[1].Unquoted || got[1].StartMode != "Auto" {
		t.Fatalf("svc1 = %+v", got[1])
	}
	if got[2].Unquoted {
		t.Fatalf("quoted svc should not be unquoted: %+v", got[2])
	}
	unq := unquotedServicePaths(got)
	if len(unq) != 1 || unq[0].Name != "VulnSvc" {
		t.Fatalf("unquoted = %+v", unq)
	}
}

func TestParseTasklist(t *testing.T) {
	out := `Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0        144 K
svchost.exe                   1048 Services                   0     12,345 K
svchost.exe                   1120 Services                   0      8,000 K
`
	got := parseTasklist(out)
	if !reflect.DeepEqual(got, []string{"System", "svchost.exe"}) {
		t.Fatalf("tasklist = %v", got)
	}
}

func TestParseWritablePaths(t *testing.T) {
	lsOut := `-rw-rw-r-- 1 root root  100 Jan  1 00:00 /etc/systemd/system/evil.service
drwxr-xr-x 2 root root 4096 Jan  1 00:00 /etc/cron.d
`
	got := parseWritablePaths(lsOut)
	if !reflect.DeepEqual(got, []string{"/etc/systemd/system/evil.service"}) {
		t.Fatalf("ls writable = %v", got)
	}
	findOut := "/etc/cron.d/backup\n/etc/systemd/system/x.service\n"
	got = parseWritablePaths(findOut)
	if !reflect.DeepEqual(got, []string{"/etc/cron.d/backup", "/etc/systemd/system/x.service"}) {
		t.Fatalf("find writable = %v", got)
	}
}

func TestParsePasswdWritable(t *testing.T) {
	out := `-rw-r--r-- 1 root root 1234 Jan  1 00:00 /etc/passwd
-rw-rw-r-- 1 root root  999 Jan  1 00:00 /etc/shadow
`
	if !parsePasswdWritable(out) {
		t.Fatal("expected group-writable shadow to be flagged")
	}
	if parsePasswdWritable("-rw-r--r-- 1 root root 1234 Jan  1 00:00 /etc/passwd\n") {
		t.Fatal("expected not writable")
	}
}

func TestCompareKernelRange(t *testing.T) {
	cases := []struct {
		v  string
		in bool
	}{
		{"5.15.0-91-generic", true},
		{"5.8", true},
		{"5.16.10", true},
		{"5.16.11", false},
		{"5.4.0", false},
		{"6.1.0", false},
		{"garbage", false},
	}
	for _, c := range cases {
		if got := compareKernelRange(c.v, "5.8", "5.16.11"); got != c.in {
			t.Fatalf("compareKernelRange(%q) = %v, want %v", c.v, got, c.in)
		}
	}
}

func TestPolkitVulnerable(t *testing.T) {
	if !polkitVulnerable("0.105") {
		t.Fatal("0.105 should be vulnerable")
	}
	if polkitVulnerable("0.121") {
		t.Fatal("0.121 should not be vulnerable")
	}
	if polkitVulnerable("garbage") {
		t.Fatal("garbage should fail closed")
	}
}

func TestDirtyPipeRange(t *testing.T) {
	if !dirtyPipeRange("5.15.0") {
		t.Fatal("5.15.0 should be in range")
	}
	if dirtyPipeRange("5.4.0") {
		t.Fatal("5.4.0 should be out of range")
	}
}

func TestCapsDangerous(t *testing.T) {
	if !capsDangerous([]string{"cap_setuid+ep"}) {
		t.Fatal("cap_setuid should be dangerous")
	}
	if capsDangerous([]string{"cap_net_raw+ep"}) {
		t.Fatal("cap_net_raw should not be dangerous")
	}
}

func TestBaseName(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/find":               "find",
		`C:\Windows\System32\cmd.exe`: "cmd.exe",
		"nmap":                        "nmap",
	}
	for in, want := range cases {
		if got := baseName(in); got != want {
			t.Fatalf("baseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCmpVersion(t *testing.T) {
	if cmpVersion([]int{5, 16, 10}, []int{5, 16, 11}) != -1 {
		t.Fatal("5.16.10 < 5.16.11")
	}
	if cmpVersion([]int{5, 16}, []int{5, 16, 0}) != 0 {
		t.Fatal("5.16 == 5.16.0")
	}
	if cmpVersion([]int{6}, []int{5, 15}) != 1 {
		t.Fatal("6 > 5.15")
	}
}

func TestParseNumericVersionFailClosed(t *testing.T) {
	if parseNumericVersion("no digits") != nil {
		t.Fatal("expected nil")
	}
}
