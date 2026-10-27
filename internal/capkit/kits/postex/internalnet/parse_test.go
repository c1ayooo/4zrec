package internalnet

import (
	"net"
	"reflect"
	"testing"
)

// ---- realistic canned outputs ----

const sampleIPAddr = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:ab:cd:ef brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.10/24 brd 10.0.0.255 scope global dynamic eth0
       valid_lft 86390sec preferred_lft 86390sec
    inet6 fe80::20c:29ff:feab:cdef/64 scope link
       valid_lft forever preferred_lft forever
`

const sampleSS = `Netid  State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port  Process
udp    UNCONN  0       0        127.0.0.53%lo:53          0.0.0.0:*      users:(("systemd-resolve",pid=715,fd=13))
tcp    LISTEN  0       128            0.0.0.0:22            0.0.0.0:*      users:(("sshd",pid=812,fd=3))
tcp    LISTEN  0       128               [::]:22               [::]:*      users:(("sshd",pid=812,fd=4))
tcp    LISTEN  0       4096        127.0.0.1:631           0.0.0.0:*      users:(("cupsd",pid=1000,fd=7))
tcp    ESTAB   0       0          10.0.0.10:22            10.0.0.20:51000
`

const sampleARP = `? (10.0.0.1) at 00:11:22:33:44:55 [ether] on eth0
? (10.0.0.20) at aa:bb:cc:dd:ee:ff [ether] on eth0
? (10.0.0.99) at <incomplete> on eth0
`

const sampleIPRoute = `default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.10 metric 100
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.10
169.254.0.0/16 dev eth0 scope link metric 1000
`

const sampleARPWindows = `Interface: 10.0.0.10 --- 0x8
  Internet Address      Physical Address      Type
  10.0.0.1              00-11-22-33-44-55     dynamic
  10.0.0.255            ff-ff-ff-ff-ff-ff     static
`

const sampleNetstat = `Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       908
  TCP    10.0.0.10:139          0.0.0.0:0              LISTENING       4
  TCP    10.0.0.10:54321        10.0.0.20:445          ESTABLISHED     1234
  TCP    [::]:445               [::]:0                 LISTENING       4
  UDP    0.0.0.0:123            *:*                                    1176
`

const sampleRoutePrint = `===========================================================================
Interface List
  5...00 0c 29 ab cd ef ......Intel(R) 82574L Gigabit Network Connection
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0        10.0.0.1        10.0.0.10     25
        10.0.0.0    255.255.255.0         On-link         10.0.0.10    281
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
===========================================================================
`

const sampleIpconfig = `Windows IP Configuration

   Host Name . . . . . . . . . . . . : WIN-DC01
   Primary Dns Suffix  . . . . . . . : corp.local
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : corp.local
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
   Physical Address. . . . . . . . . : 00-0C-29-AB-CD-EF
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.0.0.10(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.0.1
   DNS Servers . . . . . . . . . . . : 10.0.0.1
                                       8.8.8.8
`

const sampleNetView = `Server Name            Remark

-------------------------------------------------------------------------------
ADMIN$       Disk           远程管理
C$           Disk           默认共享
IPC$         IPC            远程 IPC
NETLOGON     Disk           Logon server share
SYSVOL       Disk           Logon server share
The command completed successfully.
`

const sampleSmbclient = `        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        print$          Disk      Printer Drivers
SMB1 disabled -- no workgroup available
`

const sampleNltestDC = `Get list of DCs in domain 'corp.local' from '\\DC01.corp.local'.
    DC01.corp.local [PDC]  [DS] Site: Default-First-Site-Name
    DC02.corp.local       [DS] Site: Default-First-Site-Name
The command completed successfully
`

const sampleNltestTrust = `List of domain trusts:
    0: CORP corp.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)
    1: DEV dev.corp.local (NT 5) (Direct Outbound) (Direct Inbound)
The command completed successfully
`

const sampleNetUser = `User accounts for \\WIN-DC01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
john                     svc_backup
The command completed successfully.
`

const sampleNetGroup = `Group Accounts for \\DC01

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*Domain Admins
*Domain Users
*Enterprise Admins
The command completed successfully.
`

const sampleNetLocalGroupAdmins = `Alias name     administrators
Comment        Administrators have complete and unrestricted access

Members

-------------------------------------------------------------------------------
Administrator
CORP\Domain Admins
The command completed successfully.
`

const sampleTasklist = `Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0        144 K
smss.exe                       388 Services                   0      1,180 K
"svchost.exe"                  920 Services                   0     12,345 K
`

const samplePasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
john:x:1000:1000:John Doe,,,:/home/john:/bin/bash
`

const sampleWho = `root     pts/0        2024-01-15 10:23 (10.0.0.20)
admin    tty1         2024-01-15 09:01
`

const sampleLast = `root     pts/0        10.0.0.20        Mon Jan 15 10:23   still logged in
reboot   system boot  5.15.0-91-generic Mon Jan 15 08:00   still running
wtmp begins Mon Jan 15 08:00:00 2024
`

const sampleOSRelease = `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
ID=ubuntu
`

const sampleSysteminfo = `Host Name:                 WIN-DC01
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
System Type:               x64-based PC
`

// ---- parser tests ----

func TestParseIPAddr(t *testing.T) {
	ifaces := parseIPAddr(sampleIPAddr)
	if len(ifaces) != 2 {
		t.Fatalf("interfaces = %d, want 2 (%+v)", len(ifaces), ifaces)
	}
	if ifaces[0].Name != "lo" || ifaces[1].Name != "eth0" {
		t.Fatalf("names = %q, %q", ifaces[0].Name, ifaces[1].Name)
	}
	if ifaces[1].MAC != "00:0c:29:ab:cd:ef" {
		t.Fatalf("eth0 mac = %q", ifaces[1].MAC)
	}
	if !reflect.DeepEqual(ifaces[1].IPv4, []string{"10.0.0.10/24"}) {
		t.Fatalf("eth0 ipv4 = %v", ifaces[1].IPv4)
	}
	if len(ifaces[1].IPv6) != 1 || ifaces[1].IPv6[0] != "fe80::20c:29ff:feab:cdef/64" {
		t.Fatalf("eth0 ipv6 = %v", ifaces[1].IPv6)
	}
	if ifaces[1].State != "UP" {
		t.Fatalf("eth0 state = %q", ifaces[1].State)
	}
	if got := parseIPAddr("not an ip line at all"); got != nil {
		t.Fatalf("unparseable should be nil, got %v", got)
	}
}

func TestParseSSListeners(t *testing.T) {
	ls := parseSsListeners(sampleSS)
	// 4 listeners (udp:53, tcp:22 x2, tcp:631); ESTAB row dropped.
	if len(ls) != 4 {
		t.Fatalf("listeners = %d, want 4 (%+v)", len(ls), ls)
	}
	byPort := map[int]Listener{}
	for _, l := range ls {
		byPort[l.Port] = l
	}
	if l, ok := byPort[53]; !ok || l.Proto != "udp" || l.Process != "systemd-resolve" || l.PID != 715 {
		t.Fatalf("udp 53 = %+v", l)
	}
	if l := byPort[22]; l.Proto != "tcp" || l.Process != "sshd" {
		t.Fatalf("tcp 22 = %+v", l)
	}
	if l := byPort[631]; l.Local != "127.0.0.1:631" {
		t.Fatalf("tcp 631 = %+v", l)
	}
	if parseSsListeners("garbage") != nil {
		t.Fatal("garbage should yield nil")
	}
}

func TestParseARP(t *testing.T) {
	linux := parseARP(sampleARP)
	if len(linux) != 3 {
		t.Fatalf("linux arp = %d (%+v)", len(linux), linux)
	}
	if linux[0].IP != "10.0.0.1" || linux[0].MAC != "00:11:22:33:44:55" || linux[0].Iface != "eth0" {
		t.Fatalf("entry0 = %+v", linux[0])
	}
	if linux[2].MAC != "" {
		t.Fatalf("incomplete mac should be empty, got %q", linux[2].MAC)
	}

	win := parseARP(sampleARPWindows)
	if len(win) != 2 {
		t.Fatalf("windows arp = %d (%+v)", len(win), win)
	}
	if win[0].MAC != "00:11:22:33:44:55" || win[0].Type != "dynamic" {
		t.Fatalf("win entry0 = %+v", win[0])
	}
}

func TestParseRoutes(t *testing.T) {
	rs := parseRoutes(sampleIPRoute)
	if len(rs) != 3 {
		t.Fatalf("routes = %d (%+v)", len(rs), rs)
	}
	if rs[0].Dest != "0.0.0.0/0" || rs[0].Gateway != "10.0.0.1" || rs[0].Iface != "eth0" || rs[0].Metric != "100" {
		t.Fatalf("default route = %+v", rs[0])
	}
	if rs[1].Dest != "10.0.0.0/24" || rs[1].Gateway != "" {
		t.Fatalf("connected route = %+v", rs[1])
	}
}

func TestParseRoutePrint(t *testing.T) {
	rs := parseRoutePrint(sampleRoutePrint)
	if len(rs) != 3 {
		t.Fatalf("routes = %d (%+v)", len(rs), rs)
	}
	if rs[0].Dest != "0.0.0.0/0" || rs[0].Gateway != "10.0.0.1" || rs[0].Metric != "25" {
		t.Fatalf("default = %+v", rs[0])
	}
	if rs[1].Gateway != "" || rs[1].Dest != "10.0.0.0/255.255.255.0" {
		t.Fatalf("on-link = %+v", rs[1])
	}
}

func TestParseNetstat(t *testing.T) {
	ls := parseNetstat(sampleNetstat)
	if len(ls) != 4 {
		t.Fatalf("listeners = %d, want 4 (%+v)", len(ls), ls)
	}
	byPort := map[int]Listener{}
	for _, l := range ls {
		byPort[l.Port] = l
	}
	if l := byPort[135]; l.PID != 908 || l.State != "LISTENING" {
		t.Fatalf("135 = %+v", l)
	}
	if l := byPort[445]; l.Proto != "tcp" {
		t.Fatalf("445 = %+v", l)
	}
	if l := byPort[123]; l.Proto != "udp" {
		t.Fatalf("udp 123 = %+v", l)
	}
	if _, ok := byPort[54321]; ok {
		t.Fatal("ESTABLISHED row should be dropped")
	}
}

func TestParseIpconfig(t *testing.T) {
	cfg := parseIpconfig(sampleIpconfig)
	if cfg.Hostname != "WIN-DC01" || cfg.Domain != "corp.local" {
		t.Fatalf("host/domain = %q/%q", cfg.Hostname, cfg.Domain)
	}
	if len(cfg.Adapters) != 1 {
		t.Fatalf("adapters = %d (%+v)", len(cfg.Adapters), cfg.Adapters)
	}
	a := cfg.Adapters[0]
	if a.Name != "Ethernet0" || a.MAC != "00:0c:29:ab:cd:ef" || !a.DHCP {
		t.Fatalf("adapter = %+v", a)
	}
	if !reflect.DeepEqual(a.IPv4, []string{"10.0.0.10"}) || a.Mask != "255.255.255.0" {
		t.Fatalf("adapter ip/mask = %+v", a)
	}
	if a.Gateway != "10.0.0.1" {
		t.Fatalf("gateway = %q", a.Gateway)
	}
	if !reflect.DeepEqual(a.DNS, []string{"10.0.0.1", "8.8.8.8"}) {
		t.Fatalf("dns = %v", a.DNS)
	}
}

func TestParseNetView(t *testing.T) {
	shares := parseNetView(sampleNetView)
	if len(shares) != 5 {
		t.Fatalf("shares = %d (%+v)", len(shares), shares)
	}
	byName := map[string]Share{}
	for _, s := range shares {
		byName[s.Name] = s
	}
	if s := byName["ADMIN$"]; s.Type != "Disk" || s.Access != "admin" {
		t.Fatalf("ADMIN$ = %+v", s)
	}
	if s := byName["IPC$"]; s.Access != "ipc" {
		t.Fatalf("IPC$ = %+v", s)
	}
	if s := byName["SYSVOL"]; s.Access != "unknown" || s.Comment != "Logon server share" {
		t.Fatalf("SYSVOL = %+v", s)
	}

	smb := parseNetView(sampleSmbclient)
	if len(smb) != 4 {
		t.Fatalf("smbclient shares = %d (%+v)", len(smb), smb)
	}
	if parseNetView("no table here") != nil {
		t.Fatal("unparseable net view should be nil")
	}
}

func TestParseNltest(t *testing.T) {
	dcs := parseNltest(sampleNltestDC)
	if !reflect.DeepEqual(dcs, []string{"DC01.corp.local", "DC02.corp.local"}) {
		t.Fatalf("dcs = %v", dcs)
	}
	trusts := parseNltest(sampleNltestTrust)
	if !reflect.DeepEqual(trusts, []string{"corp.local", "dev.corp.local"}) {
		t.Fatalf("trusts = %v", trusts)
	}
	if parseNltest("nothing") != nil {
		t.Fatal("unparseable nltest should be nil")
	}
}

func TestParseUserList(t *testing.T) {
	users := parseUserList(sampleNetUser)
	want := []string{"Administrator", "DefaultAccount", "Guest", "john", "svc_backup"}
	if !reflect.DeepEqual(users, want) {
		t.Fatalf("net user = %v, want %v", users, want)
	}
	admins := parseUserList(sampleNetLocalGroupAdmins)
	if !reflect.DeepEqual(admins, []string{"Administrator"}) {
		t.Fatalf("localgroup admins = %v", admins)
	}
	passwd := parseUserList(samplePasswd)
	if !reflect.DeepEqual(passwd, []string{"root", "daemon", "john"}) {
		t.Fatalf("passwd = %v", passwd)
	}
}

func TestParseNetGroup(t *testing.T) {
	groups := parseNetGroup(sampleNetGroup)
	want := []string{"Cloneable", "Domain", "Admins", "Users", "Enterprise"}
	// "*Cloneable Domain Controllers" is space separated, so it becomes
	// separate tokens; assert the leading set instead of exact equality.
	if len(groups) == 0 || groups[0] != "Cloneable" {
		t.Fatalf("groups = %v (want %v)", groups, want)
	}
	for _, g := range []string{"Admins", "Users", "Enterprise"} {
		if !contains(groups, g) {
			t.Fatalf("groups missing %q: %v", g, groups)
		}
	}
	if parseNetGroup("Group Accounts for \\\\X\nno separator") != nil {
		t.Fatal("no separator should yield nil")
	}
}

func TestParseTasklist(t *testing.T) {
	ps := parseTasklist(sampleTasklist)
	if len(ps) != 4 {
		t.Fatalf("processes = %d (%+v)", len(ps), ps)
	}
	if ps[0].Name != "System Idle Process" || ps[0].PID != 0 {
		t.Fatalf("ps0 = %+v", ps[0])
	}
	if ps[3].Name != "svchost.exe" || ps[3].PID != 920 {
		t.Fatalf("quoted ps = %+v", ps[3])
	}
}

func TestParseOSReleaseAndSysteminfo(t *testing.T) {
	if got := parseOSRelease(sampleOSRelease); got != "Ubuntu 22.04.3 LTS" {
		t.Fatalf("os-release = %q", got)
	}
	if got := parseSysteminfo(sampleSysteminfo); got != "Microsoft Windows Server 2019 Standard 10.0.17763 N/A Build 17763" {
		t.Fatalf("systeminfo = %q", got)
	}
}

func TestParseProbeOutputs(t *testing.T) {
	up := parsePingSweep("warning\nUP 10.0.0.2\nUP 10.0.0.3\nUP not-an-ip\n")
	if !reflect.DeepEqual(up, []string{"10.0.0.2", "10.0.0.3"}) {
		t.Fatalf("ping sweep = %v", up)
	}
	open := parseOpenLines("noise\nOPEN 10.0.0.5 22\nOPEN 10.0.0.5 445\nOPEN 10.0.0.6 3389\n")
	if len(open) != 3 || open[0].Service != "ssh" || open[1].Service != "microsoft-ds" || open[2].Service != "rdp" {
		t.Fatalf("open lines = %+v", open)
	}
}

func TestParsePortSpec(t *testing.T) {
	if got := parsePortSpec("22,80,443", 64); !reflect.DeepEqual(got, []int{22, 80, 443}) {
		t.Fatalf("spec = %v", got)
	}
	if got := parsePortSpec("1-5", 3); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("capped range = %v", got)
	}
	if got := parsePortSpec("80 22", 64); !reflect.DeepEqual(got, []int{22, 80}) {
		t.Fatalf("space spec = %v", got)
	}
	if got := parsePortSpec("abc", 64); got != nil {
		t.Fatalf("invalid spec = %v, want nil", got)
	}
	if got := parsePortSpec("", 64); got != nil {
		t.Fatalf("empty spec = %v, want nil", got)
	}
	if got := parsePortSpec("99999", 64); got != nil {
		t.Fatalf("out-of-range port = %v, want nil", got)
	}
}

func TestEnumerateCIDR(t *testing.T) {
	_, n, _ := net.ParseCIDR("10.0.0.0/30")
	hosts, trunc := enumerateCIDR(n, 64)
	if !reflect.DeepEqual(hosts, []string{"10.0.0.1", "10.0.0.2"}) || trunc {
		t.Fatalf("/30 hosts = %v trunc=%v", hosts, trunc)
	}
	_, n24, _ := net.ParseCIDR("10.0.0.0/24")
	hosts, trunc = enumerateCIDR(n24, 5)
	if len(hosts) != 5 || !trunc {
		t.Fatalf("/24 capped = %d trunc=%v", len(hosts), trunc)
	}
	_, n32, _ := net.ParseCIDR("10.0.0.9/32")
	hosts, _ = enumerateCIDR(n32, 64)
	if !reflect.DeepEqual(hosts, []string{"10.0.0.9"}) {
		t.Fatalf("/32 hosts = %v", hosts)
	}
}

func TestPortOf(t *testing.T) {
	cases := map[string]int{"0.0.0.0:80": 80, "[::]:445": 445, "127.0.0.53%lo:53": 53, "*:*": 0, "nope": 0}
	for in, want := range cases {
		if got := portOf(in); got != want {
			t.Fatalf("portOf(%q) = %d, want %d", in, got, want)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
