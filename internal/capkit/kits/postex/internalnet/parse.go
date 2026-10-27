package internalnet

import (
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// This file holds the pure output parsers for internalnetkit. Every parser is a
// pure function of command stdout: it never performs I/O and never touches the
// network. They fail closed — an unparseable or empty input yields an empty
// slice, never a panic and never a fabricated entry.

// ---- data shapes emitted by the tools ----

// NetInterface is one local network interface (linux `ip addr`, windows
// `ipconfig /all`).
type NetInterface struct {
	Name  string   `json:"name,omitempty"`
	MAC   string   `json:"mac,omitempty"`
	IPv4  []string `json:"ipv4,omitempty"`
	IPv6  []string `json:"ipv6,omitempty"`
	Mask  string   `json:"mask,omitempty"`
	State string   `json:"state,omitempty"`
}

// ARPEntry is one neighbour-cache entry (linux `arp -a`, windows `arp -a`).
type ARPEntry struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac,omitempty"`
	Iface string `json:"iface,omitempty"`
	Type  string `json:"type,omitempty"`
}

// Route is one routing-table entry (linux `ip route`, windows `route print`).
type Route struct {
	Dest    string `json:"dest"`
	Gateway string `json:"gateway,omitempty"`
	Iface   string `json:"iface,omitempty"`
	Metric  string `json:"metric,omitempty"`
}

// Listener is one listening socket (linux `ss -tunlp`, windows `netstat -ano`).
type Listener struct {
	Proto   string `json:"proto,omitempty"`
	Local   string `json:"local,omitempty"`
	Port    int    `json:"port,omitempty"`
	State   string `json:"state,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

// Share is one SMB share (windows `net share`/`net view`, linux `smbclient -L`).
type Share struct {
	Name    string `json:"name"`
	Type    string `json:"type,omitempty"`
	Comment string `json:"comment,omitempty"`
	Access  string `json:"access,omitempty"`
}

// Process is one running process (windows `tasklist`).
type Process struct {
	Name string `json:"name"`
	PID  int    `json:"pid,omitempty"`
}

// Ipconfig is a parsed windows `ipconfig /all`.
type Ipconfig struct {
	Hostname string    `json:"hostname,omitempty"`
	Domain   string    `json:"domain,omitempty"`
	Adapters []Adapter `json:"adapters,omitempty"`
}

// Adapter is one windows network adapter.
type Adapter struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	IPv4        []string `json:"ipv4,omitempty"`
	Mask        string   `json:"mask,omitempty"`
	Gateway     string   `json:"gateway,omitempty"`
	DNS         []string `json:"dns,omitempty"`
	DHCP        bool     `json:"dhcp,omitempty"`
}

// ---- bounded list helper (Data is further clamped by core.ClampData) ----

const parseListCap = 512

func capStrings[T any](in []T) []T {
	if len(in) > parseListCap {
		return in[:parseListCap]
	}
	return in
}

// ---- linux: ip addr ----

var (
	reIfLine = regexp.MustCompile(`^\d+:\s+([^\s:]+)(?::|\s)`)
	reMAC    = regexp.MustCompile(`link/ether\s+([0-9a-fA-F:]{17})`)
	reInet4  = regexp.MustCompile(`inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)`)
	reInet6  = regexp.MustCompile(`inet6\s+([0-9a-fA-F:]+/[0-9]+)`)
	reState  = regexp.MustCompile(`\bstate\s+(\S+)`)
)

// parseIPAddr parses `ip addr` (and `ip -o addr`) into interfaces. Lines that
// do not match any known form are skipped; an unknown input yields nil.
func parseIPAddr(stdout string) []NetInterface {
	var out []NetInterface
	cur := -1
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if m := reIfLine.FindStringSubmatch(line); m != nil {
			name := strings.TrimSuffix(m[1], "@")
			out = append(out, NetInterface{Name: name})
			cur = len(out) - 1
		}
		if cur < 0 {
			continue
		}
		if m := reMAC.FindStringSubmatch(line); m != nil && out[cur].MAC == "" {
			out[cur].MAC = m[1]
		}
		for _, m := range reInet4.FindAllStringSubmatch(line, -1) {
			out[cur].IPv4 = append(out[cur].IPv4, m[1])
		}
		for _, m := range reInet6.FindAllStringSubmatch(line, -1) {
			addr := m[1]
			if i := strings.IndexByte(addr, '%'); i >= 0 { // strip zone id
				addr = addr[:i]
			}
			out[cur].IPv6 = append(out[cur].IPv6, addr)
		}
		if m := reState.FindStringSubmatch(line); m != nil && out[cur].State == "" {
			out[cur].State = m[1]
		}
	}
	return out
}

// ---- arp -a (linux and windows) ----

var (
	reARPLinux  = regexp.MustCompile(`^(\S+)\s+\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)\s+at\s+([0-9a-fA-F:.]+|<incomplete>)(?:\s+\[(\w+)\])?(?:\s+on\s+(\S+))?`)
	reARPWin    = regexp.MustCompile(`^\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F-]{11,17})\s+(\w+)`)
	reARPWinHdr = regexp.MustCompile(`(?i)^\s*(interface|internet address)\b`)
)

// parseARP parses both the linux `arp -a` (`host (ip) at mac [ether] on if`)
// and windows `arp -a` (`ip  mac  type`) forms.
func parseARP(stdout string) []ARPEntry {
	var out []ARPEntry
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if strings.TrimSpace(line) == "" || reARPWinHdr.MatchString(line) {
			continue
		}
		if m := reARPLinux.FindStringSubmatch(line); m != nil {
			mac := m[3]
			if strings.EqualFold(mac, "<incomplete>") {
				mac = ""
			}
			out = append(out, ARPEntry{IP: m[2], MAC: mac, Type: m[4], Iface: m[5]})
			continue
		}
		if m := reARPWin.FindStringSubmatch(line); m != nil {
			out = append(out, ARPEntry{
				IP:   m[1],
				MAC:  strings.ToLower(strings.ReplaceAll(m[2], "-", ":")),
				Type: strings.ToLower(m[3]),
			})
		}
	}
	return out
}

// ---- ip route / route print ----

var reIPRoute = regexp.MustCompile(`^\d+\.\d+`)

// parseRoutes parses linux `ip route` output. Unrecognized lines are skipped.
func parseRoutes(stdout string) []Route {
	var out []Route
	for _, raw := range strings.Split(stdout, "\n") {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) == 0 {
			continue
		}
		isDefault := fields[0] == "default"
		if !isDefault && (fields[0] == "local" || !reIPRoute.MatchString(fields[0])) {
			continue
		}
		rt := Route{Dest: fields[0]}
		if isDefault {
			rt.Dest = "0.0.0.0/0"
		}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "via":
				if i+1 < len(fields) {
					rt.Gateway = fields[i+1]
				}
			case "dev":
				if i+1 < len(fields) {
					rt.Iface = fields[i+1]
				}
			case "metric":
				if i+1 < len(fields) {
					rt.Metric = fields[i+1]
				}
			}
		}
		out = append(out, rt)
	}
	return out
}

var (
	reRoutePrintHdr = regexp.MustCompile(`(?i)^\s*(network destination|active routes|interface list|ipv4 route table|persistent routes|metric)`)
	reRoutePrintSep = regexp.MustCompile(`^[=\-]{4,}`)
	reRoutePrintRow = regexp.MustCompile(`^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+(\S+)\s+(\S+)\s+(\d+)`)
)

// parseRoutePrint parses windows `route print` active-route rows.
func parseRoutePrint(stdout string) []Route {
	var out []Route
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if reRoutePrintHdr.MatchString(line) || reRoutePrintSep.MatchString(strings.TrimSpace(line)) {
			continue
		}
		m := reRoutePrintRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		gw := m[3]
		if strings.EqualFold(gw, "On-link") {
			gw = ""
		}
		dest := m[1] + "/" + m[2]
		if m[1] == "0.0.0.0" && m[2] == "0.0.0.0" {
			dest = "0.0.0.0/0"
		}
		out = append(out, Route{Dest: dest, Gateway: gw, Iface: m[4], Metric: m[5]})
	}
	return out
}

// ---- ss -tunlp / netstat -ano ----

var reSSLine = regexp.MustCompile(`^(tcp|udp|tcp6|udp6)\s+(LISTEN|UNCONN|ESTAB|SYN-SENT)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+users:\(\((?:"([^"]+)",)?pid=(\d+))?`)

// parseSsListeners parses linux `ss -tunlp`. Only listening TCP and bound UDP
// sockets are reported; an unparseable line is skipped (fail closed).
func parseSsListeners(stdout string) []Listener {
	var out []Listener
	for _, raw := range strings.Split(stdout, "\n") {
		m := reSSLine.FindStringSubmatch(strings.TrimRight(raw, " \t\r"))
		if m == nil {
			continue
		}
		state := m[2]
		if !strings.EqualFold(state, "LISTEN") && !strings.EqualFold(state, "UNCONN") {
			continue
		}
		l := Listener{
			Proto:   m[1],
			Local:   m[3],
			Port:    portOf(m[3]),
			State:   state,
			Process: m[5],
		}
		if m[6] != "" {
			l.PID, _ = strconv.Atoi(m[6])
		}
		out = append(out, l)
	}
	return out
}

var (
	reNetstatHdr = regexp.MustCompile(`(?i)^\s*(proto|active connections|tcp\s+udp)\b`)
	reNetstatRow = regexp.MustCompile(`^\s*(TCP|UDP)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s+(\d+)\s*$`)
)

// parseNetstat parses windows `netstat -ano`. TCP rows are kept only when
// LISTENING (this is a listener survey); all UDP rows are the process's binds.
func parseNetstat(stdout string) []Listener {
	var out []Listener
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if reNetstatHdr.MatchString(line) {
			continue
		}
		m := reNetstatRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		proto := strings.ToLower(m[1])
		state := strings.ToUpper(m[4])
		if proto == "tcp" && state != "LISTENING" {
			continue
		}
		l := Listener{Proto: proto, Local: m[2], Port: portOf(m[2]), State: state}
		l.PID, _ = strconv.Atoi(m[5])
		out = append(out, l)
	}
	return out
}

// portOf extracts the trailing port from an address such as `0.0.0.0:80`,
// `[::]:445`, `127.0.0.53%lo:53` or `*:*`. Returns 0 when no port is present.
func portOf(addr string) int {
	addr = strings.TrimSpace(addr)
	if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		p := addr[i+1:]
		if p == "" || p == "*" {
			return 0
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

// ---- windows ipconfig / all ----

var (
	reIpconfigKVs = regexp.MustCompile(`^\s+([A-Za-z][^:]*?)\s*(?:\.\s*){2,}:\s*(.*)$`)
	reBareIPv4    = regexp.MustCompile(`^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*$`)
)

// parseIpconfig parses windows `ipconfig /all` into adapters plus the global
// host name and primary DNS suffix.
func parseIpconfig(stdout string) Ipconfig {
	var cfg Ipconfig
	adapter := -1
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, "adapter") ||
			(strings.Contains(trimmed, " adapter ") && strings.HasSuffix(trimmed, ":")) {
			name := trimmed
			if i := strings.LastIndex(name, " adapter "); i >= 0 {
				name = name[i+len(" adapter "):]
			} else if strings.HasSuffix(name, " adapter") {
				name = strings.TrimSuffix(name, " adapter")
			}
			name = strings.TrimSuffix(strings.TrimSpace(name), ":")
			cfg.Adapters = append(cfg.Adapters, Adapter{Name: name})
			adapter = len(cfg.Adapters) - 1
			continue
		}
		if m := reIpconfigKVs.FindStringSubmatch(line); m != nil {
			key := strings.ToLower(strings.TrimSpace(m[1]))
			val := strings.TrimSpace(m[2])
			switch key {
			case "host name":
				cfg.Hostname = val
			case "primary dns suffix":
				cfg.Domain = val
			case "connection-specific dns suffix":
				if adapter >= 0 && cfg.Adapters[adapter].Name == "" {
					cfg.Adapters[adapter].Name = val
				}
			default:
				if adapter < 0 {
					continue
				}
				a := &cfg.Adapters[adapter]
				switch key {
				case "description":
					a.Description = val
				case "physical address":
					a.MAC = strings.ToLower(strings.ReplaceAll(val, "-", ":"))
				case "ipv4 address":
					if ip := stripParen(val); ip != "" {
						a.IPv4 = append(a.IPv4, ip)
					}
				case "subnet mask", "ipv4 subnet mask":
					a.Mask = val
				case "default gateway":
					if val != "" {
						a.Gateway = val
					}
				case "dns servers":
					if val != "" {
						a.DNS = append(a.DNS, val)
					}
				case "dhcp enabled":
					a.DHCP = strings.HasPrefix(strings.ToLower(val), "yes")
				}
			}
			continue
		}
		// Continuation lines: ipconfig prints a bare address under the previous
		// key when a value list spans lines (extra gateways/DNS servers).
		if adapter >= 0 {
			if m := reBareIPv4.FindStringSubmatch(line); m != nil {
				a := &cfg.Adapters[adapter]
				if a.Gateway == "" {
					a.Gateway = m[1]
				} else {
					a.DNS = append(a.DNS, m[1])
				}
			}
		}
	}
	return cfg
}

func stripParen(s string) string {
	if i := strings.IndexByte(s, '('); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// ---- users / groups ----

var reSeparator = regexp.MustCompile(`^[-=]{4,}`)

// parseUserList parses `net user` / `net user /domain` / `net localgroup`
// output (a whitespace table) and `cat /etc/passwd` (colon-separated). Only
// rows below the header separator are collected, so free-text lines such as
// `Comment ...` cannot inject bogus accounts. Group entries prefixed with
// `*` are stripped. Fail closed on empty input.
func parseUserList(stdout string) []string {
	var out []string
	seen := map[string]bool{}
	afterSep := false
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if reSeparator.MatchString(line) {
			afterSep = true
			continue
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "user accounts for") || strings.HasPrefix(low, "the command completed") ||
			strings.HasPrefix(low, "group accounts for") || strings.HasPrefix(low, "alias name") ||
			strings.HasPrefix(low, "comment ") || low == "members" || low == "comment" {
			continue
		}
		if strings.Count(line, ":") >= 6 { // /etc/passwd (no separator)
			name := strings.TrimSpace(strings.SplitN(line, ":", 2)[0])
			if validAccount(name) && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
			continue
		}
		if !afterSep {
			continue
		}
		// A domain-qualified principal (`CORP\Domain Admins`) is not a valid
		// local account; skip the line so its tail (`Admins`) cannot be
		// collected as a fabricated account.
		if strings.Contains(line, `\`) {
			continue
		}
		for _, tok := range strings.Fields(line) {
			name := strings.TrimPrefix(tok, "*")
			if validAccount(name) && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return capStrings(out)
}

func validAccount(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '_' || r == '-' || r == '.' || r == '$') {
			return false
		}
	}
	return true
}

// parseNetGroup parses `net group /domain`; rows are only read below the
// separator and group names are unstarred.
func parseNetGroup(stdout string) []string {
	var out []string
	seen := map[string]bool{}
	afterSep := false
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if reSeparator.MatchString(line) {
			afterSep = true
			continue
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "group accounts for") || strings.HasPrefix(low, "the command completed") ||
			strings.HasPrefix(low, "comment ") {
			continue
		}
		if !afterSep {
			continue
		}
		for _, tok := range strings.Fields(line) {
			name := strings.TrimPrefix(tok, "*")
			if validAccount(name) && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return capStrings(out)
}

// ---- net view / net share / smbclient -L ----

var (
	reNetViewTitle = regexp.MustCompile(`(?i)^(share name|sharename)\b`)
	reNetViewLine  = regexp.MustCompile(`^\s*(\S+)\s+(\S+)(?:\s+(.*?))?\s*$`)
)

// parseNetView parses `net view \\host`, `net share` and `smbclient -L` share
// tables into shares. Rows are only collected after the header separator, so
// banner text before the table cannot leak in as a share. An unrecognized
// layout yields nil (fail closed).
func parseNetView(stdout string) []Share {
	var out []Share
	afterSep := false
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if reSeparator.MatchString(trimmed) {
			afterSep = true
			continue
		}
		low := strings.ToLower(trimmed)
		if strings.HasPrefix(low, "the command completed") ||
			strings.HasPrefix(low, "server name") || strings.HasPrefix(low, "smb1 disabled") ||
			strings.HasPrefix(low, "enetering") || strings.HasPrefix(low, "error") ||
			strings.HasPrefix(low, "do you want") {
			continue
		}
		if !afterSep {
			continue
		}
		m := reNetViewLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		if strings.HasPrefix(name, "\\") || !validShareName(name) {
			continue
		}
		out = append(out, Share{
			Name:    name,
			Type:    m[2],
			Comment: strings.TrimSpace(m[3]),
			Access:  accessHint(name),
		})
	}
	return out
}

func validShareName(name string) bool {
	if name == "" || len(name) > 80 {
		return false
	}
	if strings.EqualFold(name, "sharename") || strings.EqualFold(name, "share") {
		return false
	}
	for _, r := range name {
		if r == '\\' || r == '/' || r == ' ' || r == '[' || r == ']' || r == '=' ||
			r == ':' || r == ',' || r == ';' || r == '"' {
			return false
		}
	}
	return true
}

// accessHint classifies well-known administrative shares.
func accessHint(name string) string {
	up := strings.ToUpper(strings.TrimPrefix(name, "\\\\"))
	switch {
	case up == "IPC$":
		return "ipc"
	case strings.HasSuffix(up, "$"):
		return "admin"
	default:
		return "unknown"
	}
}

// ---- nltest ----

var (
	reNltestDC    = regexp.MustCompile(`^\s+(\S+\.\S+)\s+\[`)
	reNltestTrust = regexp.MustCompile(`^\s*\d+:\s+(\S+)\s+(\S+)`)
)

// parseNltest extracts domain controllers (`nltest /dclist:<domain>`) and
// domain trusts (`nltest /domain_trusts`) as flat names.
func parseNltest(stdout string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if strings.Contains(strings.ToLower(line), "the command completed") {
			continue
		}
		if m := reNltestTrust.FindStringSubmatch(line); m != nil {
			add(m[2])
			continue
		}
		if m := reNltestDC.FindStringSubmatch(line); m != nil {
			add(m[1])
		}
	}
	return capStrings(out)
}

// ---- logins ----

// parseLogins normalizes `who`, `w` and `last` output into bounded lines.
func parseLogins(stdout string) []string {
	var out []string
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "wtmp begins") {
			continue
		}
		out = append(out, line)
	}
	return capStrings(out)
}

// ---- tasklist ----

// reTasklistRow: name, then a 2+ space column gap, then the pid, then a gap.
// tasklist pads with 3 spaces by default; a 2-space floor keeps it tolerant.
var reTasklistRow = regexp.MustCompile(`^\s*(.*?\S)\s{2,}(\d+)(?:\s|$)`)

// parseTasklist parses windows `tasklist` table rows into (name, pid). Column
// alignment is whitespace-run based, matching the real output layout.
func parseTasklist(stdout string) []Process {
	var out []Process
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		low := strings.ToLower(trimmed)
		if strings.HasPrefix(low, "image name") || strings.HasPrefix(low, "=") {
			continue
		}
		// name <2+ spaces> pid <2+ spaces> session ...
		m := reTasklistRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pid, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		name := strings.Trim(strings.TrimSpace(m[1]), `"`)
		if name == "" {
			continue
		}
		out = append(out, Process{Name: name, PID: pid})
	}
	return capStrings(out)
}

// ---- os-release ----

// parseOSRelease returns the PRETTY_NAME (or NAME) from /etc/os-release,
// or "" when the file is absent/unparseable.
func parseOSRelease(stdout string) string {
	var name string
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "PRETTY_NAME":
			return v
		case "NAME":
			name = v
		}
	}
	return name
}

// parseSysteminfo pulls the OS name/version out of windows `systeminfo`.
func parseSysteminfo(stdout string) string {
	var name, version string
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "OS Name":
			name = strings.TrimSpace(v)
		case "OS Version":
			version = strings.TrimSpace(v)
		}
	}
	switch {
	case name != "" && version != "":
		return name + " " + version
	default:
		return name
	}
}

// ---- probe output (ping sweep / port scan emitted by the session shell) ----

// parsePingSweep extracts live hosts from `UP <host>` markers emitted by the
// discovery loop command.
func parsePingSweep(stdout string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(stdout, "\n") {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) < 2 || !strings.EqualFold(fields[0], "UP") {
			continue
		}
		h := fields[1]
		if net.ParseIP(h) != nil && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return capStrings(out)
}

// parseOpenLines extracts `<host> <port>` hits from `OPEN <host> <port>`
// markers emitted by the port-scan loop command.
func parseOpenLines(stdout string) []OpenPort {
	var out []OpenPort
	seen := map[string]bool{}
	for _, raw := range strings.Split(stdout, "\n") {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) < 3 || !strings.EqualFold(fields[0], "OPEN") {
			continue
		}
		port, err := strconv.Atoi(fields[2])
		if err != nil || net.ParseIP(fields[1]) == nil {
			continue
		}
		key := fields[1] + ":" + fields[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, OpenPort{Host: fields[1], Port: port, Service: serviceForPort(port)})
	}
	return capStrings(out)
}

// OpenPort is one open port discovered through the foothold.
type OpenPort struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// ---- CIDR / port-spec helpers ----

// enumerateCIDR lists the usable host addresses of an IPv4 network, capped at
// max. The bool reports whether the list was truncated by the cap. Non-IPv4
// networks yield nil.
func enumerateCIDR(n *net.IPNet, max int) ([]string, bool) {
	ip := n.IP.To4()
	if ip == nil {
		return nil, false
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil, false
	}
	if max <= 0 {
		max = 1
	}
	base := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	hostBits := 32 - ones
	var total uint64 = 1 << uint(hostBits)
	first, last := base, base+uint32(total)-1
	// Trim network and broadcast for prefixes shorter than /31.
	if hostBits >= 2 {
		first++
		last--
	}
	var out []string
	truncated := false
	for cur := uint64(first); cur <= uint64(last); cur++ {
		if len(out) >= max {
			truncated = true
			break
		}
		o := byte(cur >> 24)
		t := byte(cur >> 16)
		h := byte(cur >> 8)
		l := byte(cur)
		out = append(out, net.IPv4(o, t, h, l).String())
	}
	return out, truncated
}

// ipInNet reports whether ipStr falls inside n.
func ipInNet(ipStr string, n *net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && n.Contains(ip)
}

// parsePortSpec parses "22,80,443" / "1-1024" / "22 80" into a sorted unique
// port list capped at max. Invalid tokens are dropped; an empty/invalid spec
// yields nil (fail closed).
func parsePortSpec(spec string, max int) []int {
	if max <= 0 {
		max = 1
	}
	set := map[int]bool{}
	add := func(p int) {
		if p >= 1 && p <= 65535 && len(set) < max {
			set[p] = true
		}
	}
	for _, tok := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if tok == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(tok, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || a > b {
				continue
			}
			for p := a; p <= b && len(set) < max; p++ {
				add(p)
			}
			continue
		}
		if p, err := strconv.Atoi(tok); err == nil {
			add(p)
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// commonServices maps well-known ports to a service label.
var commonServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
	443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s", 1433: "mssql",
	1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
	5900: "vnc", 5985: "winrm", 5986: "winrm-ssl", 6379: "redis", 8080: "http-proxy",
	8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

// serviceForPort returns the well-known service label, or "" when unknown.
func serviceForPort(port int) string { return commonServices[port] }
