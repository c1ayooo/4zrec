package privesc

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// This file holds the pure parsing helpers that turn raw command output into
// normalized structures. Every parser is fail-closed: input that does not match
// a known shape yields empty results rather than a guessed finding. No parser
// touches the network or spawns a process, so all of them are directly testable.

// SudoRule is one command rule from `sudo -l`.
type SudoRule struct {
	RunAs      string `json:"run_as,omitempty"`      // e.g. "ALL" or "root"
	NoPassword bool   `json:"no_password,omitempty"` // NOPASSWD rule
	Command    string `json:"command"`               // e.g. "/usr/bin/find" or "ALL"
}

// sudoRuleRe matches a "who may run what" line, e.g.
//
//	(ALL : ALL) ALL
//	(root) NOPASSWD: /usr/bin/find
//	(root) /usr/bin/less
var sudoRuleRe = regexp.MustCompile(`^\(([^)]*)\)\s*(NOPASSWD:\s*|PASSWD:\s*)?(.+?)\s*$`)

// parseSudoL extracts command rules from `sudo -l` output. Only lines that start
// with a run-as spec "(...)" are considered, so Defaults/secure_path noise is
// ignored.
func parseSudoL(out string) []SudoRule {
	var rules []SudoRule
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if !strings.HasPrefix(t, "(") {
			continue
		}
		m := sudoRuleRe.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		cmd := strings.TrimSpace(m[3])
		if cmd == "" {
			continue
		}
		rules = append(rules, SudoRule{
			RunAs:      normalizeRunAs(m[1]),
			NoPassword: strings.HasPrefix(strings.ToUpper(strings.TrimSpace(m[2])), "NOPASSWD"),
			Command:    cmd,
		})
	}
	return rules
}

// normalizeRunAs collapses "ALL : ALL" / "ALL" / "root" to the primary run-as.
func normalizeRunAs(raw string) string {
	first := raw
	if i := strings.Index(first, ":"); i >= 0 {
		first = first[:i]
	}
	return strings.TrimSpace(first)
}

// parseSUID extracts binary paths from `find / -perm -4000 -type f` output.
// It tolerates both bare path output and `-ls` style columns (path last).
func parseSUID(out string) []string {
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		p := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if p == "" {
			continue
		}
		if strings.ContainsAny(p, " \t") {
			fields := strings.Fields(p)
			p = fields[len(fields)-1]
		}
		if !strings.HasPrefix(p, "/") {
			continue
		}
		paths = append(paths, p)
	}
	return dedupeSorted(paths)
}

// FileCapability is one `getcap` result: a path and its capability tokens.
type FileCapability struct {
	Path string   `json:"path"`
	Caps []string `json:"caps"`
}

// parseCapabilities extracts file capabilities from `getcap -r /` output. It
// handles both the modern `path = cap_x+ep` and the legacy `path cap_x=ep`
// forms.
func parseCapabilities(out string) []FileCapability {
	var res []FileCapability
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if t == "" {
			continue
		}
		var path, capsPart string
		if i := strings.Index(t, " = "); i >= 0 {
			path, capsPart = strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+3:])
		} else {
			f := strings.Fields(t)
			if len(f) < 2 {
				continue
			}
			path, capsPart = f[0], strings.Join(f[1:], " ")
		}
		if !strings.HasPrefix(path, "/") {
			continue
		}
		caps := splitCaps(capsPart)
		if len(caps) == 0 {
			continue
		}
		res = append(res, FileCapability{Path: path, Caps: caps})
	}
	return res
}

// splitCaps normalizes a capability token list into individual tokens. Input may
// use spaces ("cap_a+ep cap_b+ep") or commas ("cap_a,cap_b+ep").
func splitCaps(raw string) []string {
	raw = strings.ReplaceAll(raw, ",", " ")
	var out []string
	for _, tok := range strings.Fields(raw) {
		if strings.HasPrefix(tok, "cap_") {
			out = append(out, tok)
		}
	}
	return out
}

// Privilege is one row from `whoami /priv`.
type Privilege struct {
	Name  string `json:"name"`
	State string `json:"state"` // Enabled | Disabled
}

// parseWhoamiPriv extracts privilege rows from `whoami /priv`. Parsing starts
// after the "====" separator and only accepts rows whose trailing word is
// Enabled/Disabled, so headers and blank lines never produce findings.
func parseWhoamiPriv(out string) []Privilege {
	var res []Privilege
	started := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "===") {
			started = true
			continue
		}
		if !started {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 || !strings.HasPrefix(f[0], "Se") {
			continue
		}
		desc := strings.Join(f[1:], " ")
		switch {
		case strings.HasSuffix(desc, "Enabled"):
			res = append(res, Privilege{Name: f[0], State: "Enabled"})
		case strings.HasSuffix(desc, "Disabled"):
			res = append(res, Privilege{Name: f[0], State: "Disabled"})
		}
	}
	return res
}

// parseWhoamiGroups extracts group names from `whoami /groups`, starting after
// the "====" separator. Only the first column (the group name) is kept.
func parseWhoamiGroups(out string) []string {
	var res []string
	started := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(t, "===") {
			started = true
			continue
		}
		if !started || t == "" {
			continue
		}
		f := strings.Fields(t)
		if len(f) == 0 {
			continue
		}
		res = append(res, f[0])
	}
	return res
}

// versionRe captures the leading dotted numeric version of a string.
var versionRe = regexp.MustCompile(`\d+(?:\.\d+){0,3}`)

// parseKernelVersion extracts a kernel release from `uname -r` or `uname -a`.
// For `uname -a` the release is the third field ("Linux host 5.15.0 ...").
func parseKernelVersion(unameOut string) string {
	fields := strings.Fields(unameOut)
	if len(fields) == 0 {
		return ""
	}
	candidate := fields[0]
	if len(fields) >= 3 && (strings.EqualFold(fields[0], "Linux") || strings.EqualFold(fields[0], "Darwin")) {
		candidate = fields[2]
	}
	if m := versionRe.FindString(candidate); m != "" {
		return m
	}
	return ""
}

// parseOSRelease parses /etc/os-release KEY=value pairs (quotes stripped).
func parseOSRelease(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		i := strings.Index(t, "=")
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(t[:i])
		v := strings.Trim(strings.TrimSpace(t[i+1:]), `"'`)
		if k != "" && v != "" {
			m[k] = v
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// parsePolkitVersion extracts a polkit version from `pkexec --version` output
// ("pkexec version 0.105") or a package version ("0.105-31+deb11u1"). A dotted
// version is preferred over a bare number (e.g. "policykit-1" package names).
func parsePolkitVersion(out string) string {
	all := versionRe.FindAllString(out, -1)
	for _, m := range all {
		if strings.Contains(m, ".") {
			return m
		}
	}
	if len(all) > 0 {
		return all[0]
	}
	return ""
}

// parseSysteminfo parses `systeminfo` "Key: Value" lines into a map. Repeated
// keys keep their first occurrence. The hotfix list ("[01]: KB...") is parsed
// too but harmless.
func parseSysteminfo(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if t == "" {
			continue
		}
		i := strings.Index(t, ":")
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(t[:i])
		v := strings.TrimSpace(t[i+1:])
		if k == "" || v == "" {
			continue
		}
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// AutoLogon is the parsed Winlogon auto-logon configuration.
type AutoLogon struct {
	User        string `json:"user,omitempty"`
	HasPassword bool   `json:"has_password,omitempty"`
}

// parseAutoLogon parses `reg query ...\Winlogon /v DefaultUserName` and
// `/v DefaultPassword` output.
func parseAutoLogon(out string) AutoLogon {
	var a AutoLogon
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimRight(line, "\r"))
		if len(f) < 3 {
			continue
		}
		val := strings.TrimSpace(strings.Join(f[2:], " "))
		switch f[0] {
		case "DefaultUserName":
			a.User = val
		case "DefaultPassword":
			a.HasPassword = val != ""
		}
	}
	return a
}

// parseAlwaysInstallElevated reports whether every AlwaysInstallElevated value
// seen is 0x1. A single 0 value anywhere fails the check closed, and seeing no
// value at all returns false.
func parseAlwaysInstallElevated(out string) bool {
	seen := false
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "AlwaysInstallElevated") {
			continue
		}
		f := strings.Fields(strings.TrimRight(line, "\r"))
		if len(f) == 0 {
			continue
		}
		seen = true
		if f[len(f)-1] != "0x1" {
			return false
		}
	}
	return seen
}

// ServiceConfig is one service row from `wmic service get` output.
type ServiceConfig struct {
	Name      string `json:"name"`
	PathName  string `json:"pathname"`
	StartMode string `json:"start_mode,omitempty"`
	Unquoted  bool   `json:"unquoted,omitempty"`
}

// parseServicePaths parses `wmic service get name,pathname,startmode` output and
// flags unquoted binary paths containing spaces (a service-hijack candidate).
func parseServicePaths(out string) []ServiceConfig {
	var res []ServiceConfig
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if t == "" {
			continue
		}
		low := strings.ToLower(t)
		if strings.HasPrefix(low, "name") && strings.Contains(low, "pathname") {
			continue // header
		}
		f := strings.Fields(t)
		if len(f) < 2 {
			continue
		}
		name := f[0]
		path := strings.Join(f[1:], " ")
		start := ""
		if last := f[len(f)-1]; isStartMode(last) && len(f) >= 3 {
			start = last
			path = strings.Join(f[1:len(f)-1], " ")
		}
		res = append(res, ServiceConfig{
			Name: name, PathName: path, StartMode: start,
			Unquoted: isUnquotedPath(path),
		})
	}
	return res
}

func isStartMode(s string) bool {
	switch s {
	case "Auto", "Manual", "Disabled", "Unknown":
		return true
	}
	return false
}

func isUnquotedPath(path string) bool {
	path = strings.TrimSpace(path)
	return path != "" && !strings.HasPrefix(path, `"`) && strings.Contains(path, " ")
}

// unquotedServicePaths filters parsed services down to the unquoted ones.
func unquotedServicePaths(svcs []ServiceConfig) []ServiceConfig {
	var out []ServiceConfig
	for _, s := range svcs {
		if s.Unquoted {
			out = append(out, s)
		}
	}
	return out
}

// parseTasklist extracts distinct image names from `tasklist` output.
func parseTasklist(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimRight(line, "\r"))
		if len(f) < 2 {
			continue
		}
		if _, err := strconv.Atoi(f[1]); err != nil {
			continue // header / separator: second column is not a PID
		}
		names = append(names, f[0])
	}
	return dedupeSorted(names)
}

// parseWritablePaths keeps paths from `ls -la` / `find -writable` output that
// are writable (others-write or group-write) by the current user.
func parseWritablePaths(out string) []string {
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if t == "" || strings.HasPrefix(t, "total ") {
			continue
		}
		f := strings.Fields(t)
		// `ls -l` rows start with a mode like "-rw-r--r--"; keep only writable
		// ones. `find -writable` rows are bare paths.
		if len(f) >= 1 && len(f[0]) >= 10 && (f[0][0] == '-' || f[0][0] == 'd' || f[0][0] == 'l') {
			if len(f) >= 9 && isWritableMode(f[0]) {
				paths = append(paths, f[len(f)-1])
			}
			continue
		}
		if len(f) == 1 && strings.HasPrefix(t, "/") {
			paths = append(paths, t)
		}
	}
	return dedupeSorted(paths)
}

// parsePasswdWritable reports whether `ls -l /etc/passwd /etc/shadow` shows a
// group/other-writable mode on either file.
func parsePasswdWritable(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if !strings.Contains(t, "/etc/passwd") && !strings.Contains(t, "/etc/shadow") {
			continue
		}
		f := strings.Fields(t)
		if len(f) == 0 {
			continue
		}
		if isWritableMode(f[0]) {
			return true
		}
	}
	return false
}

// isWritableMode reports whether an `ls -l` mode exposes a write for anyone
// other than root-equivalent owner-only (group/other write, or even world-write).
func isWritableMode(mode string) bool {
	if mode == "" {
		return false
	}
	// modes look like -rw-rw-rw-; positions 5 (group w) and 8 (other w).
	r := []rune(mode)
	return len(r) >= 9 && (r[5] == 'w' || r[8] == 'w')
}

// parseNumericVersion turns "5.15.0-91-generic" into [5,15,0].
func parseNumericVersion(v string) []int {
	m := versionRe.FindString(v)
	if m == "" {
		return nil
	}
	parts := strings.Split(m, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// cmpVersion compares two numeric version slices element-wise, treating a
// missing trailing element as 0.
func cmpVersion(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// compareKernelRange reports whether version is in [min, max). Unparseable input
// returns false (fail closed).
func compareKernelRange(version, min, max string) bool {
	v := parseNumericVersion(version)
	lo := parseNumericVersion(min)
	hi := parseNumericVersion(max)
	if len(v) == 0 || len(lo) == 0 || len(hi) == 0 {
		return false
	}
	return cmpVersion(v, lo) >= 0 && cmpVersion(v, hi) < 0
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
