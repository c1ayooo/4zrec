package container

import (
	"sort"
	"strings"
)

// EscapeCheck is one in-container escape-surface probe. Every command is a
// bounded, read-only test that prints exactly one verdict line: "ok <id>" when
// the primitive exists, "no <id>" when it does not. Nothing is written or
// downloaded; the test only checks whether a primitive is reachable.
type EscapeCheck struct {
	// ID is the stable parser key and the field name in EscapeSurface.
	ID string `json:"id"`
	// Path is the filesystem or kernel object the check touches.
	Path string `json:"path"`
	// Command is run through core.Session.Exec.
	Command string `json:"command"`
	// Why explains what a positive result means for escape triage.
	Why string `json:"why"`
}

// EscapeChecks is the bounded read-only in-container check list. container_
// escape_check runs each command through a Session and parses the "ok <id>" /
// "no <id>" lines. It is a documented package var so hosts can render it,
// redact it, or replace it with their own allowlist; the parser keys off IDs,
// never list order.
var EscapeChecks = []EscapeCheck{
	{
		ID:      "docker_sock",
		Path:    "/var/run/docker.sock",
		Command: `[ -w /var/run/docker.sock ] && echo "ok docker_sock" || echo "no docker_sock"`,
		Why:     "a writable docker.sock talks to the host daemon, enabling privileged container creation",
	},
	{
		ID:      "docker_sock_mounted",
		Path:    "/proc/mounts",
		Command: `grep -q 'docker.sock' /proc/mounts 2>/dev/null && echo "ok docker_sock_mounted" || echo "no docker_sock_mounted"`,
		Why:     "the socket is bind-mounted from the host, so daemon reachability is local, not network",
	},
	{
		ID:      "privileged",
		Path:    "/proc/self/status",
		Command: `[ "$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null)" = "0000003fffffffff" ] && echo "ok privileged" || echo "no privileged"`,
		Why:     "a full effective capability set is a privileged container; host devices and kernel surfaces are reachable",
	},
	{
		ID:      "cap_sys_admin",
		Path:    "/proc/self/status",
		Command: `[ $(( 0x$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null) & (1<<21) )) -ne 0 ] && echo "ok cap_sys_admin" || echo "no cap_sys_admin"`,
		Why:     "CAP_SYS_ADMIN allows mount(), the most direct host-filesystem primitive",
	},
	{
		ID:      "cap_dac_read_search",
		Path:    "/proc/self/status",
		Command: `[ $(( 0x$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null) & (1<<2) )) -ne 0 ] && echo "ok cap_dac_read_search" || echo "no cap_dac_read_search"`,
		Why:     "CAP_DAC_READ_SEARCH bypasses read permission checks, exposing host files through mounted volumes",
	},
	{
		ID:      "cgroup_release_agent_writable",
		Path:    "/sys/fs/cgroup/**/release_agent",
		Command: `find /sys/fs/cgroup -maxdepth 2 -name release_agent -writable 2>/dev/null | grep -q . && echo "ok cgroup_release_agent_writable" || echo "no cgroup_release_agent_writable"`,
		Why:     "a writable cgroup release_agent executes a host-path script on release (cgroup v1 escape)",
	},
	{
		ID:      "core_pattern_writable",
		Path:    "/proc/sys/kernel/core_pattern",
		Command: `[ -w /proc/sys/kernel/core_pattern ] && echo "ok core_pattern_writable" || echo "no core_pattern_writable"`,
		Why:     "a writable core_pattern makes the host kernel run an arbitrary command as root on the next crash",
	},
	{
		ID:      "host_pid_namespace",
		Path:    "/proc/1/cgroup",
		Command: `grep -qE '(docker|kubepods|containerd|lxc|libpod)' /proc/1/cgroup 2>/dev/null && echo "no host_pid_namespace" || echo "ok host_pid_namespace"`,
		Why:     "PID 1 outside a container cgroup means the host PID namespace is shared",
	},
	{
		ID:      "host_devices",
		Path:    "/dev",
		Command: `ls -1 /dev 2>/dev/null | grep -qE '^(sd[a-z][0-9]*|vd[a-z][0-9]*|nvme[0-9]+n[0-9]+)$' && echo "ok host_devices" || echo "no host_devices"`,
		Why:     "raw host block devices are visible, so direct reads/writes of a mounted disk are possible",
	},
	{
		ID:      "proc_sys_writable",
		Path:    "/proc/sys/kernel/ns_last_pid",
		Command: `[ -w /proc/sys/kernel/ns_last_pid ] && echo "ok proc_sys_writable" || echo "no proc_sys_writable"`,
		Why:     "writable /proc/sys entries show kernel sysctls are not read-only, widening the escape surface",
	},
}

// escapeCheckByID indexes EscapeChecks by ID for verdict enrichment.
func escapeCheckByID() map[string]EscapeCheck {
	out := make(map[string]EscapeCheck, len(EscapeChecks))
	for _, c := range EscapeChecks {
		out[c.ID] = c
	}
	return out
}

// EscapeFinding is the parsed verdict of one EscapeCheck: a positive hit plus
// the human-readable reason for why it matters.
type EscapeFinding struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Hit    bool   `json:"hit"`
	Detail string `json:"detail,omitempty"`
	Why    string `json:"why,omitempty"`
}

// parseEscapeChecks turns combined session stdout containing "ok <id>" /
// "no <id>" lines into findings, in the declared EscapeChecks order. Unknown
// IDs and malformed lines are ignored.
//
// Matching is anchored to the start of a line so a "no <id>" verdict can never
// be mistaken for a substring of another verdict (IDs share prefixes, e.g.
// "cap_sys_admin" inside "cap_sys_admin_extra").
func parseEscapeChecks(out string) []EscapeFinding {
	verdict := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ok "):
			if id := strings.TrimSpace(strings.TrimPrefix(line, "ok ")); id != "" {
				verdict[id] = true
			}
		case strings.HasPrefix(line, "no "):
			if id := strings.TrimSpace(strings.TrimPrefix(line, "no ")); id != "" {
				verdict[id] = false
			}
		}
	}
	byID := escapeCheckByID()
	var findings []EscapeFinding
	for _, c := range EscapeChecks {
		hit, ran := verdict[c.ID]
		if !ran {
			continue
		}
		findings = append(findings, EscapeFinding{
			ID: c.ID, Path: c.Path, Hit: hit, Why: byID[c.ID].Why,
		})
	}
	return findings
}

// escapeSurfaceFromFindings folds parsed findings into the boolean surface that
// container_escape_plan consumes. Capabilities are listed in a stable order.
func escapeSurfaceFromFindings(surface *EscapeSurface, findings []EscapeFinding) {
	for _, f := range findings {
		switch f.ID {
		case "docker_sock":
			surface.DockerSock = f.Hit
		case "docker_sock_mounted":
			surface.DockerSockMounted = f.Hit
		case "privileged":
			surface.Privileged = f.Hit
		case "cap_sys_admin":
			surface.CapSysAdmin = f.Hit
		case "cap_dac_read_search":
			surface.CapDacReadSearch = f.Hit
		case "cgroup_release_agent_writable":
			surface.ReleaseAgentWritable = f.Hit
		case "core_pattern_writable":
			surface.CorePatternWritable = f.Hit
		case "host_pid_namespace":
			surface.HostPID = f.Hit
		case "host_devices":
			surface.HostDevices = f.Hit
		case "proc_sys_writable":
			surface.ProcSysWritable = f.Hit
		}
	}
	var caps []string
	if surface.CapSysAdmin {
		caps = append(caps, "cap_sys_admin")
	}
	if surface.CapDacReadSearch {
		caps = append(caps, "cap_dac_read_search")
	}
	sort.Strings(caps)
	surface.Capabilities = caps
}
