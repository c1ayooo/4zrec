package persist

import (
	"strings"
)

// enumCmd is one read-only inspection command for persist_enum.
type enumCmd struct {
	Label   string
	Command string
}

// enumCommands returns the read-only inspection set for a platform.
func enumCommands(platform string) []enumCmd {
	if strings.Contains(platform, "win") {
		return []enumCmd{
			{Label: "schtasks", Command: `schtasks /Query /FO LIST`},
			{Label: "services", Command: `wmic service where "startmode='auto'" get name,pathname,startmode /format:csv`},
			{Label: "run_hkcu", Command: `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"`},
			{Label: "run_hklm", Command: `reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"`},
			{Label: "runonce", Command: `reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"`},
			{Label: "wmi_events", Command: `wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter GET Name`},
			{Label: "wmi_consumers", Command: `wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer GET Name`},
			{Label: "wmi_bindings", Command: `wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding GET Filter,Consumer`},
			{Label: "com_hijack", Command: `reg query "HKCU\Software\Classes\CLSID" /s /f "InprocServer32"`},
		}
	}
	return []enumCmd{
		{Label: "cron_system", Command: "ls -la /etc/cron.d/ 2>/dev/null; cat /etc/crontab 2>/dev/null"},
		{Label: "cron_users", Command: "for u in $(cut -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null; done"},
		{Label: "systemd", Command: "systemctl list-unit-files --type=service --state=enabled 2>/dev/null"},
		{Label: "authorized_keys", Command: "for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f \"$f\" ] && echo \"=== $f ===\" && cat \"$f\"; done 2>/dev/null"},
		{Label: "bashrc", Command: "grep -RniE 'capkit|curl|wget|/tmp/' /root/.bashrc /home/*/.bashrc 2>/dev/null"},
		{Label: "ldpreload", Command: "cat /etc/ld.so.preload 2>/dev/null"},
		{Label: "pam", Command: "grep -Rni 'pam_exec' /etc/pam.d/ 2>/dev/null"},
		{Label: "init_d", Command: "ls -la /etc/init.d/ 2>/dev/null; ls -la /etc/rc*.d/ 2>/dev/null"},
	}
}

// buildSignals turns raw command output into a small normalized signal map.
// It is a minimal heuristic; anything unrecognized is left out (fail-closed).
func buildSignals(platform string, out map[string]string) map[string]any {
	signals := map[string]any{}
	find := func(label, needle string) bool {
		return strings.Contains(strings.ToLower(out[label]), strings.ToLower(needle))
	}
	if strings.Contains(platform, "win") {
		signals["scheduled_tasks"] = countNonEmpty(out["schtasks"])
		signals["autorun_hkcu"] = find("run_hkcu", "")
		signals["autorun_hklm"] = find("run_hklm", "")
		signals["wmi_subscriptions"] = countNonEmpty(out["wmi_events"])
		signals["com_hijack_present"] = strings.Contains(out["com_hijack"], "InprocServer32")
	} else {
		signals["cron_present"] = anyNonEmpty(out["cron_system"], out["cron_users"])
		signals["systemd_enabled"] = countNonEmpty(out["systemd"])
		signals["authorized_keys_present"] = strings.Contains(out["authorized_keys"], "ssh-")
		signals["ld_preload_present"] = strings.TrimSpace(out["ldpreload"]) != ""
		signals["pam_exec_present"] = strings.Contains(out["pam"], "pam_exec")
	}
	return signals
}

func anyNonEmpty(vals ...string) bool {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func countNonEmpty(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
