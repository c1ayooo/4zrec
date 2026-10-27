package av

// cmdOut is one enumeration command's outcome, in the Data payload.
type cmdOut struct {
	Label    string `json:"label"`
	Command  string `json:"command"`
	Output   string `json:"output,omitempty"`
	ExitCode int    `json:"exit_code"`
	OK       bool   `json:"ok"`
}

// enumCmd is a read-only inspection command. All are bounded and non-mutating.
type enumCmd struct {
	Label   string
	Command string
}

// detectCommands returns the read-only enumeration set for a platform. The
// outputs are concatenated and matched against the fingerprint database.
func detectCommands(platform string) []enumCmd {
	if containsWin(platform) {
		return []enumCmd{
			{Label: "processes", Command: `tasklist /fo csv /nh`},
			{Label: "services", Command: `sc query type= service state= all`},
			{Label: "drivers", Command: `driverquery /fo csv /nh`},
			{Label: "security_center", Command: `wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState /format:csv`},
			{Label: "defender_status", Command: `powershell -NoProfile -Command "Get-MpComputerStatus | Select-Object -Property AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled | Format-List"`},
			{Label: "run_keys", Command: `reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" /s 2>nul`},
			{Label: "installed", Command: `wmic product get name,version /format:csv`},
		}
	}
	return []enumCmd{
		{Label: "processes", Command: `ps -eo comm= 2>/dev/null`},
		{Label: "services", Command: `systemctl list-units --type=service --all --no-pager 2>/dev/null || (ls /etc/init.d/ 2>/dev/null; service --status-all 2>/dev/null)`},
		{Label: "modules", Command: `lsmod 2>/dev/null`},
		{Label: "packages", Command: `(dpkg -l 2>/dev/null || rpm -qa 2>/dev/null) | grep -iE 'wazuh|osquery|falco|auditbeat|ossec|aide|trellix|mcafee|falcon|crowdstrike|sentinel|kaspersky|eset|bitdefender|sophos|clamav'`},
		{Label: "files", Command: `ls -d /opt/CrowdStrike /opt/McAfee/agent /var/ossec /etc/osquery /etc/auditbeat /etc/falco /etc/aide.conf /usr/bin/aide 2>/dev/null`},
		{Label: "auditd", Command: `systemctl is-active auditd 2>/dev/null; auditctl -l 2>/dev/null | head -n 40`},
	}
}

func containsWin(platform string) bool { return len(platform) >= 3 && (platform[:3] == "win") }
