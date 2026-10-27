package privesc

import (
	"context"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Platform selectors for privesc_enum / platform-pinned variants.
const (
	platformAuto    = "auto"
	platformLinux   = "linux"
	platformWindows = "windows"
)

// Bounds applied to every enumeration command. They are deliberately small: the
// enumeration must never hang a session or flood Data. The read-only command set
// itself is declared below so it is auditable in one place.
const (
	enumTimeout   = 20 * time.Second
	enumMaxOutput = 256 << 10 // 256 KiB per command
)

// enumCommand is one bounded, read-only enumeration command.
type enumCommand struct {
	Key     string
	Command string
}

// linuxEnumCommands is the Linux privilege-escalation enumeration set. Every
// command is read-only. `sudo -n -l` is used instead of `sudo -l` so it can never
// block on a password prompt (boundedness).
var linuxEnumCommands = []enumCommand{
	{Key: "uname", Command: "uname -a"},
	{Key: "os_release", Command: "cat /etc/os-release 2>/dev/null"},
	{Key: "kernel_version", Command: "uname -r"},
	{Key: "id", Command: "id"},
	{Key: "sudo_l", Command: "sudo -n -l 2>/dev/null"},
	{Key: "suid", Command: "find / -xdev -perm -4000 -type f 2>/dev/null"},
	{Key: "capabilities", Command: "getcap -r / 2>/dev/null"},
	{Key: "polkit_version", Command: "pkexec --version 2>/dev/null || dpkg-query -W -f='${Version}' policykit-1 2>/dev/null || rpm -q --qf '%{VERSION}\\n' polkit 2>/dev/null"},
	{Key: "writable_paths", Command: "find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/systemd/system /lib/systemd/system /etc/crontab -writable 2>/dev/null"},
	{Key: "passwd_writable", Command: "ls -l /etc/passwd /etc/shadow 2>/dev/null"},
}

// windowsEnumCommands is the Windows enumeration set, likewise read-only. Service
// binary paths are collected with `wmic service get name,pathname,startmode`
// (the enumeration-capable form of `sc qc <service>`); `sc query` lists services
// even when wmic is unavailable.
var windowsEnumCommands = []enumCommand{
	{Key: "whoami", Command: "whoami"},
	{Key: "whoami_priv", Command: "whoami /priv"},
	{Key: "whoami_groups", Command: "whoami /groups"},
	{Key: "systeminfo", Command: "systeminfo"},
	{Key: "services", Command: "sc query type= service state= all"},
	{Key: "service_paths", Command: "wmic service get name,pathname,startmode 2>nul"},
	{Key: "tasklist", Command: "tasklist"},
	{Key: "always_install_elevated", Command: `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated & reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated`},
	{Key: "autologon", Command: `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName & reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword`},
}

// commandOutcome records what one enumeration command returned, without the body
// (bodies would blow the 8KB Data budget).
type commandOutcome struct {
	Key       string `json:"key"`
	Command   string `json:"command"`
	ExitCode  int    `json:"exit_code"`
	Bytes     int    `json:"bytes,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Signals is the normalized, structured result of enumeration. It is embedded in
// enumResult.Data and is the exact input privesc_advise consumes, so an enum
// result can be passed through unchanged (no re-execution needed).
type Signals struct {
	Platform              string            `json:"platform"`
	Kernel                string            `json:"kernel,omitempty"`
	OSInfo                map[string]string `json:"os_info,omitempty"`
	SudoRules             []SudoRule        `json:"sudo_rules,omitempty"`
	SUIDBinaries          []string          `json:"suid_binaries,omitempty"`
	Capabilities          []FileCapability  `json:"capabilities,omitempty"`
	PolkitVersion         string            `json:"polkit_version,omitempty"`
	WritablePaths         []string          `json:"writable_paths,omitempty"`
	PasswdWritable        bool              `json:"passwd_writable,omitempty"`
	WhoamiPrivileges      []Privilege       `json:"whoami_privileges,omitempty"`
	Groups                []string          `json:"groups,omitempty"`
	Services              []ServiceConfig   `json:"services,omitempty"`
	Processes             []string          `json:"processes,omitempty"`
	AlwaysInstallElevated bool              `json:"always_install_elevated,omitempty"`
	AutoLogon             AutoLogon         `json:"autologon,omitempty"`
}

// enumResult is the Data payload of privesc_enum and its pinned variants.
type enumResult struct {
	SessionID string           `json:"session_id,omitempty"`
	Host      string           `json:"host,omitempty"`
	Platform  string           `json:"platform"`
	Kernel    string           `json:"kernel,omitempty"`
	Commands  []commandOutcome `json:"commands"`
	Signals   Signals          `json:"signals"`
}

// runEnumeration executes the bounded command set for platform and folds the
// output into Signals. A single failed command is recorded and skipped; the run
// only fails when every command failed, which means the session is unusable.
func runEnumeration(ctx context.Context, s core.Session, platform string) (enumResult, error) {
	cmds := linuxEnumCommands
	if platform == platformWindows {
		cmds = windowsEnumCommands
	}
	res := enumResult{Platform: platform, Commands: make([]commandOutcome, 0, len(cmds))}
	outs := make(map[string]string, len(cmds))
	var firstErr error
	ok := 0
	for _, ec := range cmds {
		out, err := s.Exec(ctx, ec.Command, core.ExecOpts{Timeout: enumTimeout, MaxOutput: enumMaxOutput})
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			res.Commands = append(res.Commands, commandOutcome{
				Key: ec.Key, Command: ec.Command, ExitCode: -1, Error: err.Error(),
			})
			continue
		}
		ok++
		outs[ec.Key] = out.Stdout
		res.Commands = append(res.Commands, commandOutcome{
			Key: ec.Key, Command: ec.Command, ExitCode: out.ExitCode,
			Bytes: len(out.Stdout), Truncated: out.Truncated,
		})
	}
	if ok == 0 && firstErr != nil {
		return res, firstErr
	}
	res.Signals = buildSignals(platform, outs)
	res.Kernel = res.Signals.Kernel
	return res, nil
}

// buildSignals maps raw per-command output to normalized Signals. It is pure and
// platform-dispatched; unknown keys are ignored.
func buildSignals(platform string, outs map[string]string) Signals {
	sig := Signals{Platform: platform}
	switch platform {
	case platformLinux:
		sig.Kernel = parseKernelVersion(core.FirstNonEmpty(outs["kernel_version"], outs["uname"]))
		sig.OSInfo = parseOSRelease(outs["os_release"])
		sig.SudoRules = parseSudoL(outs["sudo_l"])
		sig.SUIDBinaries = parseSUID(outs["suid"])
		sig.Capabilities = parseCapabilities(outs["capabilities"])
		sig.PolkitVersion = parsePolkitVersion(outs["polkit_version"])
		sig.WritablePaths = parseWritablePaths(outs["writable_paths"])
		sig.PasswdWritable = parsePasswdWritable(outs["passwd_writable"])
	case platformWindows:
		sig.OSInfo = parseSysteminfo(outs["systeminfo"])
		sig.WhoamiPrivileges = parseWhoamiPriv(outs["whoami_priv"])
		sig.Groups = parseWhoamiGroups(outs["whoami_groups"])
		sig.Services = parseServicePaths(outs["service_paths"])
		sig.Processes = parseTasklist(outs["tasklist"])
		sig.AlwaysInstallElevated = parseAlwaysInstallElevated(outs["always_install_elevated"])
		sig.AutoLogon = parseAutoLogon(outs["autologon"])
		if sig.OSInfo != nil {
			sig.Kernel = sig.OSInfo["OS Version"]
		}
	}
	return sig
}
