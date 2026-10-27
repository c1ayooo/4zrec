package privesc

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// This file maps enumeration Signals to ranked candidate exploits as
// core.NextStep values. It deliberately stops at the library boundary from the
// design doc ("识别与决策在库内，成品载荷在库外"): it identifies and ranks
// candidates and states the reason, but never builds or runs a payload. The
// suggested Tool is the in-library session_exec, because the out-of-library
// exploit artifact is ultimately run over the foothold; the exploit identity,
// CVE and preconditions travel in Reason and Params.

const toolSessionExec = "session_exec"

// knownBadSUID is the GTFOBins subset of SUID binaries that trivially lend
// themselves to privilege escalation when setuid-root.
var knownBadSUID = map[string]bool{
	"bash": true, "sh": true, "dash": true, "find": true, "vim": true, "vi": true,
	"nano": true, "less": true, "more": true, "awk": true, "gawk": true, "env": true,
	"nmap": true, "perl": true, "python": true, "python3": true, "ruby": true,
	"tar": true, "zip": true, "gdb": true, "cp": true, "mv": true, "tee": true,
	"nc": true, "ncat": true, "curl": true, "wget": true, "rsync": true, "openssl": true,
	"mount": true, "umount": true, "pkexec": true, "passwd": true, "chsh": true,
	"systemctl": true, "journalctl": true, "apt": true, "apt-get": true, "docker": true,
}

// dangerousCaps are file capabilities that, when set on an attacker-useful
// binary, give effective root or near-root primitives.
var dangerousCaps = []string{
	"cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
	"cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_chown",
	"cap_fowner", "cap_setfcap",
}

type candidate struct {
	rank int
	step core.NextStep
}

// advise ranks candidate exploits derived from Signals, most promising first.
func advise(sig Signals) []core.NextStep {
	var cands []candidate
	add := func(rank int, step core.NextStep) {
		cands = append(cands, candidate{rank: rank, step: step})
	}

	switch sig.Platform {
	case platformWindows:
		adviseWindows(sig, add)
	default:
		adviseLinux(sig, add)
	}

	// Stable sort by descending rank; ties keep insertion order.
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].rank > cands[j].rank })
	out := make([]core.NextStep, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.step)
	}
	return out
}

func adviseLinux(sig Signals, add func(int, core.NextStep)) {
	// Full, passwordless sudo is a direct win.
	for _, r := range sig.SudoRules {
		up := strings.ToUpper(strings.TrimSpace(r.Command))
		if r.NoPassword && strings.HasPrefix(up, "ALL") {
			add(110, exploitStep("sudo-all-nopasswd", "sudo 允许无密码以任意用户执行任意命令（(ALL) NOPASSWD: ALL），可直接提权",
				map[string]any{"vector": "sudo", "run_as": r.RunAs, "command": r.Command}))
		}
	}
	// Passwordless sudo on a specific binary: GTFOBins if it is a known one,
	// otherwise still worth noting as a config weakness.
	for _, r := range sig.SudoRules {
		if !r.NoPassword {
			continue
		}
		base := baseName(strings.Fields(r.Command)[0])
		rank := 85
		note := "sudo NOPASSWD 规则可用于提权（结合 GTFOBins 用法）"
		if knownBadSUID[base] {
			rank = 96
			note = "sudo 允许无密码运行 GTFOBins 二进制 " + base + "，可借此提权"
		}
		add(rank, exploitStep("sudo-nopasswd:"+r.Command, note,
			map[string]any{"vector": "sudo", "run_as": r.RunAs, "command": r.Command, "gtfobins_binary": base}))
	}
	if v := sig.PolkitVersion; v != "" && polkitVulnerable(v) {
		add(92, exploitStep("CVE-2021-4034", "检测到 pkexec/polkit "+v+"（存在 PwnKit CVE-2021-4034 的版本范围），可本地提权到 root",
			map[string]any{"cve": "CVE-2021-4034", "exploit": "PwnKit", "polkit_version": v, "platform": platformLinux}))
	}
	if sig.Kernel != "" && dirtyPipeRange(sig.Kernel) {
		add(84, exploitStep("CVE-2022-0847", "内核 "+sig.Kernel+" 落在 DirtyPipe (CVE-2022-0847) 影响范围，可覆写只读文件提权",
			map[string]any{"cve": "CVE-2022-0847", "exploit": "DirtyPipe", "kernel": sig.Kernel, "platform": platformLinux}))
	}
	for _, p := range sig.SUIDBinaries {
		base := baseName(p)
		if knownBadSUID[base] {
			add(72, exploitStep("suid:"+p, "SUID 二进制 "+p+" 属于 GTFOBins 已知可提权项",
				map[string]any{"vector": "suid", "binary": p, "path": p, "gtfobins_binary": base}))
		}
	}
	for _, c := range sig.Capabilities {
		if capsDangerous(c.Caps) {
			add(68, exploitStep("cap:"+c.Path, "文件能力 "+strings.Join(c.Caps, ",")+" 作用于 "+c.Path+"，可借此提升权限",
				map[string]any{"vector": "capabilities", "path": c.Path, "caps": c.Caps}))
		}
	}
	if sig.PasswdWritable {
		add(100, exploitStep("writable-passwd", "/etc/passwd 或 /etc/shadow 对当前用户可写，可直接写入提权账户",
			map[string]any{"vector": "passwd-writable"}))
	}
	for _, p := range sig.WritablePaths {
		add(60, exploitStep("writable:"+p, "可写路径 "+p+"（cron/systemd）可被写入以 root 执行的任务",
			map[string]any{"vector": "writable-path", "path": p}))
	}
}

func adviseWindows(sig Signals, add func(int, core.NextStep)) {
	for _, p := range sig.WhoamiPrivileges {
		if p.State != "Enabled" {
			continue
		}
		switch p.Name {
		case "SeImpersonatePrivilege":
			add(95, exploitStep("SeImpersonatePrivilege", "持有并启用 SeImpersonatePrivilege，可用 Potato 家族（JuicyPotato/PrintSpoofer/GodPotato）提权到 SYSTEM",
				map[string]any{"privilege": p.Name, "exploit": "Potato", "platform": platformWindows}))
		case "SeAssignPrimaryTokenPrivilege":
			add(90, exploitStep("SeAssignPrimaryTokenPrivilege", "持有并启用 SeAssignPrimaryTokenPrivilege，可用 RottenPotato/JuicyPotato 完成令牌窃取提权",
				map[string]any{"privilege": p.Name, "exploit": "RottenPotato", "platform": platformWindows}))
		case "SeDebugPrivilege":
			add(70, exploitStep("SeDebugPrivilege", "持有并启用 SeDebugPrivilege，可注入/窃取高权限进程令牌",
				map[string]any{"privilege": p.Name, "exploit": "token-steal", "platform": platformWindows}))
		case "SeBackupPrivilege", "SeRestorePrivilege":
			add(60, exploitStep(p.Name, "持有并启用 "+p.Name+"，可读取/覆盖受保护文件（如 SAM/SYSTEM 注册表配置单元）",
				map[string]any{"privilege": p.Name, "exploit": "backup-restore", "platform": platformWindows}))
		case "SeTakeOwnershipPrivilege":
			add(62, exploitStep("SeTakeOwnershipPrivilege", "持有并启用 SeTakeOwnershipPrivilege，可夺取任意文件/对象所有权后替换",
				map[string]any{"privilege": p.Name, "exploit": "take-ownership", "platform": platformWindows}))
		}
	}
	if sig.AlwaysInstallElevated {
		add(88, exploitStep("AlwaysInstallElevated", "AlwaysInstallElevated 已启用（HKLM 与 HKCU 均为 0x1），可安装任意 MSI 以 SYSTEM 权限执行",
			map[string]any{"vector": "msi", "exploit": "msi-install", "platform": platformWindows}))
	}
	if sig.AutoLogon.HasPassword {
		add(80, exploitStep("autologon", "Winlogon 自动登录配置中保存了明文 DefaultPassword，可直接复用凭据",
			map[string]any{"vector": "autologon", "user": sig.AutoLogon.User, "platform": platformWindows}))
	}
	for _, s := range unquotedServicePaths(sig.Services) {
		add(74, exploitStep("unquoted-service:"+s.Name, "服务 "+s.Name+" 的可执行路径含空格且未加引号（"+s.PathName+"），存在服务路径劫持风险",
			map[string]any{"vector": "unquoted-service", "service": s.Name, "pathname": s.PathName}))
	}
}

// exploitStep builds the standard candidate NextStep. Params carries the
// machine-readable candidate so a host or planner can filter/rank by vector
// without parsing Reason.
func exploitStep(key, reason string, params map[string]any) core.NextStep {
	if params == nil {
		params = map[string]any{}
	}
	if _, ok := params["candidate"]; !ok {
		params["candidate"] = key
	}
	raw, _ := json.Marshal(params)
	return core.NextStep{
		Tool:   toolSessionExec,
		Reason: reason,
		Preconditions: []string{
			"需要库外成品 exploit 载荷（本库只做识别与决策）",
			"会话可执行命令",
		},
		Risk:   core.RiskHigh,
		Params: raw,
	}
}

func baseName(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.LastIndex(p, `\`); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}

// polkitVulnerable reports whether a polkit version predates the PwnKit fix
// (0.120 upstream; distro backports notwithstanding, older is the candidate).
func polkitVulnerable(v string) bool {
	got := parseNumericVersion(v)
	fixed := parseNumericVersion("0.120")
	if len(got) == 0 {
		return false
	}
	return cmpVersion(got, fixed) < 0
}

// dirtyPipeRange reports whether a kernel is in the DirtyPipe-affected range
// [5.8, 5.16.11).
func dirtyPipeRange(kernel string) bool {
	return compareKernelRange(kernel, "5.8", "5.16.11")
}

func capsDangerous(caps []string) bool {
	for _, c := range caps {
		low := strings.ToLower(c)
		for _, d := range dangerousCaps {
			if strings.Contains(low, d) {
				return true
			}
		}
	}
	return false
}
