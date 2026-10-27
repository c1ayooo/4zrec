package privesc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Package privesckit implements privilege-escalation enumeration and triage over
// a post-exploitation core.Session (design doc §4.6, phase P2).
//
// It is deliberately a triage capability, not a weapon: privesc_enum runs a
// bounded, read-only command set and normalizes what it finds; privesc_advise
// maps those observations to ranked candidate exploits as core.NextStep
// suggestions. No exploit payload is built or executed here — that artifact
// stays out of the library ("识别与决策在库内，成品载荷在库外").

const (
	kitName    = "privesckit"
	kitVersion = "0.1.0"
	apiVersion = "v1"
)

// Capability exposes the privilege-escalation tools. It depends only on the
// injected core.Deps, never on a concrete transport or sibling kit.
type Capability struct {
	deps core.Deps
}

// NewCapability builds the privesc capability.
func NewCapability(deps core.Deps) (core.Capability, error) {
	return &Capability{deps: deps}, nil
}

// Manifest declares the privesc tool surface.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: kitName, Version: kitVersion, APIVersion: apiVersion,
		Requires: []string{"scope", "limiter", "audit", "sessions"},
		Tools: []core.ToolSpec{
			enumSpec("privesc_enum", "枚举会话目标（Linux/Windows）上的提权线索：只读、有界。Linux 采集内核/发行版、id、sudo -n -l、SUID、文件能力、可写 cron/systemd 路径、/etc/passwd 可写性；Windows 采集 whoami /priv、whoami /groups、systeminfo、服务、tasklist、AlwaysInstallElevated 与 Winlogon 自动登录注册表。返回结构化信号与归一化结论，不执行任何利用。"),
			enumSpec("privesc_linux_enum", "Linux 平台固定版本的 privesc_enum：忽略自动判定，仅运行 Linux 只读枚举命令集。"),
			enumSpec("privesc_windows_enum", "Windows 平台固定版本的 privesc_enum：忽略自动判定，仅运行 Windows 只读枚举命令集。"),
			adviseSpec(),
		},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches the privesc tools.
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "privesc_enum":
		return c.enum(ctx, call, "")
	case "privesc_linux_enum":
		return c.enum(ctx, call, platformLinux)
	case "privesc_windows_enum":
		return c.enum(ctx, call, platformWindows)
	case "privesc_advise":
		return c.advise(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (c *Capability) manager() (core.SessionManager, *core.Error) {
	if c.deps.Sessions == nil {
		return nil, core.ToolMissing("SessionManager 未注入（宿主需提供 core.Deps.Sessions）")
	}
	return c.deps.Sessions, nil
}

// --- tool specs ---

func enumSpec(name, description string) core.ToolSpec {
	return core.ToolSpec{
		Name:        name,
		Description: description,
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 2, Burst: 1, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string","description":"已打开会话的 id"},
    "platform":{"type":"string","enum":["auto","linux","windows"],"description":"默认 auto，按 session.Info().OS 判定"}
  },
  "required":["session_id"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "platform":{"type":"string"},
    "kernel":{"type":"string"},
    "commands":{"type":"array","items":{"type":"object"}},
    "signals":{"type":"object"}
  }
}`),
	}
}

func adviseSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "privesc_advise",
		Description: "把提权枚举结果映射为按优先级排序的候选利用（core.NextStep 建议），例如 PwnKit(CVE-2021-4034)、DirtyPipe(CVE-2022-0847)、sudo 配置错误、SUID 已知危险二进制、SeImpersonatePrivilege→Potato 家族、AlwaysInstallElevated→MSI。仅做识别与决策，不执行任何利用，不生成/落地载荷。输入可以是 session_id（内部先枚举）或直接的 enum_result。",
		Risk:        core.RiskLow,
		RateLimit:   core.RateLimitSpec{PerSecond: 5, Burst: 2, Concurrency: 2},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string","description":"与 enum_result 二选一"},
    "platform":{"type":"string","enum":["auto","linux","windows"]},
    "enum_result":{"type":"object","description":"privesc_enum 的 Data，直接复用可避免重新枚举"}
  },
  "anyOf":[{"required":["session_id"]},{"required":["enum_result"]}]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "platform":{"type":"string"},
    "count":{"type":"integer"},
    "candidates":{"type":"array","items":{"type":"object"}}
  }
}`),
	}
}

// --- handlers ---

// enum implements privesc_enum and the platform-pinned variants. pinned is
// "" for auto, or a fixed platform for the *_linux_enum / *_windows_enum tools.
func (c *Capability) enum(ctx context.Context, call core.Call, pinned string) (core.Result, error) {
	mgr, e := c.manager()
	if e != nil {
		return core.FailResult(e), nil
	}
	var in struct {
		SessionID string `json:"session_id"`
		Platform  string `json:"platform"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if strings.TrimSpace(in.SessionID) == "" {
		return core.FailResult(core.InvalidInput("session_id 必填")), nil
	}
	s, ok := mgr.Get(in.SessionID)
	if !ok {
		return core.FailResult(core.NotFound("会话不存在: " + in.SessionID)), nil
	}
	info := s.Info()
	platform := pinned
	if platform == "" {
		var e2 *core.Error
		if platform, e2 = resolvePlatform(in.Platform, info); e2 != nil {
			return core.FailResult(e2), nil
		}
	}

	er, err := runEnumeration(ctx, s, platform)
	if err != nil {
		return core.FailResult(core.UpstreamError("枚举命令执行失败: " + err.Error())), nil
	}
	er.SessionID = in.SessionID
	er.Host = hostOrID(info)

	target := sessionTarget(info, call.Context.ProjectID)
	steps := advise(er.Signals)

	res := core.NewResult(core.StatusSuccess, "")
	data, _ := json.Marshal(er)
	res.Data = data
	res.Summary = core.ClampSummary(fmt.Sprintf(
		"会话 %s 提权枚举完成（%s，%d 条命令，%d 项信号，%d 个候选）",
		in.SessionID, platform, len(er.Commands), signalCount(er.Signals), len(steps)))
	res.Findings = signalsFindings(er.Signals, target)
	res.Meta = core.Meta{Tool: callToolName(call.Tool), Version: kitVersion, Target: target.Key()}
	if len(steps) > 0 {
		params, _ := json.Marshal(map[string]any{"session_id": in.SessionID, "platform": platform})
		res.Next = []core.NextStep{{
			Tool: "privesc_advise", Reason: fmt.Sprintf("基于枚举结果生成 %d 个候选提权 exploit", len(steps)),
			Risk: core.RiskLow, Params: params,
		}}
	}
	res.ClampData()
	return res, nil
}

// advise implements privesc_advise.
func (c *Capability) advise(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		SessionID  string      `json:"session_id"`
		Platform   string      `json:"platform"`
		EnumResult *enumResult `json:"enum_result"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}

	var er enumResult
	target := core.Target{}
	switch {
	case in.EnumResult != nil:
		er = *in.EnumResult
	case strings.TrimSpace(in.SessionID) != "":
		mgr, e := c.manager()
		if e != nil {
			return core.FailResult(e), nil
		}
		s, ok := mgr.Get(in.SessionID)
		if !ok {
			return core.FailResult(core.NotFound("会话不存在: " + in.SessionID)), nil
		}
		info := s.Info()
		platform, e2 := resolvePlatform(in.Platform, info)
		if e2 != nil {
			return core.FailResult(e2), nil
		}
		run, err := runEnumeration(ctx, s, platform)
		if err != nil {
			return core.FailResult(core.UpstreamError("枚举命令执行失败: " + err.Error())), nil
		}
		run.SessionID = in.SessionID
		run.Host = hostOrID(info)
		er = run
		target = sessionTarget(info, call.Context.ProjectID)
	default:
		return core.FailResult(core.InvalidInput("需要 session_id 或 enum_result 之一")), nil
	}

	if er.Signals.Platform == "" {
		er.Signals.Platform = er.Platform
	}
	if er.Signals.Platform == "" {
		er.Signals.Platform = platformLinux
	}
	if target.Host == "" && er.Host != "" {
		target = core.Target{Kind: core.TargetHost, Host: strings.ToLower(er.Host)}
	}

	steps := advise(er.Signals)

	res := core.NewResult(core.StatusSuccess, "")
	data, _ := json.Marshal(map[string]any{
		"platform": er.Signals.Platform, "count": len(steps), "candidates": steps,
	})
	res.Data = data
	res.Summary = core.ClampSummary(fmt.Sprintf(
		"基于 %s 枚举结果给出 %d 个候选提权 exploit（仅建议，不执行）", er.Signals.Platform, len(steps)))
	res.Findings = candidateFindings(steps, target)
	res.Next = steps
	res.Meta = core.Meta{Tool: "privesc_advise", Version: kitVersion, Target: target.Key()}
	res.ClampData()
	return res, nil
}

// resolvePlatform turns the requested platform (or "auto") into a concrete one
// using the session info. Unknown/undetectable input fails closed.
func resolvePlatform(requested string, info core.SessionInfo) (string, *core.Error) {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "", platformAuto:
		switch strings.ToLower(strings.TrimSpace(info.OS)) {
		case platformLinux:
			return platformLinux, nil
		case platformWindows:
			return platformWindows, nil
		}
		return "", core.InvalidInput("无法自动判定平台（session.Info().OS 为空），请显式传 platform=linux|windows")
	case platformLinux:
		return platformLinux, nil
	case platformWindows:
		return platformWindows, nil
	default:
		return "", core.InvalidInput("未知 platform: " + requested + "（auto|linux|windows）")
	}
}

// --- envelope helpers ---

func signalCount(sig Signals) int {
	n := 0
	if len(sig.SudoRules) > 0 {
		n++
	}
	if sig.PolkitVersion != "" {
		n++
	}
	if sig.Kernel != "" {
		n++
	}
	if len(sig.SUIDBinaries) > 0 {
		n++
	}
	if len(sig.Capabilities) > 0 {
		n++
	}
	if sig.PasswdWritable {
		n++
	}
	if len(sig.WritablePaths) > 0 {
		n++
	}
	if len(sig.WhoamiPrivileges) > 0 {
		n++
	}
	if len(sig.Groups) > 0 {
		n++
	}
	if len(sig.Services) > 0 {
		n++
	}
	if len(sig.Processes) > 0 {
		n++
	}
	if sig.AlwaysInstallElevated {
		n++
	}
	if sig.AutoLogon.HasPassword || sig.AutoLogon.User != "" {
		n++
	}
	return n
}

// signalsFindings turns observed misconfigurations into normalized findings.
// Config observations are Confirmed (directly read); version-range matches are
// candidates, not confirmations.
func signalsFindings(sig Signals, target core.Target) []core.Finding {
	var out []core.Finding
	add := func(fp, detail string, confirmed bool) {
		out = append(out, core.Finding{
			Target: target, Kind: "privesc", Fingerprint: fp, Confirmed: confirmed,
			Evidence: []string{detail}, Source: kitName,
		})
	}
	for _, r := range sig.SudoRules {
		if r.NoPassword {
			add("privesc|sudo_nopasswd|"+r.RunAs+"|"+r.Command,
				"sudo NOPASSWD 规则: ("+r.RunAs+") "+r.Command, true)
		}
	}
	if sig.PolkitVersion != "" && polkitVulnerable(sig.PolkitVersion) {
		add("privesc|CVE-2021-4034|polkit|"+sig.PolkitVersion,
			"polkit "+sig.PolkitVersion+" 落在 PwnKit 版本范围", false)
	}
	if sig.Platform == platformLinux && sig.Kernel != "" && dirtyPipeRange(sig.Kernel) {
		add("privesc|CVE-2022-0847|kernel|"+sig.Kernel,
			"内核 "+sig.Kernel+" 落在 DirtyPipe 影响范围", false)
	}
	for _, p := range sig.SUIDBinaries {
		if knownBadSUID[baseName(p)] {
			add("privesc|suid|"+p, "SUID GTFOBins 二进制: "+p, true)
		}
	}
	for _, c := range sig.Capabilities {
		if capsDangerous(c.Caps) {
			add("privesc|cap|"+c.Path, "危险文件能力: "+c.Path+" "+strings.Join(c.Caps, ","), true)
		}
	}
	if sig.PasswdWritable {
		add("privesc|passwd_writable", "/etc/passwd 或 /etc/shadow 可写", true)
	}
	for _, p := range sig.WritablePaths {
		add("privesc|writable|"+p, "可写路径: "+p, true)
	}
	for _, pr := range sig.WhoamiPrivileges {
		if pr.State == "Enabled" {
			add("privesc|priv|"+pr.Name, "启用特权: "+pr.Name, true)
		}
	}
	if sig.AlwaysInstallElevated {
		add("privesc|always_install_elevated", "AlwaysInstallElevated 已启用", true)
	}
	if sig.AutoLogon.HasPassword {
		add("privesc|autologon", "Winlogon 自动登录保存了明文口令", true)
	}
	for _, s := range unquotedServicePaths(sig.Services) {
		add("privesc|unquoted_service|"+s.Name, "未加引号服务路径: "+s.Name+" -> "+s.PathName, true)
	}
	return out
}

// candidateFindings mirrors advise candidates as non-confirmed findings so the
// conclusion is also visible in Findings, not only in Next.
func candidateFindings(steps []core.NextStep, target core.Target) []core.Finding {
	out := make([]core.Finding, 0, len(steps))
	for _, st := range steps {
		var p map[string]any
		_ = json.Unmarshal(st.Params, &p)
		key, _ := p["candidate"].(string)
		exploit, _ := p["exploit"].(string)
		if exploit == "" {
			exploit, _ = p["vector"].(string)
		}
		out = append(out, core.Finding{
			Target: target, Kind: "privesc", Fingerprint: "privesc|candidate|" + key,
			Confirmed: false, Payload: exploit, Evidence: []string{st.Reason}, Source: kitName,
		})
	}
	return out
}

func sessionTarget(info core.SessionInfo, projectID int64) core.Target {
	return core.Target{
		ProjectID: projectID, Kind: core.TargetHost, Host: strings.ToLower(hostOrID(info)),
	}
}

func hostOrID(info core.SessionInfo) string {
	if h := strings.TrimSpace(info.Host); h != "" {
		return h
	}
	return info.ID
}

func callToolName(tool string) string {
	if tool == "" {
		return "privesc_enum"
	}
	return tool
}
