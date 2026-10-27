package container

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// CheckResult is the raw outcome of one EscapeCheck command.
type CheckResult struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Command  string `json:"command"`
	Output   string `json:"output,omitempty"`
	Error    string `json:"error,omitempty"`
	ExitCode int    `json:"exit_code"`
}

// EscapeSurface is the structured escape surface of one foothold. The boolean
// fields are what container_escape_plan consumes; it can also be built by a
// host from its own checks and passed straight into the plan tool.
type EscapeSurface struct {
	SessionID string `json:"session_id,omitempty"`
	Host      string `json:"host,omitempty"`
	OS        string `json:"os,omitempty"`

	DockerSock           bool `json:"docker_sock"`
	DockerSockMounted    bool `json:"docker_sock_mounted"`
	Privileged           bool `json:"privileged"`
	CapSysAdmin          bool `json:"cap_sys_admin"`
	CapDacReadSearch     bool `json:"cap_dac_read_search"`
	ReleaseAgentWritable bool `json:"release_agent_writable"`
	CorePatternWritable  bool `json:"core_pattern_writable"`
	HostPID              bool `json:"host_pid"`
	HostDevices          bool `json:"host_devices"`
	ProcSysWritable      bool `json:"proc_sys_writable"`

	Capabilities []string        `json:"capabilities,omitempty"`
	Checks       []EscapeFinding `json:"checks,omitempty"`
	Raw          []CheckResult   `json:"raw,omitempty"`
}

// HitCount counts the escape primitives that tested positive.
func (s EscapeSurface) HitCount() int {
	n := 0
	for _, hit := range []bool{
		s.DockerSock, s.DockerSockMounted, s.Privileged, s.CapSysAdmin,
		s.CapDacReadSearch, s.ReleaseAgentWritable, s.CorePatternWritable,
		s.HostPID, s.HostDevices, s.ProcSysWritable,
	} {
		if hit {
			n++
		}
	}
	return n
}

func (c *Capability) manager() (core.SessionManager, *core.Error) {
	if c.deps.Sessions == nil {
		return nil, core.ToolMissing("SessionManager 未注入（宿主需提供 core.Deps.Sessions）")
	}
	return c.deps.Sessions, nil
}

// --- container_escape_check ---

func (c *Capability) escapeCheck(ctx context.Context, call core.Call) (core.Result, error) {
	start := time.Now()
	var in struct {
		SessionID string `json:"session_id"`
		TimeoutMS int    `json:"timeout_ms"`
		MaxOutput int    `json:"max_output"`
	}
	if e := decodeJSON(call.Input, &in); e != nil {
		return core.FailResult(e), nil
	}
	if strings.TrimSpace(in.SessionID) == "" {
		return core.FailResult(core.InvalidInput("session_id 必填")), nil
	}
	mgr, e := c.manager()
	if e != nil {
		return core.FailResult(e), nil
	}
	s, ok := mgr.Get(in.SessionID)
	if !ok {
		return core.FailResult(core.NotFound("会话不存在: " + in.SessionID)), nil
	}
	surface := surveySession(ctx, s, in.SessionID, escapeTimeout(in.TimeoutMS), escapeMaxOutput(in.MaxOutput))

	summary := "未发现明显容器逃逸面"
	if surface.HitCount() > 0 {
		summary = fmt.Sprintf("发现 %d 个容器逃逸面：%s", surface.HitCount(), strings.Join(surface.Capabilities, ","))
	}
	res := dataMap(summary, surface)
	res.Meta.Target = surface.Host
	res.Findings = escapeFindings(surface)
	if surface.HitCount() > 0 {
		res.Next = []core.NextStep{{
			Tool: "container_escape_plan", Reason: "根据逃逸面生成候选技术并排序",
			Risk: core.RiskHigh, Preconditions: []string{"session 可用"},
			Params: mustJSON(map[string]any{"session_id": in.SessionID}),
		}}
	}
	return stamp(res, call.Tool, start), nil
}

// surveySession runs the bounded EscapeChecks and folds the verdicts into a
// surface. It is shared by container_escape_check and container_escape_plan.
func surveySession(ctx context.Context, s core.Session, sessionID string, timeout time.Duration, maxOutput int) EscapeSurface {
	info := s.Info()
	surface := EscapeSurface{SessionID: sessionID, Host: info.Host, OS: info.OS}
	var combined strings.Builder
	for _, check := range EscapeChecks {
		out, err := s.Exec(ctx, check.Command, core.ExecOpts{Timeout: timeout, MaxOutput: maxOutput})
		cr := CheckResult{ID: check.ID, Path: check.Path, Command: check.Command}
		if err != nil {
			cr.Error = err.Error()
		} else {
			cr.Output = strings.TrimSpace(out.Stdout)
			cr.ExitCode = out.ExitCode
		}
		surface.Raw = append(surface.Raw, cr)
		combined.WriteString(out.Stdout)
		combined.WriteByte('\n')
	}
	findings := parseEscapeChecks(combined.String())
	surface.Checks = findings
	escapeSurfaceFromFindings(&surface, findings)
	return surface
}

func escapeTimeout(ms int) time.Duration {
	if ms <= 0 {
		return 10 * time.Second
	}
	return time.Duration(ms) * time.Millisecond
}

func escapeMaxOutput(n int) int {
	if n <= 0 {
		return 4096
	}
	return n
}

// escapeFindingKind maps a check ID to the normalized Finding.Kind.
var escapeFindingKind = map[string]string{
	"docker_sock":                   "container_docker_sock",
	"docker_sock_mounted":           "container_docker_sock_mount",
	"privileged":                    "container_privileged",
	"cap_sys_admin":                 "container_cap_sys_admin",
	"cap_dac_read_search":           "container_cap_dac_read_search",
	"cgroup_release_agent_writable": "container_release_agent",
	"core_pattern_writable":         "container_core_pattern",
	"host_pid_namespace":            "container_host_pid",
	"host_devices":                  "container_host_devices",
	"proc_sys_writable":             "container_proc_sys_writable",
}

func escapeFindings(surface EscapeSurface) []core.Finding {
	target := sessionTarget(surface.Host)
	var out []core.Finding
	for _, f := range surface.Checks {
		if !f.Hit {
			continue
		}
		kind := escapeFindingKind[f.ID]
		if kind == "" {
			kind = "container_" + f.ID
		}
		out = append(out, core.Finding{
			Target: target, Kind: kind,
			Fingerprint: fingerprint(kind, surface.Host, ""),
			Confirmed:   true, Source: "containerkit",
			Evidence: []string{f.Path + ": " + f.Why},
		})
	}
	return out
}

func sessionTarget(host string) core.Target {
	if host == "" {
		return core.Target{Kind: core.TargetHost}
	}
	if t, err := core.TargetFromString(0, host); err == nil {
		return t
	}
	return core.Target{Kind: core.TargetHost, Host: strings.ToLower(host)}
}

// --- container_escape_plan ---

func (c *Capability) escapePlan(ctx context.Context, call core.Call) (core.Result, error) {
	start := time.Now()
	var in struct {
		SessionID string         `json:"session_id"`
		Surface   *EscapeSurface `json:"surface"`
		TimeoutMS int            `json:"timeout_ms"`
	}
	if e := decodeJSON(call.Input, &in); e != nil {
		return core.FailResult(e), nil
	}

	var surface EscapeSurface
	switch {
	case in.Surface != nil:
		surface = *in.Surface
		if surface.SessionID == "" {
			surface.SessionID = in.SessionID
		}
	case strings.TrimSpace(in.SessionID) != "":
		mgr, e := c.manager()
		if e != nil {
			return core.FailResult(e), nil
		}
		s, ok := mgr.Get(in.SessionID)
		if !ok {
			return core.FailResult(core.NotFound("会话不存在: " + in.SessionID)), nil
		}
		surface = surveySession(ctx, s, in.SessionID, escapeTimeout(in.TimeoutMS), escapeMaxOutput(0))
	default:
		return core.FailResult(core.InvalidInput("需要 surface 或 session_id")), nil
	}

	techniques := planTechniques(surface)
	summary := "未发现可用的逃逸候选技术"
	if len(techniques) > 0 {
		summary = fmt.Sprintf("生成 %d 条候选逃逸技术（按可利用性排序）", len(techniques))
	}
	res := dataMap(summary, map[string]any{
		"count": len(techniques), "techniques": techniques, "surface": surface,
	})
	res.Meta.Target = surface.Host
	res.Next = techniques
	return stamp(res, call.Tool, start), nil
}

// planTechniques ranks candidate escapes for a surface. It returns data only:
// nothing here executes an escape. Order is the ranking.
func planTechniques(s EscapeSurface) []core.NextStep {
	var out []core.NextStep
	add := func(tool, reason string, risk core.Risk, pre ...string) {
		out = append(out, core.NextStep{Tool: tool, Reason: reason, Risk: risk, Preconditions: pre})
	}

	if s.DockerSock || s.DockerSockMounted {
		add("docker_run_privileged",
			"docker.sock 可访问：创建 privileged 容器并把宿主 / 以 bind mount 挂入，直接在宿主文件系统读写",
			core.RiskHigh, "session 可写 docker.sock", "宿主/可达的 docker daemon 可用")
	}
	if s.Privileged || s.ReleaseAgentWritable {
		add("cgroup_release_agent",
			"privileged 或 release_agent 可写（cgroup v1）：向 release_agent 写入脚本并触发 cgroup 释放，在宿主以 root 执行",
			core.RiskHigh, "CAP_SYS_ADMIN", "cgroup v1 且可写 release_agent")
	}
	if s.Privileged || s.CorePatternWritable {
		add("core_pattern",
			"privileged 或 core_pattern 可写：改写 /proc/sys/kernel/core_pattern 指向恶意程序，触发进程崩溃后在宿主执行",
			core.RiskHigh, "core_pattern 可写或 privileged")
	}
	if s.CapSysAdmin {
		add("mount_host_root",
			"拥有 CAP_SYS_ADMIN：挂载宿主块设备或宿主文件系统，读取/覆盖宿主文件",
			core.RiskHigh, "CAP_SYS_ADMIN", "宿主设备或可挂载的卷可见")
	}
	if s.CapDacReadSearch {
		add("open_by_handle_at",
			"拥有 CAP_DAC_READ_SEARCH：用 open_by_handle_at 绕过权限检查读取宿主文件",
			core.RiskMedium, "CAP_DAC_READ_SEARCH")
	}
	if s.HostPID && (s.Privileged || s.CapSysAdmin) {
		add("nsenter_host",
			"共享宿主 PID 命名空间且有 SYS_ADMIN：nsenter 进入 PID 1 的 mount/net/pid 命名空间",
			core.RiskHigh, "宿主 PID namespace", "CAP_SYS_ADMIN 或 privileged")
	}
	if s.HostDevices {
		add("raw_disk_access",
			"可见宿主块设备：直接读写磁盘绕过文件系统权限",
			core.RiskHigh, "设备节点可见", "对设备节点有权限")
	}
	if s.ProcSysWritable {
		add("proc_sys_write",
			"可写 /proc/sys：修改内核 sysctl（如 core_pattern、modprobe）扩大逃逸面",
			core.RiskMedium, "对应 sysctl 文件可写")
	}
	return out
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
