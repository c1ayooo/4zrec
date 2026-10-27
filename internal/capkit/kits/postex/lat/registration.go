package lat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Static identity of the capability, kept in constants so Manifest() and any
// host-side audit/telemetry agree on one source of truth.
const (
	kitName    = "latkit"
	kitVersion = "0.1.0"
	apiVersion = "v1"
)

// Capability adapts the impacket/NetExec wrappers to the registry/capability
// contract. Every tool returns a Result envelope (Status/Summary/Data/
// Findings/Next), never bare data. The kit performs no authorization itself;
// scope, approval, rate limit and audit are enforced by the host's injected
// gate chain. All process execution goes through core.ProcessRunner — no
// os/exec, no direct binary invocation.
type Capability struct {
	deps core.Deps
}

// NewCapability builds the capability from injected ports. A nil ProcessRunner
// is tolerated here: the Call path reports core.Unavailable for every tool so
// a host that registered latkit without the port still gets a clean envelope
// rather than a construction panic. The registry's Requires=["process"] is the
// real wiring gate.
func NewCapability(deps core.Deps) (core.Capability, error) {
	return &Capability{deps: deps}, nil
}

// runner returns the injected process port, or a core.Unavailable error when
// the host wired latkit without one. Every handler funnels subprocess execution
// through here so the missing-dependency contract is identical for all eight
// tools.
func (c *Capability) runner() (core.ProcessRunner, *core.Error) {
	if c.deps.Processes == nil {
		return nil, core.Unavailable("ProcessRunner 未注入，latkit 无法调用外部工具（impacket/NetExec）")
	}
	return c.deps.Processes, nil
}

// Manifest declares the eight lateral-movement / Kerberos tools. Each tool's
// Data shape is described by output_schema so agents know the return before
// calling. Risk is high for every tool: each executes a command or extracts
// credential material on an in-scope target.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: kitName, Version: kitVersion, APIVersion: apiVersion,
		Requires: []string{"scope", "limiter", "audit", "process"},
		Tools: []core.ToolSpec{
			latPsexecSpec(),
			latWmiexecSpec(),
			latSmbexecSpec(),
			latWinRMSpec(),
			latPassTheHashSpec(),
			latKerberoastSpec(),
			latAsrepRoastSpec(),
			latDCSyncSpec(),
		},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches by tool name, returning a populated envelope.
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "lat_psexec":
		return c.run(ctx, call, "lat_psexec")
	case "lat_wmiexec":
		return c.run(ctx, call, "lat_wmiexec")
	case "lat_smbexec":
		return c.run(ctx, call, "lat_smbexec")
	case "lat_winrm":
		return c.run(ctx, call, "lat_winrm")
	case "lat_pass_the_hash":
		return c.run(ctx, call, "lat_pass_the_hash")
	case "lat_kerberoast":
		return c.run(ctx, call, "lat_kerberoast")
	case "lat_asrep_roast":
		return c.run(ctx, call, "lat_asrep_roast")
	case "lat_dcsync":
		return c.run(ctx, call, "lat_dcsync")
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

// run builds the argv, runs the external tool through the injected
// ProcessRunner, and wraps the result into the envelope. Hashes parsed from
// Kerberos / DCSync output are returned as Findings + NextStep suggestions.
func (c *Capability) run(ctx context.Context, call core.Call, tool string) (core.Result, error) {
	proc, runErr := c.runner()
	if runErr != nil {
		return core.FailResult(runErr), nil
	}
	in, err := parseInput(call.Input)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	path, args, err := BuildCommand(tool, call.Input)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	timeout := 5 * time.Minute
	target, _ := core.TargetFromString(call.Context.ProjectID, in.Target)
	spec := core.ProcessSpec{
		Path:      path,
		Args:      args,
		Timeout:   timeout,
		Targets:   []core.Target{target},
		RateLimit: core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
	}
	res, err := proc.Run(ctx, spec)
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}

	stdout := string(res.Stdout)
	stderr := string(res.Stderr)
	data, _ := core.DataResult(map[string]any{
		"command":   path + " " + strings.Join(args, " "),
		"exit_code": res.ExitCode,
		"stdout":    prune(stdout),
		"stderr":    prune(stderr),
	})

	roast := tool == "lat_kerberoast" || tool == "lat_asrep_roast" || tool == "lat_dcsync"
	if !roast {
		data.Summary = core.ClampSummary(tool + " 已在 " + in.Target + " 执行（exit " +
			fmt.Sprintf("%d", res.ExitCode) + "）")
		return data, nil
	}

	hashes := ParseHashes(tool, res.Stdout)
	findings := make([]core.Finding, 0, len(hashes))
	for _, h := range hashes {
		findings = append(findings, core.Finding{
			Target:    target,
			Kind:      h.Type,
			Confirmed: true,
			Payload:   h.Hash,
			Evidence:  []string{h.Account},
			Source:    "latkit",
		})
	}
	data.Findings = findings
	data.Meta.Target = target.Key()
	if len(hashes) > 0 {
		data.Summary = core.ClampSummary(tool + " 提取到 " +
			fmt.Sprintf("%d", len(hashes)) + " 条凭据哈希（" + hashes[0].Type + " 等）")
		next := nextForTool(tool, in.Target)
		data.Next = next
	} else {
		data.Summary = core.ClampSummary(tool + " 执行完成，未解析到凭据哈希（exit " +
			fmt.Sprintf("%d", res.ExitCode) + "）")
	}
	return data, nil
}

// nextForTool suggests the logical follow-up (crack / replay) for a roast.
func nextForTool(tool, target string) []core.NextStep {
	switch tool {
	case "lat_kerberoast", "lat_asrep_roast":
		return []core.NextStep{{
			Tool:          "john",
			Reason:        "对提取的 Kerberos 哈希离线破解，获取服务账户明文密码",
			Risk:          core.RiskMedium,
			Preconditions: []string{"目标在授权范围", "已获得离线破解算力"},
		}}
	case "lat_dcsync":
		return []core.NextStep{{
			Tool:   "lat_pass_the_hash",
			Reason: "用提取的 NTLM hash 进行 pass-the-hash 横向移动",
			Risk:   core.RiskHigh,
			Params: mustJSONRaw(map[string]any{"target": target}),
		}}
	}
	return nil
}

// mustJSONRaw marshals v to json.RawMessage, ignoring errors (schema is fixed).
func mustJSONRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// prune caps a string to 4KB so the Data envelope stays well under the 8KB cap.
func prune(s string) string {
	if len(s) > 4<<10 {
		return s[:4<<10]
	}
	return s
}

// --- tool specs ---

const commonSchemaProps = `{
	  "type":"object",
	  "properties":{
	    "target":{"type":"string","description":"目标主机/IP，impacket 的域控或成员机"},
	    "domain":{"type":"string","description":"AD 域（如 CORP）"},
	    "user":{"type":"string","description":"用户名"},
	    "secret":{"type":"string","description":"密码（与 hash 二选一）"},
	    "hash":{"type":"string","description":"NTLM 哈希（32 位十六进制，可带 LM: 前缀；与 secret 二选一）"},
	    "command":{"type":"string","description":"远程执行的单条命令"},
	    "port":{"type":"integer","description":"非默认端口（psexec/smbexec/winrm 可选）"}
	  }
	}`

// commonRequired renders the JSON `"required":[...]` fragment for the given
// property names. Calling it with no names yields an empty required array, so a
// tool that needs only the caller's identity still gets a valid schema.
func commonRequired(parts ...string) string {
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = `"` + p + `"`
	}
	return `"required":[` + strings.Join(quoted, ",") + `]`
}

// inputSchema assembles a valid InputSchema of the shared shape plus the given
// required field names.
func inputSchema(required ...string) json.RawMessage {
	quoted := make([]string, len(required))
	for i, r := range required {
		quoted[i] = `"` + r + `"`
	}
	body := strings.TrimRight(strings.TrimSpace(commonSchemaProps), "}")
	body = strings.TrimSpace(body) + `,
  "required":[` + strings.Join(quoted, ",") + `]
}`
	return json.RawMessage(body)
}

func latPsexecSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:           "lat_psexec",
		Description:    "通过 impacket psexec.py 以 SMB + 服务方式在目标 Windows 主机执行远程命令。仅 subprocess 调用 impacket（禁止 import 其代码）；凭据与命令经校验，禁止 shell 元字符注入。",
		Risk:           core.RiskHigh,
		RateLimit:      core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema:    inputSchema("command"),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"command":{"type":"string"},"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stderr":{"type":"string"}}}`),
		ExtractTargets: targetFromInput,
	}
}

func latWmiexecSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:           "lat_wmiexec",
		Description:    "通过 impacket wmiexec.py 用 WMI 半交互式 shell 在目标执行远程命令（不走 smbexec 服务）。仅 subprocess 调用 impacket；输入经校验。",
		Risk:           core.RiskHigh,
		RateLimit:      core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema:    inputSchema("command"),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"command":{"type":"string"},"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stderr":{"type":"string"}}}`),
		ExtractTargets: targetFromInput,
	}
}

func latSmbexecSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:           "lat_smbexec",
		Description:    "通过 impacket smbexec.py 用批处理服务在目标执行远程命令。仅 subprocess 调用 impacket；输入经校验。",
		Risk:           core.RiskHigh,
		RateLimit:      core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema:    inputSchema("command"),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"command":{"type":"string"},"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stderr":{"type":"string"}}}`),
		ExtractTargets: targetFromInput,
	}
}

func latWinRMSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:           "lat_winrm",
		Description:    "通过 NetExec (nxc) winrm 模块在目标执行远程命令。仅 subprocess 调用 NetExec（禁止 import 其代码）；凭据或 hash 二选一，命令经校验。",
		Risk:           core.RiskHigh,
		RateLimit:      core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema:    inputSchema("command"),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"command":{"type":"string"},"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stderr":{"type":"string"}}}`),
		ExtractTargets: targetFromInput,
	}
}

func latPassTheHashSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:           "lat_pass_the_hash",
		Description:    "用 impacket 的 -hashes 选项进行 pass-the-hash：以 NTLM 哈希而非明文密码在目标执行远程命令。仅 subprocess 调用 impacket；哈希格式经校验。",
		Risk:           core.RiskHigh,
		RateLimit:      core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema:    inputSchema("hash", "command"),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"command":{"type":"string"},"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stderr":{"type":"string"}}}`),
		ExtractTargets: targetFromInput,
	}
}

func latKerberoastSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:           "lat_kerberoast",
		Description:    "通过 impacket GetUserSPNs.py -request 请求域内服务票据并提取可离线破解的 krb5tgs 哈希。仅 subprocess 调用 impacket；返回的哈希作为 Finding。",
		Risk:           core.RiskHigh,
		RateLimit:      core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema:    inputSchema(),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stderr":{"type":"string"},"findings":{"type":"array"}}}`),
		ExtractTargets: targetFromInput,
	}
}

func latAsrepRoastSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:           "lat_asrep_roast",
		Description:    "通过 impacket GetNPUsers.py -no-pass 对不要求预认证（DONT_REQ_PREAUTH）的账户请求 AS-REP 并提取 krb5as 哈希。仅 subprocess 调用 impacket；返回的哈希作为 Finding。",
		Risk:           core.RiskHigh,
		RateLimit:      core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema:    inputSchema(),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stderr":{"type":"string"},"findings":{"type":"array"}}}`),
		ExtractTargets: targetFromInput,
	}
}

func latDCSyncSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:           "lat_dcsync",
		Description:    "通过 impacket secretsdump.py -just-dc 从域控提取 NTDS 凭据（NTLM 哈希）。仅 subprocess 调用 impacket；提取的哈希作为 Finding，便于后续 pass-the-hash。",
		Risk:           core.RiskHigh,
		RateLimit:      core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema:    inputSchema(),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stderr":{"type":"string"},"findings":{"type":"array"}}}`),
		ExtractTargets: targetFromInput,
	}
}

// targetFromInput pulls the target host out of the Input so the host's scope
// gate runs before the tool touches anything.
func targetFromInput(raw json.RawMessage) ([]core.Target, error) {
	var in struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	t := strings.TrimSpace(in.Target)
	if t == "" {
		return nil, fmt.Errorf("target 必填")
	}
	tg, err := core.TargetFromString(0, t)
	if err != nil {
		return nil, err
	}
	return []core.Target{tg}, nil
}
