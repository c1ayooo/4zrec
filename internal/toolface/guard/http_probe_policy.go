package guard

import (
	"context"
	"strings"

	"github.com/c1ayooo/4zrec/internal/toolface/intercept"
)

// httpProbePolicyViolation 落实「HTTP 请求优先 http_probe」这条硬规则：
// worker/planner/recon/auto 的简单 curl/wget 会被拦下，要求改用 http_probe。
// 这样每次请求都会落库完整报文和 traffic_id，报告/复测才有可绑定证据；
// 管道处理（curl ... | grep）、流式/原始报文、-K 配置等例外不拦。
func httpProbePolicyViolation(ctx context.Context, toolName, cmd string) string {
	if toolName != "Bash" {
		return ""
	}
	_, agent := intercept.TaskInfoFromContext(ctx)
	if !strings.Contains(agent, "worker") && !strings.Contains(agent, "planner") &&
		!strings.Contains(agent, "recon") && !strings.Contains(agent, "auto") {
		return ""
	}
	if !simpleHTTPFetch(cmd) {
		return ""
	}
	return "简单 HTTP/HTTPS 请求请改用 http_probe（自动存证完整报文并返回 traffic_id，支持 headers/body/cookie_jar/extract/save_to_file）；" +
		"curl/wget 仅用于流式/原始报文/管道处理等本工具覆盖不了的场景，并在 record_fact 写明原因"
}

// simpleHTTPFetch reports whether cmd is a plain curl/wget request that
// http_probe can fully replace. Pipelines, redirections, command substitution,
// config files and help/version invocations are left alone.
func simpleHTTPFetch(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	// 多行命令里的反斜杠续行仍是同一条简单命令。
	cmd = strings.ReplaceAll(cmd, "\\\r\n", " ")
	cmd = strings.ReplaceAll(cmd, "\\\n", " ")
	for _, meta := range []string{"|", ">", "<", ";", "&&", "||", "$(", "`", "\n"} {
		if strings.Contains(cmd, meta) {
			return false
		}
	}
	args := tokenize(cmd)
	if len(args) == 0 {
		return false
	}
	c, rest, inner, opaque, _ := peelCommand(args)
	if opaque || inner != "" {
		return false
	}
	if c != "curl" && c != "wget" {
		return false
	}
	// 只包含 help/version 的调用不是对目标的请求。
	harmless := len(rest) > 0
	for _, tok := range rest {
		switch tok {
		case "-h", "--help", "-V", "--version":
			continue
		default:
			if strings.HasPrefix(tok, "-") {
				continue
			}
			harmless = false
		}
	}
	if harmless {
		return false
	}
	for _, tok := range rest {
		switch tok {
		case "-K", "--config",
			"-T", "--upload-file":
			// 配置文件/原始上传不是简单请求。
			return false
		}
		if c == "wget" {
			switch tok {
			case "-r", "--recursive", "-m", "--mirror", "-p", "--page-requisites",
				"-k", "--convert-links":
				// 递归抓取不是单次请求，http_probe 不覆盖。
				return false
			}
		}
	}
	return true
}
