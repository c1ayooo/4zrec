package guard

import (
	"context"
	"regexp"
	"strings"

	capguard "github.com/c1ayooo/4zrec/internal/capkit/guard"

	"github.com/c1ayooo/4zrec/internal/toolface/intercept"
)

// httpProbePolicyViolation 落实「HTTP 请求优先 http_probe」这条硬规则：
// worker/planner/recon/auto 的简单 curl/wget 会被拦下，要求改用 http_probe。
// 这样每次请求都会落库完整报文和 traffic_id，报告/复测才有可绑定证据；
// 管道处理（curl ... | grep）、流式/原始报文、-K 配置等例外不拦。
//
// 批量循环同样拦截（2026-10-22）：http_probe 的 requests[] / template+matrix/range
// 一次调用就能逐包发送并逐条落证，「用一个 bash 循环省意图」不再是绕开结构化
// 工具的理由——循环体内的简单 curl/wget 与裸 curl 同罪，指路批量模式。
func httpProbePolicyViolation(ctx context.Context, toolName, cmd string) string {
	if toolName != "Bash" {
		return ""
	}
	_, agent := intercept.TaskInfoFromContext(ctx)
	if !strings.Contains(agent, "worker") && !strings.Contains(agent, "planner") &&
		!strings.Contains(agent, "recon") && !strings.Contains(agent, "auto") {
		return ""
	}
	if simpleHTTPFetch(cmd) {
		return "简单 HTTP/HTTPS 请求请改用 http_probe（自动存证完整报文并返回 traffic_id，支持 headers/body/cookie_jar/extract/save_to_file）；" +
			"curl/wget 仅用于流式/原始报文/管道处理等本工具覆盖不了的场景，并在 record_fact 写明原因"
	}
	if loopSimpleFetch(cmd) {
		return "批量探测请改用 http_probe：requests[] 一次调用逐包发送、逐条完整报文落证并各自返回 traffic_id；变量遍历/差分用 template+matrix/range。" +
			"bash for/while 循环里跑 curl/wget 属于批量场景，「省意图」不再是理由；管道/流式/原始报文等复杂形态不受影响"
	}
	return ""
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
	return isPlainFetchArgs(capguard.Tokenize(cmd))
}

// isPlainFetchArgs 是 tokenize 之后的判定主体：curl/wget、非 help/version、
// 无 -K/-T/wget 递归——即 http_probe 单发模式可完整替代的请求。
func isPlainFetchArgs(args []string) bool {
	if len(args) == 0 {
		return false
	}
	c, rest, inner, opaque, _ := capguard.PeelCommand(args)
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

// reLoopBody 匹配 for/while/until … do … done 的循环体（非贪婪；多层循环时
// 内层先行配对，外层随后再配到自己的 done）。
var reLoopBody = regexp.MustCompile(`(?is)(?:^|[;\n&|(\s])do\b(.*?)\bdone\b`)

// loopSimpleFetch 报告 cmd 的任一循环体里存在一条可被 http_probe 完整替代的
// curl/wget。循环体按 ;/换行 切成简单命令段逐段判定；段内仍不允许管道/重定向/
// 命令替换（与简单请求的例外口径一致）。
func loopSimpleFetch(cmd string) bool {
	cmd = strings.ReplaceAll(cmd, "\\\r\n", " ")
	cmd = strings.ReplaceAll(cmd, "\\\n", " ")
	for _, m := range reLoopBody.FindAllStringSubmatch(cmd, -1) {
		for _, seg := range strings.Split(m[1], ";") {
			for _, line := range strings.Split(seg, "\n") {
				if segmentPlainFetch(line) {
					return true
				}
			}
		}
	}
	return false
}

// segmentPlainFetch 判定单个简单命令段；调用方已按 ;/换行 切分，段内再出现
// 管道/重定向/命令替换即不算「可被 http_probe 替代」。
func segmentPlainFetch(seg string) bool {
	seg = strings.TrimSpace(seg)
	if seg == "" {
		return false
	}
	for _, meta := range []string{"|", ">", "<", "&&", "||", "$(", "`"} {
		if strings.Contains(seg, meta) {
			return false
		}
	}
	return isPlainFetchArgs(capguard.Tokenize(seg))
}
