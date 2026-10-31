// fence_object.go 把围栏从“扫描命令文本”升级为“识别命令作用的对象”。
//
// 做法：
//  1. 用与 shell 一致的切分/分词（splitCommands/tokenize）把命令拆成简单命令；
//  2. 先剥掉 sudo/env/timeout/nice/xargs/find -exec/sh -c 等包装，拿到真正
//     发起动作的命令；
//  3. 已知出网命令只取其目标操作数（URL/host/IP/CIDR/目标列表文件）；
//  4. 解释器代码/脚本、未知命令、不可读的目标列表等无法静态确定对象的形态
//     标记为 Opaque，由围栏走人工审批，而不是“没提取到目标就放行”。
//
// 这不是一个通用沙箱：最终仍建议把 HTTP(S) 出口放到授权代理层。但相比旧实现，
// 它不再依赖“在整段文本里找像域名的 token”，而是围绕命令对象判定。
package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ExtractFenceTargets 从工具输入文本提取围栏目标（兼容旧调用）。
func ExtractFenceTargets(text string) fenceTargets {
	return ExtractFenceTargetsWithDir(text, "")
}

// ExtractFenceTargetsWithDir 在旧的字面目标提取之外，再按命令对象解析一层。
// workDir 是 agent 的工作目录，用于读取 -iL / -l / 解释器脚本等对象清单；
// 为空时文件读取一律视为不可读（Opaque），不会去读服务器进程的 CWD。
func ExtractFenceTargetsWithDir(text, workDir string) fenceTargets {
	t := extractFenceTargetsLegacy(text)
	extra, opaque, reason := analyzeCommandObjects(text, workDir, 0)
	mergeFenceTargets(&t, extra)
	if opaque {
		t.Opaque = true
		if t.Reason == "" {
			t.Reason = reason
		}
	}
	// Opaque 命令的字面目标兜底扫描：heredoc/解释器脚本体在命令对象分析阶段被
	// 剥离，但写死在脚本体里的 IP/URL 是静态可见的目标——收进结果，围栏才能对
	// 「全部字面目标均在授权范围内」的场景自动放行，审批卡片也能展示真实目标。
	// 结果仍标 Opaque：动态构造的目标依旧不可见，fail-closed 语义不变。
	if t.Opaque {
		mergeFenceTargets(&t, sweepLiteralTargets(text))
	}
	return t
}

// reIPv4Literal 匹配 IPv4 四组字面量；	validFenceIPv4 再做 octet 与保留段校验。
var reIPv4Literal = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// sweepLiteralTargets 对原始文本（含 heredoc 体）做字面目标兜底扫描。
// 只收高置信形态——IPv4 四组字面量与 scheme://host 的 URL host（复用
// addHost/addIP 的归一与公共基础设施过滤），不收泛域名与裸单词，
// 避免把版本号、普通单词误当目标。
func sweepLiteralTargets(text string) fenceTargets {
	c := newFenceCollector(collectVars(text))
	for _, m := range reIPv4Literal.FindAllString(text, -1) {
		if validFenceIPv4(m) {
			c.addIP(m)
		}
	}
	for _, u := range reURLObject.FindAllString(text, -1) {
		c.addHost(u)
	}
	return c.result()
}

var (
	reURLObject = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s"'<>]+`)
	// 解释器代码里出现这些调用/关键字时，说明它可能联网；即使提取到部分 URL，
	// 也不能假定对象已经完整（动态拼接、循环、读配置都会漏）。
	reNetworkIndicator = regexp.MustCompile(`(?i)(https?://|ftp://|\brequests\.|\burllib\b|\bhttp\.client\b|\bsocket\.|\bfetch\s*\(|\baxios\b|\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bssh\b|\bnmap\b|\bmasscan\b|\bdig\b|\bnslookup\b|\bping\b|\btelnet\b|\bhttp\.get\b|\bhttp\.request\b|\bnet\.Dial\b|\bhttp\.Client\b)`)
)

// localOnlyCommands 明确不会发起网络连接、也不执行子命令的本地命令。
// 未列出的命令一律按“无法确定对象”处理（Opaque），宁可多一次审批。
var localOnlyCommands = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "grep": true, "egrep": true,
	"fgrep": true, "sed": true, "awk": true, "cut": true, "sort": true, "uniq": true,
	"wc": true, "tr": true, "tee": true, "echo": true, "printf": true, "test": true,
	"[": true, "true": true, "false": true, "pwd": true, "cd": true, "pushd": true,
	"popd": true, "mkdir": true, "rmdir": true, "rm": true, "cp": true, "mv": true,
	"ln": true, "touch": true, "chmod": true, "chown": true, "chgrp": true,
	"stat": true, "file": true, "strings": true, "xxd": true, "hexdump": true,
	"od": true, "base64": true, "md5sum": true, "sha1sum": true, "sha256sum": true,
	"sha512sum": true, "diff": true, "comm": true, "join": true, "paste": true,
	"split": true, "csplit": true, "date": true, "sleep": true, "seq": true,
	"yes": true, "which": true, "type": true, "printenv": true, "id": true,
	"whoami": true, "uname": true, "hostname": true, "df": true, "du": true,
	"free": true, "ps": true, "top": true, "kill": true, "pkill": true, "killall": true,
	"jobs": true, "bg": true, "fg": true, "wait": true, "set": true, "unset": true,
	"export": true, "readonly": true, "declare": true, "typeset": true, "local": true,
	"shift": true, "return": true, "break": true, "continue": true, "trap": true,
	"umask": true, "ulimit": true, "alias": true, "unalias": true, "history": true,
	":": true, "read": true, "mapfile": true, "readarray": true,
	"mktemp": true, "dirname": true, "basename": true, "realpath": true,
	"readlink": true, "expr": true, "bc": true, "dc": true, "jq": true, "yq": true,
	"column": true, "fold": true, "fmt": true, "nl": true, "pr": true, "rev": true,
	"tac": true, "expand": true, "unexpand": true, "look": true, "ptx": true,
	"tsort": true, "numfmt": true, "cksum": true, "sum": true, "shuf": true,
	"uuidgen": true, "logger": true, "tty": true, "stty": true, "clear": true,
	"reset": true, "tput": true, "locale": true, "cal": true, "nproc": true,
	"arch": true, "getconf": true, "ldd": true, "nm": true, "objdump": true,
	"readelf": true, "size": true, "strip": true, "ar": true, "ranlib": true,
	"less": true, "more": true, "most": true, "view": true, "vim": true, "vi": true,
	"nano": true, "emacs": true, "man": true, "info": true, "help": true,
	"apropos": true, "whatis": true, "shellcheck": true, "bat": true, "fd": true,
	"rg": true, "tree": true, "pandoc": true,
	// 本地漏洞库检索(exploitdb 离线数据),不出网;此前在出网命令表里,
	// `searchsploit apache 2.4.49` 会把 "apache" 提成域名目标。
	"searchsploit": true,
}

// infraCommands 是工具链/包管理器这类“基础设施出网”，不是对目标的测试流量。
// 它们通常访问 registry/镜像站，不纳入资产围栏；需要 clone 目标仓库时，
// 由 git/svn/hg 的 URL 提取分支处理。
var infraCommands = map[string]bool{
	"pip": true, "pip3": true, "npm": true, "npx": true, "yarn": true, "pnpm": true,
	"gem": true, "cargo": true, "rustc": true, "go": true, "apt": true, "apt-get": true,
	"yum": true, "dnf": true, "apk": true, "brew": true, "docker": true, "podman": true,
	"make": true, "cmake": true, "gcc": true, "g++": true, "clang": true, "javac": true,
	"mvn": true, "gradle": true, "composer": true, "bundle": true, "dotnet": true,
	"nuget": true, "conda": true, "micromamba": true, "ssh-keygen": true, "gpg": true,
	"unzip": true, "zip": true, "tar": true, "gzip": true, "gunzip": true, "bzip2": true,
	"xz": true, "unxz": true, "7z": true, "rar": true, "unrar": true,
}

// urlOnlyCommands 只提取 URL 对象，不因为其他参数无法识别而 Opaque。
var urlOnlyCommands = map[string]bool{"git": true, "svn": true, "hg": true}

var interpreterCommands = map[string]bool{
	"python": true, "python2": true, "python3": true, "pypy": true, "pypy3": true,
	"node": true, "nodejs": true, "deno": true, "bun": true, "ruby": true, "perl": true,
	"php": true, "pwsh": true, "powershell": true, "osascript": true, "lua": true,
	"luajit": true, "rscript": true, "java": true, "jshell": true, "scala": true,
}

var shellControlKeywords = map[string]bool{
	"for": true, "while": true, "until": true, "if": true, "then": true, "elif": true,
	"else": true, "fi": true, "case": true, "esac": true, "do": true, "done": true,
	"select": true, "function": true, "in": true, "time": true, "{": true, "}": true,
	"!": true, "[[": true, "]]": true,
}

// targetFileFlags 各命令的目标清单文件旗标。文件内容按行视为目标对象；
// 文件不可读时整条命令 Opaque。
var targetFileFlags = map[string]map[string]bool{
	"nmap":      {"-iL": true},
	"masscan":   {"-iL": true},
	"wget":      {"-i": true, "--input-file": true},
	"httpx":     {"-l": true, "--list": true},
	"nuclei":    {"-l": true, "--list": true},
	"katana":    {"-list": true},
	"subfinder": {"-dL": true, "--domain-list": true},
	"dnsx":      {"-l": true},
	"naabu":     {"-list": true},
}

func baseCommand(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// loopBind 一层活跃的 for 循环:变量名 → 候选值(词表字面量,或工作目录内
// glob 展开出的文件)。循环体按候选逐一展开分析,目标取并集。
type loopBind struct {
	name   string
	values []string
}

// loopVariantsCap 展开候选数上限:超过就放弃展开、按未展开文本分析
// (动态占位符路径会走 Opaque,fail-closed 而不是爆炸)。
const loopVariantsCap = 64

// loopLeadPrefixes 循环头识别前可剥的语句前缀:外层 `;`/换行切分后,
// 嵌套结构与 if 分支体会带这些前缀。
var loopLeadPrefixes = map[string]bool{"do": true, "then": true, "else": true, "!": true}

// analyzeCommandObjects 是对象解析主入口。
func analyzeCommandObjects(text, workDir string, depth int) (fenceTargets, bool, string) {
	var out fenceTargets
	if depth > 3 {
		return out, true, "命令嵌套过深，无法静态确定网络对象"
	}
	// 变量赋值按整段命令收集(d="x"; dig "$d" 跨段引用),供目标参数代入;
	// 代入不了的($d 来自循环)在动态占位符检查里 fail-closed。
	vars := collectVars(text)
	var loops []loopBind
	for _, seg := range splitCommandSegments(stripHeredocs(text)) {
		// 注释行：以 # 开头的段是注释，不是命令（2026-10-29 实锤误伤）。
		s := strings.TrimSpace(seg.Text)
		if strings.HasPrefix(s, "#") {
			continue
		}
		// 子 shell 包装残片：splitCommands 在 `;` 处把 (cmd1; cmd2) 拆开后，
		// 首段带前导 "("、末段带尾随 ")"——剥掉后按普通段分析（$() 命令替换
		// 已在下方单独跳过，不受影响）。
		if strings.HasPrefix(s, "(") {
			s = strings.TrimRight(strings.TrimLeft(s, "( "), ") ")
			if s == "" {
				continue
			}
		}
		args := Tokenize(s)
		if len(args) == 0 {
			continue
		}
		// for 头:登记循环变量与候选值;done 弹出。词表不可静态解析
		// ($(seq ...) 等)就不绑定,循环体按原行为分析(动态占位符 fail-closed)。
		// 嵌套循环的头是 `do for b in x y`(外层 ; 切分后带 do 前缀),识别前
		// 只剥 do/then/else/! 这类语句前缀——不能剥整个 shellControlKeywords,
		// for/in 本身就在关键字表里。
		lead := 0
		for lead < len(args) && loopLeadPrefixes[args[lead]] {
			lead++
		}
		head := args[lead:]
		if len(head) > 0 {
			if head[0] == "for" {
				if lb, ok := parseForHeader(head, workDir); ok {
					loops = append(loops, lb)
				}
				continue
			}
			if head[0] == "done" {
				if len(loops) > 0 {
					loops = loops[:len(loops)-1]
				}
				continue
			}
		}
		if len(loops) == 0 {
			sub, cop, creason := analyzeSegment(s, seg.Piped, workDir, depth, vars)
			mergeFenceTargets(&out, sub)
			if cop {
				return out, true, creason
			}
			continue
		}
		// 循环体:每个候选值都可能是实际取值——逐一分析求并集;任一候选
		// 不可判定 → 整体 fail-closed。
		for _, variant := range loopVariants(s, loops) {
			sub, cop, creason := analyzeSegment(variant, seg.Piped, workDir, depth, vars)
			mergeFenceTargets(&out, sub)
			if cop {
				return out, true, creason
			}
		}
	}
	return out, false, ""
}

// parseForHeader 解析 `for VAR in W1 W2 ...` 头（Tokenize 后的 token）。
// 词表全部可静态解析（无 $/命令替换/子 shell）才登记绑定；含 glob 的词按
// 工作目录展开（只留文件）。展开为空保留字面词，后续读取失败自然 Opaque。
func parseForHeader(args []string, workDir string) (loopBind, bool) {
	if len(args) < 4 || args[2] != "in" || !isForVarName(args[1]) {
		return loopBind{}, false
	}
	words := args[3:]
	if words[len(words)-1] == "do" {
		words = words[:len(words)-1]
	}
	if len(words) == 0 {
		return loopBind{}, false
	}
	for _, w := range words {
		if strings.ContainsAny(w, "$`(") {
			return loopBind{}, false
		}
	}
	lb := loopBind{name: args[1]}
	for _, w := range words {
		lb.values = append(lb.values, expandLoopWord(w, workDir)...)
		if len(lb.values) > loopVariantsCap {
			return loopBind{}, false
		}
	}
	return lb, true
}

// isForVarName 循环变量必须是 shell 标识符(排除 C 风格 for ((i=0;...)) 残片)。
func isForVarName(s string) bool {
	if s == "" || !isNameStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isNameChar(s[i]) {
			return false
		}
	}
	return true
}

// expandLoopWord 展开循环词:含 glob 通配符时按工作目录展开为绝对路径
// (只留普通文件);无 glob 或不可展开时原样返回。
func expandLoopWord(word, workDir string) []string {
	if !strings.ContainsAny(word, "*?[") || workDir == "" {
		return []string{word}
	}
	matches, err := filepath.Glob(filepath.Join(workDir, word))
	if err != nil {
		return []string{word}
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if info, err := os.Stat(m); err == nil && !info.IsDir() {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return []string{word}
	}
	return out
}

// loopVariants 对循环体文本做逐层变量代入,产出候选变体(嵌套循环取笛卡尔
// 积)。候选数超上限放弃展开,返回原文——按动态占位符 fail-closed。
func loopVariants(text string, loops []loopBind) []string {
	variants := []string{text}
	for _, lb := range loops {
		next := make([]string, 0, len(variants)*len(lb.values))
		for _, v := range variants {
			for _, val := range lb.values {
				next = append(next, substituteVars(v, map[string]string{lb.name: val}))
			}
		}
		if len(next) > loopVariantsCap {
			return []string{text}
		}
		variants = next
	}
	return variants
}

// analyzeSegment 分析单个简单命令段（已切分）。piped 表示段前有管道；
// vars 供目标/脚本路径的变量代入。返回本段目标与 Opaque 判定。
func analyzeSegment(text string, piped bool, workDir string, depth int, vars map[string]string) (fenceTargets, bool, string) {
	// WebFetch 等工具直接给一个裸 URL，没有命令前缀；目标已由旧提取器
	// 提取，不能把 URL 当未知命令判 Opaque。
	if strings.Contains(text, "://") && !strings.ContainsAny(text, " \t\n;|&") {
		return fenceTargets{}, false, ""
	}
	// 命令替换由旧提取器递归处理；这里跳过外层文本，避免把替换体里的
	// 代码当未知命令误判。
	if strings.Contains(text, "$(") || strings.Contains(text, "`") {
		return fenceTargets{}, false, ""
	}
	// 函数定义：分析 { 之后真正会执行的命令体，而不是把函数名当命令。
	if body := functionBody(text); body != "" {
		return analyzeCommandObjects(body, workDir, depth+1)
	}
	args := Tokenize(text)
	if len(args) == 0 {
		return fenceTargets{}, false, ""
	}
	cmd, rest, inner, opaque, reason := PeelCommand(args)
	if opaque {
		return fenceTargets{}, true, reason
	}
	if inner != "" {
		return analyzeCommandObjects(inner, workDir, depth+1)
	}
	switch {
	case cmd == "":
		// 纯 shell 语法/重定向；字面目标已由旧提取器处理。
		return fenceTargets{}, false, ""
	case cmd == "__shell_script__":
		if len(rest) == 0 {
			return fenceTargets{}, true, "shell 脚本路径缺失，无法确定网络对象"
		}
		data, ok := readFenceFile(workDir, substituteVars(rest[0], vars))
		if !ok {
			return fenceTargets{}, true, fmt.Sprintf("无法读取 shell 脚本 %q（仅允许任务工作目录内文件）", rest[0])
		}
		return analyzeCommandObjects(string(data), workDir, depth+1)
	case interpreterCommands[cmd]:
		return analyzeInterpreter(cmd, rest, workDir, vars)
	case isConnectionCommand(cmd):
		sub, cop, creason := analyzeKnownCommand(cmd, rest, workDir, vars)
		if cop {
			return sub, true, creason
		}
		// 管道末端的连接类命令若没有显式目标参数,目标来自 stdin
		// (cat subs.txt | httpx 是 recon 流水线的标准形态)——静态
		// 不可见,fail-closed 转人工;与 xargs 的 stdin 规则同口径。
		if sub.empty() && piped {
			return sub, true, fmt.Sprintf("%s 无显式目标参数：目标来自管道输入，无法静态确定网络对象", cmd)
		}
		return sub, false, ""
	case urlOnlyCommands[cmd]:
		return extractURLsFromText(strings.Join(rest, " ")), false, ""
	case localOnlyCommands[cmd], infraCommands[cmd], shellControlKeywords[cmd]:
		// 明确本地/基础设施命令，不产生目标。
		return fenceTargets{}, false, ""
	default:
		// 长尾本地工具（pgrep/lsof/strace…数百个）不可能枚举穷尽，
		// 按「有无网络特征」判定而非按名单打地鼠（2026-10-29：pgrep 白名单
		// 漏项把纯本地查询挡进审批）。无特征 → 按本地放行（此时段内字面
		// IP/域名【不会】被提取——字面兜底扫描只在 Opaque 时运行，这是
		// 「宁漏勿扰」的既定取舍）；有特征 → 维持 fail-closed 转人工。
		if reNetworkIndicator.MatchString(strings.Join(rest, " ")) || reNetworkIndicator.MatchString(cmd) {
			return fenceTargets{}, true, fmt.Sprintf("未识别的命令 %q：包含网络调用特征，无法静态确定其网络对象", cmd)
		}
		return fenceTargets{}, false, ""
	}
}

// peelCommand 剥掉包装命令，返回真正执行动作的命令。
// inner 非空表示内部脚本（sh -c / eval / watch 单字符串）。
// functionBody returns the command text after `{` when seg is a shell function
// definition (`name() { ... }` / `function name { ... }`). Empty otherwise.
func functionBody(seg string) string {
	i := strings.IndexByte(seg, '{')
	if i < 0 {
		return ""
	}
	head := strings.TrimSpace(seg[:i])
	if !strings.Contains(head, "()") && !strings.HasPrefix(head, "function ") {
		return ""
	}
	return strings.TrimSpace(seg[i+1:])
}

func PeelCommand(args []string) (cmd string, rest []string, inner string, opaque bool, reason string) {
	for len(args) > 0 {
		head := strings.TrimSpace(args[0])
		if head == "" {
			args = args[1:]
			continue
		}
		// 变量赋值 / 重定向 / shell 控制关键字。
		if strings.HasPrefix(head, ">") || strings.HasPrefix(head, "<") {
			args = args[1:]
			continue
		}
		if strings.Contains(head, "=") && !strings.HasPrefix(head, "-") && validAssign(head) {
			args = args[1:]
			continue
		}
		c := baseCommand(head)
		switch c {
		case "for", "while", "until", "if", "case", "select", "function":
			// 控制结构头部本身不是命令；真正的命令在后续 do/then/body 段。
			return "", nil, "", false, ""
		}
		if shellControlKeywords[c] {
			args = args[1:]
			continue
		}
		switch c {
		case "sudo":
			args = skipFlagsWithValues(args[1:], map[string]bool{"-u": true, "-g": true, "-C": true, "-p": true, "-r": true, "-t": true, "-T": true, "-U": true, "-h": true, "-D": true})
		case "doas":
			args = skipFlagsWithValues(args[1:], map[string]bool{"-u": true, "-C": true})
		case "env":
			if inner, ok := envSplitString(args[1:]); ok {
				return "", nil, inner, false, ""
			}
			args = skipEnv(args[1:])
		case "timeout":
			rest = args[1:]
			rest = skipFlagsWithValues(rest, map[string]bool{"-s": true, "-k": true, "--signal": true, "--kill-after": true})
			if len(rest) > 0 {
				rest = rest[1:] // duration
			}
			args = rest
		case "nice":
			args = skipFlagsWithValues(args[1:], map[string]bool{"-n": true, "--adjustment": true})
		case "nohup", "setsid", "unbuffer", "command", "builtin", "exec":
			args = skipSimpleFlags(args[1:])
		case "stdbuf":
			args = skipFlagsWithValues(args[1:], map[string]bool{"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true})
		case "ionice":
			args = skipFlagsWithValues(args[1:], map[string]bool{"-c": true, "-n": true, "-p": true, "-P": true, "-u": true})
		case "script":
			for i, tok := range args[1:] {
				if tok == "-c" && i+2 < len(args) {
					return "", nil, args[i+2], false, "" // -c 的脚本是真正的命令
				}
			}
			args = skipFlagsWithValues(args[1:], map[string]bool{"-E": true, "-T": true, "-I": true, "-O": true, "-B": true, "-m": true, "-a": true})
			if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
				args = args[1:] // output file
			}
		case "chroot":
			args = skipFlagsWithValues(args[1:], map[string]bool{"--userspec": true, "--groups": true})
			if len(args) > 0 {
				args = args[1:] // new root
			}
		case "busybox":
			if len(args) > 1 {
				args = args[1:]
				continue
			}
			return "", nil, "", false, ""
		case "xargs":
			rest = skipFlagsWithValues(args[1:], map[string]bool{"-I": true, "-n": true, "-P": true, "-L": true, "-s": true, "-d": true, "-E": true, "-a": true})
			if len(rest) == 0 {
				return "echo", nil, "", false, "" // xargs 默认 echo，不联网
			}
			// xargs 把 stdin 追加到内部命令后面；内部命令是出网命令且没有
			// 显式目标时，对象来自 stdin，静态不可知 → fail-closed。
			if isConnectionCommand(baseCommand(rest[0])) {
				explicit := false
				for _, a := range rest[1:] {
					if a != "" && !strings.HasPrefix(a, "-") {
						explicit = true
						break
					}
				}
				if !explicit {
					return "", nil, "", true, "xargs 的目标来自 stdin，无法静态确定网络对象"
				}
			}
			args = rest
			continue
		case "find":
			if exec := findExecCommand(args[1:]); len(exec) > 0 {
				args = exec
				continue
			}
			return "find", nil, "", false, ""
		case "watch":
			rest = skipFlagsWithValues(args[1:], map[string]bool{"-n": true, "--interval": true, "-d": true, "--differences": true, "-q": true})
			if len(rest) == 0 {
				return "", nil, "", true, "watch 缺少要执行的命令"
			}
			if len(rest) == 1 {
				return "", nil, rest[0], false, ""
			}
			args = rest
			continue
		case "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish":
			return peelShell(args)
		case "eval":
			return "", nil, strings.Join(args[1:], " "), false, ""
		case ".", "source":
			if len(args) > 1 {
				return "__shell_script__", args[1:], "", false, ""
			}
			return "", nil, "", true, "source 缺少脚本路径"
		case "su", "runuser", "parallel", "entr":
			return "", nil, "", true, fmt.Sprintf("%q 会执行任意子命令，无法静态确定网络对象", c)
		default:
			return c, args[1:], "", false, ""
		}
	}
	return "", nil, "", false, ""
}

func peelShell(args []string) (string, []string, string, bool, string) {
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		tok := rest[i]
		if tok == "--" {
			rest = rest[i+1:]
			break
		}
		if tok == "-c" || (strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "--") && strings.Contains(tok, "c")) {
			if i+1 < len(rest) {
				return "", nil, strings.Join(rest[i+1:], " "), false, ""
			}
			return "", nil, "", true, "shell -c 缺少脚本内容"
		}
		if strings.HasPrefix(tok, "-") {
			continue
		}
		return "__shell_script__", []string{tok}, "", false, ""
	}
	return "", nil, "", true, "shell 从 stdin 读取脚本：无法静态确定网络对象"
}

func skipSimpleFlags(args []string) []string {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		args = args[1:]
	}
	return args
}

func skipFlagsWithValues(args []string, valueFlags map[string]bool) []string {
	for len(args) > 0 {
		tok := args[0]
		if tok == "--" {
			return args[1:]
		}
		if !strings.HasPrefix(tok, "-") {
			return args
		}
		// --flag=value 形态自身已带值。
		if strings.Contains(tok, "=") {
			args = args[1:]
			continue
		}
		if valueFlags[tok] {
			if len(args) > 1 {
				args = args[2:]
			} else {
				args = args[1:]
			}
			continue
		}
		args = args[1:]
	}
	return args
}

// envSplitString 处理 `env -S 'nmap ...'`：值本身就是要执行的命令字符串。
func envSplitString(args []string) (string, bool) {
	for i, tok := range args {
		if tok == "--" {
			return "", false
		}
		if tok == "-S" || tok == "--split-string" {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if !strings.HasPrefix(tok, "-") {
			return "", false
		}
	}
	return "", false
}

func skipEnv(args []string) []string {
	for len(args) > 0 {
		tok := args[0]
		switch {
		case tok == "-i" || tok == "-0" || tok == "--ignore-environment" || tok == "--null":
			args = args[1:]
		case tok == "-u" || tok == "--unset":
			args = args[2:]
		case strings.HasPrefix(tok, "--unset="):
			args = args[1:]
		case strings.Contains(tok, "=") && !strings.HasPrefix(tok, "-"):
			args = args[1:]
		case tok == "-S" || tok == "--split-string":
			if len(args) > 1 {
				// -S 的值本身是命令字符串。
				return []string{args[1]}
			}
			return nil
		case strings.HasPrefix(tok, "-"):
			args = args[1:]
		default:
			return args
		}
	}
	return args
}

func findExecCommand(args []string) []string {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-exec", "-execdir", "-ok", "-okdir":
			var out []string
			for j := i + 1; j < len(args); j++ {
				if args[j] == ";" || args[j] == "+" {
					break
				}
				out = append(out, args[j])
			}
			return out
		}
	}
	return nil
}

// analyzeKnownCommand 处理已知出网命令：先读目标列表文件，再交给旧提取器
// 按该命令的旗标/位置参数取对象。vars 是整段命令的变量赋值表(dig "$d" 的
// 目标在变量里,代入后才可见)。
func analyzeKnownCommand(cmd string, rest []string, workDir string, vars map[string]string) (fenceTargets, bool, string) {
	// 先按命令自身的对象规则扫描参数（已剥包装，sh -c/xargs/find -exec 的
	// 内部命令也会走到这里）。
	c := newFenceCollector(vars)
	scanCommandTargets(cmd, rest, c)
	out := c.result()
	if flags := targetFileFlags[cmd]; len(flags) > 0 {
		for i := 0; i < len(rest); i++ {
			if !flags[rest[i]] {
				continue
			}
			if i+1 >= len(rest) {
				return out, true, fmt.Sprintf("%s %s 缺少文件路径", cmd, rest[i])
			}
			// 清单路径可能来自变量(nmap -iL "$list"),代入后再读。
			data, ok := readFenceFile(workDir, substituteVars(rest[i+1], vars))
			if !ok {
				return out, true, fmt.Sprintf("无法读取目标列表 %q（仅允许任务工作目录内文件）", rest[i+1])
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				lineCollector := newFenceCollector(nil)
				scanCommandTargets(cmd, []string{line}, lineCollector)
				mergeFenceTargets(&out, lineCollector.result())
			}
		}
	}
	// ssh 的远程命令 / ProxyCommand 可以再发起任意网络请求，目标不在
	// 参数表面；出现网络调用时 fail-closed。
	if cmd == "ssh" {
		hostSeen := false
		for _, a := range rest {
			if strings.Contains(a, "ProxyCommand") || strings.Contains(a, "proxycommand") {
				return out, true, "ssh ProxyCommand 可执行任意联网命令，无法静态确定网络对象"
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			if !hostSeen {
				hostSeen = true
				continue
			}
			if reNetworkIndicator.MatchString(a) {
				return out, true, "ssh 远程命令包含网络调用，无法静态确定网络对象"
			}
		}
	}
	// curl -K/--config 可包含任意选项，静态解析不可靠：直接 fail-closed。
	if cmd == "curl" {
		for _, tok := range rest {
			if tok == "-K" || tok == "--config" {
				return out, true, "curl -K/--config 的配置文件可包含任意目标与选项，无法静态确定网络对象"
			}
		}
		// --resolve host:port:addr 的实际连接对象包含 addr。
		for i := 0; i+1 < len(rest); i++ {
			if rest[i] == "--resolve" {
				parts := strings.SplitN(rest[i+1], ":", 3)
				if len(parts) == 3 {
					resolveCollector := newFenceCollector(nil)
					scanCommandTargets("curl", []string{parts[2]}, resolveCollector)
					mergeFenceTargets(&out, resolveCollector.result())
				}
			}
		}
	}
	// 已知命令的字面目标已由 extractFenceTargetsLegacy 在原始文本上提取；
	// 这里只补充文件清单 / --resolve 这类“对象在参数之外”的目标，避免把
	// 命令重新拼回字符串时破坏引号语义。
	if out.empty() {
		for _, tok := range rest {
			if strings.ContainsAny(tok, "$`{}") {
				return out, true, fmt.Sprintf("%s 的目标包含动态占位符，无法静态确定网络对象", cmd)
			}
		}
	}
	return out, false, ""
}

// analyzeInterpreter 处理 python/node/...：能读到代码/脚本时提取 URL 对象；
// 出现网络调用则保留 Opaque（动态目标无法穷举）；读不到脚本则 fail-closed。
// vars 供脚本路径/-c 代码的变量代入（f=scan.py; python3 "$f" 与
// for f in *.py; do python3 "$f"; done 两类形态都靠它落到真实文件）。
func analyzeInterpreter(cmd string, rest []string, workDir string, vars map[string]string) (fenceTargets, bool, string) {
	var out fenceTargets
	code, script, module := interpreterInput(rest)
	if module != "" {
		return out, true, fmt.Sprintf("%s -m/--module 执行外部模块，无法静态确定网络对象", cmd)
	}
	// python --version / node -v / java -version 这类只读版本/帮助调用不联网。
	if code == "" && script == "" && harmlessInterpreterInvocation(rest) {
		return out, false, ""
	}
	code = substituteVars(code, vars)
	script = substituteVars(script, vars)
	if code != "" {
		out = extractURLsFromText(code)
		// 字面兜底（与命令文本路径同款）：脚本体内写死的 IPv4/URL 要进结果，
		// 围栏才能对「全部字面目标均已授权」自动放行（如 HOST="49.51.48.17" 元组赋值）。
		mergeFenceTargets(&out, sweepLiteralTargets(code))
		if reNetworkIndicator.MatchString(code) {
			return out, true, fmt.Sprintf("%s 内联代码包含网络调用，静态只识别到部分目标", cmd)
		}
		return out, false, ""
	}
	if script != "" {
		data, ok := readFenceFile(workDir, script)
		if !ok {
			// 动态路径与目录外文件是两种不同的情况,审批文案要能区分:
			// 前者人也没法替 agent 读,只能按脚本能去任何地方来裁决。
			if strings.Contains(script, "$") {
				return out, true, fmt.Sprintf("%s 脚本路径 %q 含变量，静态无法读取脚本内容", cmd, script)
			}
			return out, true, fmt.Sprintf("无法读取 %s 脚本 %q（仅允许任务工作目录内文件）", cmd, script)
		}
		text := string(data)
		out = extractURLsFromText(text)
		mergeFenceTargets(&out, sweepLiteralTargets(text))
		if reNetworkIndicator.MatchString(text) {
			return out, true, fmt.Sprintf("%s 脚本包含网络调用，静态只识别到部分目标", cmd)
		}
		return out, false, ""
	}
	return out, true, fmt.Sprintf("%s 未提供可静态分析的代码/脚本，无法确定网络对象", cmd)
}

func harmlessInterpreterInvocation(rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	for _, a := range rest {
		switch a {
		case "-v", "-V", "--version", "-version", "--help", "-h", "-?":
			continue
		default:
			return false
		}
	}
	return true
}

func interpreterInput(rest []string) (code, script, module string) {
	for i := 0; i < len(rest); i++ {
		tok := rest[i]
		switch tok {
		case "-c", "-e", "-r", "--eval", "-Command", "-command":
			if i+1 < len(rest) {
				return strings.Join(rest[i+1:], " "), "", ""
			}
			return "", "", ""
		case "-m", "--module":
			if i+1 < len(rest) {
				return "", "", rest[i+1]
			}
			return "", "", "-"
		case "-jar":
			return "", "", "-jar"
		}
		if strings.HasPrefix(tok, "-") {
			// 解释器旗标（-u/-B/-I/-W/-X...）跳过；其值可能被误当脚本，
			// 但后续 fail-closed 会兜住不可读路径。
			continue
		}
		return "", tok, ""
	}
	return "", "", ""
}

func extractURLsFromText(s string) fenceTargets {
	var out fenceTargets
	for _, m := range reURLObject.FindAllString(s, -1) {
		mergeFenceTargets(&out, extractFenceTargetsLegacy(m))
	}
	return out
}

func readFenceFile(workDir, path string) ([]byte, bool) {
	workDir = strings.TrimSpace(workDir)
	path = strings.TrimSpace(path)
	if workDir == "" || path == "" {
		return nil, false
	}
	root, err := filepath.Abs(workDir)
	if err != nil {
		return nil, false
	}
	target := path
	if !filepath.IsAbs(target) {
		target = filepath.Join(root, target)
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return nil, false
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, false
	}
	info, err := os.Stat(target)
	if err != nil || info.IsDir() || info.Size() > 4<<20 {
		return nil, false
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return nil, false
	}
	return data, true
}

func mergeFenceTargets(dst *fenceTargets, src fenceTargets) {
	dst.Domains = mergeStringSet(dst.Domains, src.Domains)
	dst.IPs = mergeStringSet(dst.IPs, src.IPs)
}

func mergeStringSet(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, group := range [][]string{a, b} {
		for _, s := range group {
			s = strings.TrimSpace(s)
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func validAssign(s string) bool {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return false
	}
	for j, r := range s[:i] {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (j > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}
