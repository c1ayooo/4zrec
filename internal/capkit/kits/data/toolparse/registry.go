// Package toolparse 提供外部 CLI 工具的结构化输出解析与事实黑板自动落库。
//
// 设计见 docs/工具结构化输出与事实黑板打通-改造档案.md §四：
//   - 输出层：executor 挂钩层把平台独占输出标志注入 argv（模型不可覆盖），
//     纯 stdout 模式直接产出结构化内容，落文件模式（-o/-of/--log-xml）由
//     挂钩层把结构化文件内容并入 stdout 后再交给解析器（§4.3 runner 契约）。
//   - 解析层：按工具名分发到注册的 Parser，产出 Result（关键字段 + 事实候选 + raw_ref）。
//   - 落库层：store.go 把事实候选写入 project_facts / assets（同步、失败不阻断、fail-closed）。
//
// 解析失败一律回退现状（原文 + 截断 + spill），不落任何事实（§4.7）。
package toolparse

import (
	"fmt"
	"strings"
)

// FactLink 事实关系边（from → 当前 fact_key）。
type FactLink struct {
	From string `json:"from"`
	Type string `json:"type"`
}

// FactCandidate 结构化 → 事实黑板的一条候选（落库层消费）。
// 字段口径与 upsert_project_fact 工具一致（见 internal/app/project_fact_tools.go）。
type FactCandidate struct {
	FactKey    string     `json:"fact_key"`   // 必须符合既有约定：<category>/<slug>（§4.5 规则 1）
	Category   string     `json:"category"`   // finding|target|infra|auth|...（既有枚举，禁止新增）
	Summary    string     `json:"summary"`    // 「什么+在哪+如何验证」
	Body       string     `json:"body"`       // 复现细节（命令/证据摘录；原始输出不写入，只挂 raw_ref）
	Confidence string     `json:"confidence"` // tentative|confirmed（解析器不得直接写升级判定）
	Links      []FactLink `json:"links,omitempty"`
}

// Result 一个工具的解析结果。
type Result struct {
	Tool   string          `json:"tool"`
	OK     bool            `json:"ok"`
	Fields map[string]any  `json:"fields"`  // 关键字段（端口/状态码/技术栈…），只放标量与计数
	Facts  []FactCandidate `json:"facts"`   // 事实候选
	RawRef string          `json:"raw_ref"` // 原始证据落盘路径（read_file 可回读）
	Err    string          `json:"err,omitempty"`
}

// Parser 解析器接口。实现须对畸形/截断输入安全（fail-closed）：解析失败返回
// OK=false 且 Facts 为空，不得从半截文本猜事实。
type Parser interface {
	// Match 判定该解析器是否处理这次调用（按工具名 + 已注入的输出标志）。
	Match(tool string, argv []string) bool
	// Parse 解析原始输出（runner 契约见 §4.3：stdout 已含该模式最完整的结构化内容）。
	Parse(stdout, stderr string, rawRef string) (*Result, error)
}

// TargetAware 需要目标 URL 才能生成事实键的解析器（arjun/sqlmap 等结构化内容里无 host）。
// executor 挂钩层会把注入 argv 中的目标 URL 以 "TARGET: <url>\n" 前缀并入 stdout。
type TargetAware interface {
	NeedsTarget() bool
}

var registry = map[string]Parser{}

// Register 注册解析器（工具名 → 解析器，同名覆盖取最后一次）。
func Register(p Parser) {
	if p == nil {
		return
	}
	for _, tool := range parserTools(p) {
		registry[tool] = p
	}
}

// init 注册全部解析器（A/B/C 三档 16 个，见档案 §4.4；nuclei 复用 vulnverify 解析）。
func init() {
	Register(httpxParser{})
	Register(ffufParser{})
	Register(katanaParser{})
	Register(nucleiParser{})
	Register(nmapParser{})
	Register(sqlmapParser{})
	Register(dirsearchParser{})
	Register(dalfoxParser{})
	Register(arjunParser{})
	Register(wpscanParser{})
	Register(wafw00fParser{})
	Register(niktoParser{})
	Register(whatwebParser{})
	Register(fscanParser{})
	Register(hashcatParser{})
	Register(johnParser{})
}

// parserTools 从解析器自曝的工具名清单注册（避免每注册一个解析器手写一个 key）。
func parserTools(p Parser) []string {
	if t, ok := p.(interface{ Tools() []string }); ok {
		return t.Tools()
	}
	return nil
}

// Lookup 按工具名 + argv 找匹配解析器；未注册/未注入输出标志 → 保持现状（nil）。
func Lookup(tool string, argv []string) Parser {
	p, ok := registry[tool]
	if !ok {
		return nil
	}
	if !p.Match(tool, argv) {
		return nil
	}
	return p
}

// RegisteredTools 已注册解析器的工具名集合（调试/门禁自检用）。
func RegisteredTools() []string {
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	return out
}

// ── 平台独占注入描述 ──

// Injection 描述一次工具调用的平台注入：追加 argv 与执行后需并入 stdout 的文件。
type Injection struct {
	Tool string
	// Args 追加进 argv 的平台独占标志（filterDangerousFlags 之后、exec 之前，模型不可覆盖）。
	Args []string
	// ResultFileRel 相对注入目录的结果文件（目录由挂钩层生成：<workspace>/toolparse/<executionID>/）。
	// 该文件内容由挂钩层并入 stdout 供解析器消费；空 = 无落盘文件（纯 stdout 模式）。
	ResultFileRel string
	// 生成注入目录的子目录名（工具名，避免多文件互相覆盖）。
}

// injections 平台注入表（A/B/C 三档，见档案 §4.4；nuclei 走 vulnverify 链路不在此列）。
// 棘轮：只允许登记"已实现解析器"的工具——注入输出标志而无人解析 = 白注入（且会破坏
// 模型要读的文本输出形态）。补解析器时同步加回对应注入条目。
var injections = []Injection{
	// A 档：原生 JSON/JSONL 直出 stdout（ffuf -json 即 NDJSON 到 stdout，-of 需配合 -o 文件，不注入）
	{Tool: "httpx", Args: []string{"-json", "-silent"}},
	{Tool: "ffuf", Args: []string{"-json"}},
	{Tool: "katana", Args: []string{"-jsonl", "-or", "-ob"}},
	// B 档：nmap -oX - 直出 XML 到 stdout（-oX 在 dangerousFlagPrefixes 里仅拦截模型侧
	// additional_args；平台注入经 filter 之后追加，模型无法复刻该输出模式）
	{Tool: "nmap", Args: []string{"-oX", "-"}},
	// C 档：半结构化（判定行），无机器可读输出
	{Tool: "sqlmap", Args: []string{"--batch", "--output-dir", "<TMPDIR>"}},
	// fscan（C 档）：stdout 判定行 + result.txt 落文件并入（result.txt 的分段行比 stdout 更规整，
	// 且把结果文件收进平台 tmpdir，避免在工作区散落 result.txt）。文本形态不变，模型可读性不受影响。
	{Tool: "fscan", Args: []string{"-o", "<TMPDIR>/result.txt"}, ResultFileRel: "result.txt"},
	// 破解工具（C 档）：stdout 破解行 + potfile 并入。破解行 `<hash>:<plaintext>` 运行期即打印，
	// potfile 收进平台 tmpdir 再并入可兜住 stdout 漏行，且按次隔离不污染默认 ~/.hashcat/，
	// 破解命中自动落 auth/ confirmed 事实（凭据→横向联动的最后一步）。
	{Tool: "hashcat", Args: []string{"--potfile-path", "<TMPDIR>/hashcat.potfile"}, ResultFileRel: "hashcat.potfile"},
	// john：--pot= 指到平台 tmpdir（pot 行 `$NT$<hex>:<plain>` / krb 行内嵌 user$realm）；
	// 用户名来自 stdout 判定行 `password (user)` 与 --show 的 `login:password` 档案行。
	{Tool: "john", Args: []string{"--pot=<TMPDIR>/john.pot"}, ResultFileRel: "john.pot"},
	// 落文件模式（挂钩层生成 tmpdir 后替换 <TMPDIR> 并读取文件并入 stdout，§4.3 runner 契约）
	{Tool: "dirsearch", Args: []string{"-O", "json", "-o", "<TMPDIR>/result.json"}, ResultFileRel: "result.json"},
	{Tool: "dalfox", Args: []string{"--format", "jsonl", "-o", "<TMPDIR>/result.jsonl"}, ResultFileRel: "result.jsonl"},
	{Tool: "arjun", Args: []string{"-oJ", "<TMPDIR>/result.json"}, ResultFileRel: "result.json"},
	{Tool: "wpscan", Args: []string{"-f", "json", "-o", "<TMPDIR>/result.json"}, ResultFileRel: "result.json"},
	{Tool: "wafw00f", Args: []string{"-f", "json", "-o", "<TMPDIR>/result.json"}, ResultFileRel: "result.json"},
	{Tool: "nikto", Args: []string{"-Format", "xml", "-o", "<TMPDIR>/result.xml"}, ResultFileRel: "result.xml"},
	{Tool: "whatweb", Args: []string{"--log-xml=<TMPDIR>/result.xml"}, ResultFileRel: "result.xml"},
}

// InjectionFor 返回某工具的注入描述（未注册 → nil，保持现状零行为变化）。
func InjectionFor(tool string) *Injection {
	for i := range injections {
		if injections[i].Tool == tool {
			inj := injections[i]
			return &inj
		}
	}
	return nil
}

// InjectedTools 注入表覆盖的工具名集合（供挂钩层判断"是否需要走结构化通道"）。
func InjectedTools() []string {
	out := make([]string, 0, len(injections))
	for _, inj := range injections {
		out = append(out, inj.Tool)
	}
	return out
}

// 注入目录模板占位符（挂钩层执行前替换为实际 tmpdir）。
const TmpDirPlaceholder = "<TMPDIR>"

// ResolveArgs 把注入 argv 里的目录占位符替换为实际 tmpdir（幂等）。
func (inj *Injection) ResolveArgs(tmpdir string) []string {
	out := make([]string, 0, len(inj.Args))
	for _, a := range inj.Args {
		out = append(out, strings.ReplaceAll(a, TmpDirPlaceholder, tmpdir))
	}
	return out
}

// ResolveResultPath 返回结果文件的绝对路径（无 ResultFileRel 返回 ""）。
func (inj *Injection) ResolveResultPath(tmpdir string) string {
	if inj.ResultFileRel == "" {
		return ""
	}
	return tmpdir + "/" + strings.TrimPrefix(inj.ResultFileRel, "/")
}

// ── fact_key 工具函数（§4.5 规则 1）──

// ValidCategories 既有 fact_key category 前缀白名单（禁止新增，见档案 §十）。
var ValidCategories = map[string]bool{
	"finding":  true,
	"chain":    true,
	"exploit":  true,
	"poc":      true,
	"target":   true,
	"auth":     true,
	"infra":    true,
	"business": true,
}

// Sluggify 把 host/路径等转成 fact_key slug：全小写、保留 :/.、空格→-、去 URL scheme。
func Sluggify(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	// 去 URL scheme（http:// https://）
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// 去路径尾（fact_key 用 host[:port]，不带 /path）
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == ':', r == '.', r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		case r == '_':
			b.WriteByte('-')
		default:
			// 其他字符（含中文/特殊符号）转 -
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// ValidateFactKey 校验 fact_key 前缀与整体形态（与既有 ValidateFactKey 同口径，
// 见 internal/database/project_fact_edges.go；此处为 toolparse 侧前置校验，落库前还会再过一次 DB 层）。
func ValidateFactKey(factKey string) error {
	if factKey == "" {
		return fmt.Errorf("fact_key 为空")
	}
	parts := strings.SplitN(factKey, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("fact_key %q 必须为 <category>/<slug> 形式", factKey)
	}
	if !ValidCategories[parts[0]] {
		return fmt.Errorf("fact_key %q 的 category %q 不在既有枚举内（finding|chain|exploit|poc|target|auth|infra|business）", factKey, parts[0])
	}
	if strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("fact_key %q slug 为空", factKey)
	}
	return nil
}

// hasFlag 判定 argv 是否含指定标志（解析器 Match 用；精确匹配与 -flag=value 两种形态）。
func hasFlag(argv []string, flag string) bool {
	for _, a := range argv {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}
