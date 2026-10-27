package poc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// IntelInput is the advisory a caller wants turned into an artifact. It is
// the subset of core.IntelItem the prompts actually use, plus the enrichment
// fields (affected / github_poc) that exist only after a host has enriched an
// advisory.
type IntelInput struct {
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Affected    []string `json:"affected,omitempty"`
	Solutions   string   `json:"solutions,omitempty"`
	GithubPoc   []string `json:"github_poc,omitempty"`
}

// Analysis is the structured write-up of one advisory.
type Analysis struct {
	TitleZh       string `json:"title_zh"`
	DescriptionZh string `json:"description_zh"`
	Principle     string `json:"principle"`
	AttackScope   string `json:"attack_scope"`
	POC           *POC   `json:"poc"`
	POCOrigin     string `json:"poc_origin"` // ai | upstream | none
	// POCNote explains why no script was produced when POC is nil. It is an
	// operator-facing sentence, not a machine code.
	POCNote string `json:"poc_note,omitempty"`
}

// POC is a runnable verification script built by buildPoCScript. Language is
// always "python" today; it stays a field so a host can dispatch on it.
type POC struct {
	Language string   `json:"language"`
	Code     string   `json:"code"`
	Spec     *PoCSpec `json:"spec,omitempty"` // the elements the script was built from
}

// PoC origins. "upstream" means the advisory already links a public exploit
// repository, so generating code would be inventing what the source did not
// provide.
const (
	pocOriginAI       = "ai"
	pocOriginUpstream = "upstream"
	pocOriginNone     = "none"
)

const (
	analysisMaxTokens = 3000
	analysisTimeout   = 3 * time.Minute
	indicatorTokens   = 800
	indicatorTimeout  = 60 * time.Second
	fingerprintTokens = 600
	fingerprintTO     = 60 * time.Second
)

const sysAnalysis = `你是资深漏洞分析专家，熟悉漏洞披露通告、CVE 与可利用性验证。把一条漏洞情报整理成结构化的中文分析，严格只输出 JSON，不要 markdown 代码块，不要任何额外解释。

铁律：
- 只依据给定情报与公开的漏洞原理作答。**不要臆造**厂商、版本号、接口路径、参数名等具体信息；无法确定的字段留空字符串，不要编造。
- CVE 编号、组件名、函数名、接口路径一律保留原文，不要翻译、不要改写大小写。
- **不要写 PoC 代码**。你只填「验证要素」poc_spec，脚本由程序按固定骨架拼装：
  - path：能触发该漏洞的入口路径，必须以 / 开头，且必须能在情报原文里找到出处；找不到就留空。
  - method：GET 或 POST。
  - params：这次探测要带的参数（名字 + 无害的验证值）。参数名尽量用情报原文出现过的。
  - body_format：POST 用 form 还是 json。
  - marker：目标存在漏洞时响应里会出现的特征字符串，必须能在情报原文里找到出处（特征文件名、报错关键字、版本号等）；给不出就留空。**不要**用 error、success、true 这类任何响应都会出现的泛词。
  - match_status：仅凭状态码即可判定时填写（如 200），否则填 0。
  - evidence：一句话说明判定依据。
  - constructible：情报不足以构造出能验证该漏洞的请求时置 false，并在 reason 里说明缺什么。宁可说构造不出，也不要编造入口或参数。
- 只做无损的验证性探测，**不得**包含破坏性、持久化或横向移动操作。
- 输出字段：title_zh(中文标题，简短)、description_zh(中文简介，2-4 句)、principle(漏洞原理，说明成因与触发条件)、attack_scope(攻击范围，说明影响的产品/版本/前置条件)、poc_spec(上述对象)。`

const userAnalysis = `请分析以下漏洞情报。

标题：%s
严重等级：%s
CVE：%s
所属标签/受影响组件：%s
描述：%s
处置建议：%s
已知 PoC 仓库（若为空表示暂无公开 PoC）：%s

只输出如下 JSON：
{"title_zh":"","description_zh":"","principle":"","attack_scope":"","poc_spec":{"constructible":false,"reason":"","method":"GET","path":"","params":[],"body_format":"form","marker":"","match_status":0,"evidence":""}}`

const sysIndicators = `你是 nuclei 模板工程师。根据漏洞情报给出「判断目标是否存在该漏洞」所需的最小 HTTP 探测指标，严格只输出 JSON，不要 markdown 代码块。

铁律：
- path 是该漏洞的典型入口路径（以 / 开头）；无法确定时给 "/"。
- words 是响应中能佐证命中漏洞的特征字符串，必须具体（版本号、特征文件名、报错关键字等），**不要**用 "error"、"success"、"true" 这类在任何响应里都会出现的泛词。
- 只做无害的探测，不要给出破坏性请求。
- 输出字段：method(GET 或 POST)、path、words(字符串数组)、regex(字符串数组，可为空)。`

const userIndicators = `漏洞标题：%s
CVE：%s
组件/标签：%s
漏洞原理：%s

只输出 JSON：{"method":"GET","path":"/","words":[],"regex":[]}`

const sysFingerprint = `你是资深资产指纹专家，熟悉 Web 产品的页面/响应头特征。把一条漏洞情报整理成一条**资产指纹规则**（用于识别「这台机器上装的是不是这个受影响产品」），严格只输出 JSON，不要 markdown 代码块，不要任何额外解释。

铁律：
- 只能使用情报里**已经出现过的字样**作为匹配特征（产品名、组件名、默认路径、响应头名、页面片段）。**不要臆造**版本号、路径、页面文本或接口；情报里没有的特征一律不要写。
- patterns 每一项的 type 只能是 body/header/cookie/url/title/script/meta/favicon；header/cookie/meta 需要 part 指定键名；value 是字面包含匹配，若写成正则需把 regex 置为 true。
- 规则必须能把该产品与其他站点区分开：至少有一个 item 落在 body/title/header/cookie/url 上，值长度不少于 5 个字符；不要用 200、"html"、"login" 这类几乎谁都命中的条件。
- 建议用 2-3 个 item 组合以减少误报；只有特征本身足够独特时才用单个 item。
- name 用产品/组件名（中文或英文均可，不要带 CVE 号），category 用小写英文分类（framework/cms/middleware/plugin ...），判断不了就填 other。
- 情报里找不到任何可用于区分的特征时，把 patterns 置为空数组。

只输出如下 JSON：
{"name":"","product":"","category":"","patterns":[{"type":"body","value":""}],"reason":""}`

const userFingerprint = `请为以下漏洞情报生成一条资产指纹规则。

标题：%s
CVE：%s
严重等级：%s
标签/受影响组件：%s
描述：%s

只输出如下 JSON：
{"name":"","product":"","category":"","patterns":[{"type":"body","value":""}],"reason":""}`

type analysisOut struct {
	TitleZh       string   `json:"title_zh"`
	DescriptionZh string   `json:"description_zh"`
	Principle     string   `json:"principle"`
	AttackScope   string   `json:"attack_scope"`
	POCSpec       *PoCSpec `json:"poc_spec"`
}

type indicatorOut struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Words  []string `json:"words"`
	Regex  []string `json:"regex"`
}

// generateAnalysis asks the model for the write-up and the verification
// elements, then assembles the PoC here. The model never writes the script:
// see pocscript.go for why.
//
// PoC provenance is decided by what exists, not by what the model claimed:
// code actually assembled here means "ai"; otherwise a linked public exploit
// repository means "upstream" (there is something to read, but capkit did not
// write it); otherwise "none".
func (k *Kit) generateAnalysis(ctx context.Context, in IntelInput) (Analysis, error) {
	raw, err := k.complete(ctx, sysAnalysis, fmt.Sprintf(userAnalysis,
		in.Title, orDash(in.Severity), orDash(in.CVE), strings.Join(in.Tags, ", "),
		orDash(in.Description), orDash(in.Solutions), strings.Join(in.GithubPoc, ", "),
	), analysisMaxTokens, analysisTimeout)
	if err != nil {
		return Analysis{}, err
	}
	var out analysisOut
	if err := unmarshalLoose(raw, &out); err != nil {
		return Analysis{}, err
	}
	if strings.TrimSpace(out.Principle) == "" && strings.TrimSpace(out.DescriptionZh) == "" {
		return Analysis{}, fmt.Errorf("模型未返回有效分析内容")
	}
	a := Analysis{
		TitleZh:       strings.TrimSpace(out.TitleZh),
		DescriptionZh: strings.TrimSpace(out.DescriptionZh),
		Principle:     strings.TrimSpace(out.Principle),
		AttackScope:   strings.TrimSpace(out.AttackScope),
	}
	// The write-up often names the entry point the advisory left implicit, so
	// grounding looks at both.
	corpus := intelCorpus(in, a.Principle, a.DescriptionZh, a.AttackScope)
	switch {
	case out.POCSpec != nil:
		spec := *out.POCSpec
		code, note, perr := buildPoCScript(in, corpus, spec)
		if perr != nil {
			a.POCNote = perr.Error()
		} else {
			a.POC = &POC{Language: "python", Code: code, Spec: &spec}
			a.POCOrigin = pocOriginAI
			a.POCNote = note
		}
	case len(in.GithubPoc) > 0:
		a.POCOrigin = pocOriginUpstream
		a.POCNote = "情报已给出公开 PoC 仓库，未另行生成脚本"
	default:
		a.POCOrigin = pocOriginNone
		a.POCNote = "模型未给出可用的验证要素，未生成 PoC"
	}
	// A spec that could not be assembled still leaves the origin to report:
	// there is public exploit code to read, or there is nothing.
	if a.POC == nil && a.POCOrigin == "" {
		if len(in.GithubPoc) > 0 {
			a.POCOrigin = pocOriginUpstream
		} else {
			a.POCOrigin = pocOriginNone
		}
	}
	return a, nil
}

// suggestIndicators asks for the minimal HTTP probe. A failure is not fatal:
// the deterministic skeleton still produces a usable template with a "/" path.
func (k *Kit) suggestIndicators(ctx context.Context, in IntelInput, principle string) (indicatorOut, error) {
	var out indicatorOut
	raw, err := k.complete(ctx, sysIndicators, fmt.Sprintf(userIndicators,
		in.Title, orDash(in.CVE), strings.Join(in.Tags, ", "), orDash(principle),
	), indicatorTokens, indicatorTimeout)
	if err != nil {
		return out, err
	}
	if err := unmarshalLoose(raw, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (k *Kit) suggestFingerprint(ctx context.Context, in IntelInput) (FingerprintDraft, error) {
	var draft FingerprintDraft
	raw, err := k.complete(ctx, sysFingerprint, fmt.Sprintf(userFingerprint,
		in.Title, orDash(in.CVE), orDash(in.Severity), strings.Join(in.Tags, ", "), orDash(in.Description),
	), fingerprintTokens, fingerprintTO)
	if err != nil {
		return draft, err
	}
	if err := unmarshalLoose(raw, &draft); err != nil {
		return draft, err
	}
	return draft, nil
}

// complete is the single place the kit talks to the model port. The host owns
// the profile, temperature and budget; the kit only states what it wants.
func (k *Kit) complete(ctx context.Context, system, user string, maxTokens int, timeout time.Duration) (string, error) {
	if k.completer == nil {
		return "", core.Unavailable("宿主未配置模型端口，无法生成内容")
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := k.completer.Complete(callCtx, system, user, maxTokens)
	if err != nil {
		return "", fmt.Errorf("调用模型失败: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("模型返回空响应")
	}
	return raw, nil
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "（无）"
	}
	return s
}

// decodeInput reads the tool input, filling the analysis when the caller
// passes a pre-generated one so the template path can reuse the principle
// instead of paying for a second model call.
func decodeInput(call core.Call) (IntelInput, error) {
	var wrapper struct {
		IntelInput
		Analysis *struct {
			Principle     string `json:"principle"`
			DescriptionZh string `json:"description_zh"`
		} `json:"analysis"`
	}
	if len(call.Input) > 0 {
		if err := json.Unmarshal(call.Input, &wrapper); err != nil {
			return IntelInput{}, err
		}
	}
	if strings.TrimSpace(wrapper.Title) == "" && strings.TrimSpace(wrapper.CVE) == "" {
		return IntelInput{}, fmt.Errorf("title 或 cve 至少需要一个")
	}
	in := wrapper.IntelInput
	if wrapper.Analysis != nil {
		// The principle is the richest prompt material for the indicator call,
		// so it takes precedence over the raw description when present.
		switch {
		case strings.TrimSpace(wrapper.Analysis.Principle) != "":
			in.Description = wrapper.Analysis.Principle
		case in.Description == "":
			in.Description = wrapper.Analysis.DescriptionZh
		}
	}
	return in, nil
}
