// 情报 → 指纹规则(fingerprint_rules)草稿(fpgen)。指纹回答的是「这台机器上
// 是不是装着受影响的产品」,与 nuclei 模板(「怎么验这个洞」)是两件事:
// 入库后 fingerprint_scan / enrich 用它识别资产,而 nuclei 扫描又以指纹证据
// 为门禁 —— 没有指纹证据的目标连扫都不让扫。
//
// 与 tplgen 同一取向:表达式必须能被平台的 fingerprint.ParseExpression 接受,
// 且必须落在情报已经给出的字样上(产品名/默认路径/响应头/页面特征)。模型
// 给不出可核验的特征时**不产草稿**——一条匹配任意站点的指纹比没有指纹更糟。
package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/recon/fingerprint"
	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// FingerprintSink 由宿主注入:把确认后的指纹规则写进规则库,返回规则 id。
// 能力包不直接持有指纹 Store(那是 recon 侧的东西)。
type FingerprintSink func(name, category, expression string) (string, error)

const (
	fpMaxTokens = 600
	fpTimeout   = 60 * time.Second
)

// FingerprintDraft 是一条待人工确认的指纹规则草稿(存成 JSON 文本)。
type FingerprintDraft struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Expression string `json:"expression"`
	Reason     string `json:"reason,omitempty"`
}

const sysFingerprint = `你是资深资产指纹专家，熟悉 Web 产品的页面/响应头特征与指纹表达式语法。把一条漏洞情报整理成一条**资产指纹规则**（用于识别"这台机器上装的是不是这个受影响产品"），严格只输出 JSON，不要 markdown 代码块，不要任何额外解释。

铁律：
- 只能使用情报里**已经出现过的字样**作为匹配特征（产品名、组件名、默认路径、响应头名、页面片段）。**不要臆造**版本号、路径、页面文本或接口；情报里没有的特征一律不要写。
- 表达式语法：字段 操作符 "值"，字段只允许 header/cookie/body/server/title/cert/status/content_type/path/banner/port/protocol/body_hash/icon_hash；操作符只允许 =、!=、==、~=（正则），可用 && 与 || 组合，值必须用双引号包住。
- 表达式必须能把该产品与其他站点区分开：至少有一个条件落在 body/title/header/cookie/path/server 上，值长度不少于 5 个字符；不要用 status=200、content_type~="html" 这类几乎谁都命中的条件。
- 建议用 2-3 个条件用 && 组合以减少误报。单个条件的规则只在特征本身足够独特时才用。
- name 用产品/组件名（中文或英文均可，不要带 CVE 号），category 用小写分类（如 framework/cms/plugin/中间件 英文），如实在无法判断就填 other。
- 情报里找不到任何可用于区分的特征时，把 expression 置为空字符串。

只输出如下 JSON：
{"name":"","category":"","expression":"","reason":""}`

const userFingerprint = `请为以下漏洞情报生成一条资产指纹规则。

标题：%s
CVE：%s
严重等级：%s
标签/受影响组件：%s
描述：%s

只输出如下 JSON：
{"name":"","category":"","expression":"","reason":""}`

// GenerateFingerprintDraft 为一条情报生成指纹规则**草稿**并落库,但不写进
// 指纹规则库。表达式由模型补全,是否入库由人决定 —— 指纹决定资产归类,写错
// 会让整个资产的判定跟着错。返回草稿文本。
func (m *Manager) GenerateFingerprintDraft(ctx context.Context, v db.EnrichedVulnIntel) (string, error) {
	llm := m.llmConfig()
	if llm.Complete == nil {
		return "", fmt.Errorf("未配置 LLM，无法生成指纹规则")
	}
	ctx, cancel := context.WithTimeout(ctx, fpTimeout)
	defer cancel()

	user := fmt.Sprintf(userFingerprint,
		v.Title, v.CVE, v.Severity,
		joinJSONList(v.Tags, v.Affected), firstNonEmpty(v.Description, "（无）"),
	)
	raw, err := llm.Complete(ctx, sysFingerprint, user, fpMaxTokens)
	if err != nil {
		return "", fmt.Errorf("调用模型失败: %w", err)
	}
	var out FingerprintDraft
	if err := unmarshalLoose(raw, &out); err != nil {
		return "", fmt.Errorf("解析模型输出失败: %w", err)
	}
	out.Name = strings.TrimSpace(out.Name)
	out.Category = strings.TrimSpace(out.Category)
	out.Expression = strings.TrimSpace(out.Expression)
	if out.Category == "" {
		out.Category = "other"
	}
	if out.Expression == "" {
		return "", fmt.Errorf("情报中没有可用于区分产品的特征，未生成指纹草稿")
	}
	if err := ValidateFingerprintExpression(out.Expression); err != nil {
		return "", err
	}
	if out.Name == "" {
		return "", fmt.Errorf("模型未给出规则名称")
	}

	text, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	if err := m.pg.SaveIntelAnalysisStage(db.VulnIntelAnalysisStage{
		VulnIntelID: v.ID, Fingerprint: string(text),
	}); err != nil {
		return "", err
	}
	return string(text), nil
}

// ValidateFingerprintExpression 校验一条指纹表达式能不能入库:语法必须被平台
// 解析器接受,且必须含有至少一个"有区分度"的条件 —— 落在内容/路径类字段上
// 且值不是几乎人人都命中的通用词。校验不过的规则会长期误报,宁可不出。
func ValidateFingerprintExpression(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fmt.Errorf("指纹表达式为空")
	}
	ast, err := fingerprint.ParseExpression(expr)
	if err != nil {
		return fmt.Errorf("指纹表达式不合法: %w", err)
	}
	conds := collectFieldConds(ast)
	if len(conds) == 0 {
		return fmt.Errorf("指纹表达式没有任何匹配条件")
	}
	distinctive := 0
	for _, c := range conds {
		if c.Value == "" {
			return fmt.Errorf("指纹表达式的条件 %s 值为空", c.Field)
		}
		if !distinctiveField(c.Field) {
			continue
		}
		if len(strings.TrimSpace(c.Value)) < 5 {
			continue
		}
		if genericFingerprintValue[strings.ToLower(strings.TrimSpace(c.Value))] {
			continue
		}
		distinctive++
	}
	if distinctive == 0 {
		return fmt.Errorf("指纹表达式缺少有区分度的条件（需要至少一个落在 body/title/header/cookie/path/server 上、值长度 ≥5 的非通用条件）")
	}
	return nil
}

// distinctiveField 是有区分度的字段:内容与路径类,不含状态码/端口这类几乎
// 所有站点都满足的字段。
func distinctiveField(field string) bool {
	switch field {
	case "body", "title", "header", "cookie", "path", "server", "banner", "cert":
		return true
	}
	return false
}

// genericFingerprintValue 是几乎没有区分度的通用值(出现在 body/title 里也
// 匹配一堆站点)。
var genericFingerprintValue = map[string]bool{
	"html": true, "text/html": true, "utf-8": true, "ok": true, "index": true,
	"admin": true, "login": true, "http": true, "https": true, "www": true,
	"error": true, "welcome": true, "首页": true, "登录": true,
}

// collectFieldConds 展开 AST 里的全部字段条件。
func collectFieldConds(e fingerprint.Expr) []*fingerprint.FieldCond {
	switch t := e.(type) {
	case *fingerprint.FieldCond:
		return []*fingerprint.FieldCond{t}
	case *fingerprint.AndExpr:
		return append(collectFieldConds(t.Left), collectFieldConds(t.Right)...)
	case *fingerprint.OrExpr:
		return append(collectFieldConds(t.Left), collectFieldConds(t.Right)...)
	case *fingerprint.NotExpr:
		return collectFieldConds(t.Inner)
	}
	return nil
}

// ParseFingerprintDraft 解析草稿文本(存的是 JSON)。
func ParseFingerprintDraft(text string) (FingerprintDraft, error) {
	var d FingerprintDraft
	text = strings.TrimSpace(text)
	if text == "" {
		return d, fmt.Errorf("没有指纹草稿")
	}
	if err := json.Unmarshal([]byte(text), &d); err != nil {
		return d, err
	}
	return d, nil
}

// ConfirmFingerprint 把指纹草稿写进指纹规则库(人工确认这一步),并记规则 id。
// 草稿不存在时先生成一份再入库。
func (m *Manager) ConfirmFingerprint(ctx context.Context, v db.EnrichedVulnIntel) (string, error) {
	text, name, category, expr := "", "", "", ""
	if a, err := m.pg.GetIntelAnalysis(v.ID); err == nil && a != nil {
		text = a.Fingerprint
	}
	if text != "" {
		if d, perr := ParseFingerprintDraft(text); perr == nil {
			name, category, expr = d.Name, d.Category, d.Expression
		}
	}
	if expr == "" {
		genText, err := m.GenerateFingerprintDraft(ctx, v)
		if err != nil {
			return "", err
		}
		text = genText
		d, err := ParseFingerprintDraft(genText)
		if err != nil {
			return "", err
		}
		name, category, expr = d.Name, d.Category, d.Expression
	}
	if err := ValidateFingerprintExpression(expr); err != nil {
		return "", err
	}

	sink := m.fingerprintSink()
	if sink == nil {
		return "", fmt.Errorf("指纹规则库未就绪，无法保存")
	}
	ruleID, err := sink(name, category, expr)
	if err != nil {
		return "", fmt.Errorf("写入指纹规则库失败: %w", err)
	}
	if err := m.pg.SaveIntelAnalysisStage(db.VulnIntelAnalysisStage{
		VulnIntelID: v.ID, Fingerprint: text, FingerprintID: ruleID,
	}); err != nil {
		return "", err
	}
	return ruleID, nil
}

// DiscardFingerprint 丢弃一条未入库的指纹草稿。已入库的规则不在这里撤销——
// 撤下规则要走指纹库的删除路径,否则匹配缓存与库会不同步。
func (m *Manager) DiscardFingerprint(id int64) error {
	v, err := m.pg.GetVulnIntel(id)
	if err != nil {
		return err
	}
	if v.FingerprintID != "" {
		return fmt.Errorf("指纹规则 %s 已入库，请到指纹规则库删除", v.FingerprintID)
	}
	return m.pg.ClearIntelFingerprintDraft(id)
}

// fingerprintSink 读取注入的指纹落库钩子。
func (m *Manager) fingerprintSink() FingerprintSink {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fpSink
}

// SetFingerprintSink 注入指纹规则落库实现(写 fingerprint_rules)。
func (m *Manager) SetFingerprintSink(fn FingerprintSink) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fpSink = fn
}

// logFingerprintErr 统一记一条指纹草稿失败(不影响分析主链)。
func logFingerprintErr(id int64, err error) {
	log.Printf("[vulnintel] 指纹草稿生成 %d: %v", id, err)
}
