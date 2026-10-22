// 情报中文化(localize):英文情报与模板元数据翻成中文,CVE 编号、组件名、
// 函数名、接口路径保留原文。对齐 ai_bobao 的 translate 阶段。
//
// 与分析层的关系:分析(analyzer)已经会顺带产出中文标题与简介,所以这里是
// **兜底**路径 —— 覆盖「关掉 AI 分析只想要中文标题」以及历史数据的批量补齐。
package vulnintel

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

const (
	localizeMaxTokens = 1200
	localizeTimeout   = 90 * time.Second
)

const sysLocalize = `你是安全情报翻译专家。把给定的英文漏洞情报标题与描述翻译成简体中文，严格只输出 JSON，不要 markdown 代码块，不要额外解释。

铁律：
- CVE 编号、组件/产品名、函数名、接口路径、命令、参数名一律保留原文，不要翻译、不要改写大小写。
- 已通行的安全术语用业界通用译法（如 RCE 译作「远程代码执行」、SSRF 译作「服务端请求伪造」），必要时中英并列。
- 不添加原文没有的信息，不做扩写。
- 输出字段：title_zh(中文标题)、description_zh(中文描述，保留原文信息量)。`

const userLocalize = `请把以下情报翻译成简体中文。

标题：%s
描述：%s

只输出 JSON：{"title_zh":"","description_zh":""}`

type localizeOut struct {
	TitleZh       string `json:"title_zh"`
	DescriptionZh string `json:"description_zh"`
}

// localizeItem 保证一条情报有中文标题;英文原文则调模型翻译标题+描述。
func (m *Manager) localizeItem(ctx context.Context, v db.EnrichedVulnIntel) error {
	// 原文已是中文:不浪费一次调用,直接把原文作为中文标题落库。
	if !needsLocalization(v.Title) && !needsLocalization(v.Description) {
		if strings.TrimSpace(v.TitleZh) != "" {
			return nil
		}
		return m.pg.SaveIntelAnalysisStage(db.VulnIntelAnalysisStage{
			VulnIntelID: v.ID, TitleZh: v.Title, Localized: true,
		})
	}

	llm := m.llmConfig()
	if llm.Complete == nil {
		return fmt.Errorf("未配置 LLM，无法中文化")
	}
	ctx, cancel := context.WithTimeout(ctx, localizeTimeout)
	defer cancel()

	raw, err := llm.Complete(ctx, sysLocalize,
		fmt.Sprintf(userLocalize, v.Title, firstNonEmpty(v.Description, "（无）")), localizeMaxTokens)
	if err != nil {
		return fmt.Errorf("调用模型失败: %w", err)
	}
	var out localizeOut
	if err := unmarshalLoose(raw, &out); err != nil {
		return fmt.Errorf("解析模型输出失败: %w", err)
	}
	titleZh := strings.TrimSpace(out.TitleZh)
	if titleZh == "" {
		return fmt.Errorf("模型未返回中文标题")
	}
	return m.pg.SaveIntelAnalysisStage(db.VulnIntelAnalysisStage{
		VulnIntelID:   v.ID,
		TitleZh:       titleZh,
		DescriptionZh: strings.TrimSpace(out.DescriptionZh),
		Localized:     true,
	})
}

// needsLocalization 判断文本是否以非中文为主(需要翻译)。
//
// 判据:字母数达到一定量、且汉字「按信息密度折算」(1 个汉字≈3 个拉丁字母)后
// 仍不及拉丁字母量。这样中英混排的技术描述(如「某系统反序列化漏洞 in Java」)
// 不会被误判为需要翻译 —— 它已经有中文了,再翻一遍是白花 token。
func needsLocalization(s string) bool {
	cjk, latin := 0, 0
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Han, r):
			cjk++
		case unicode.IsLetter(r):
			latin++
		}
	}
	if latin < 8 {
		return false // 太短(多为纯编号/代号),不做判断
	}
	return cjk*3 < latin
}
