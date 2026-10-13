package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/artex/tools"
)

// searchVulnKB lets an agent search the 1day exploit knowledge base by product
// (fingerprint hit) / CVE / keyword. This is the payoff of the fingerprint
// pipeline: recognize a technology → ask what is known to work against it →
// get a ready request+payload instead of deriving an exploit from scratch.
func (t *ToolSet) searchVulnKB() actool.CoreTool {
	return readTool(
		"search_vuln_kb",
		"检索 1day 漏洞知识库（指纹命中后的打击面查询）：按产品名/CVE/关键词搜索已知漏洞，返回指纹表达式、请求行与 Payload。\n"+
			"典型用法：资产指纹识别出某产品（如 通达OA、Shiro、若依）后，先查本库拿到现成的验证请求与 Payload，再决定是否尝试；不要凭记忆构造利用，先查库。\n"+
			"返回字段：title/product/vuln_type/cve/fingerprint/request_line/payload/response_sig；payload 为空表示该条只有指纹特征无现成利用。",
		obj(map[string]any{
			"q": str("必填。产品名 / CVE 编号 / 关键词（模糊匹配标题、产品、CVE、指纹表达式）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("search_vuln_kb 未启用: AssetStore 未初始化"), nil
			}
			var a struct {
				Q string `json:"q"`
			}
			_ = json.Unmarshal(in, &a)
			q := strings.TrimSpace(a.Q)
			if q == "" {
				return actool.Errorf("q 不能为空：给产品名 / CVE / 关键词"), nil
			}
			pg := t.as.DB()
			if pg == nil {
				return actool.Errorf("search_vuln_kb 未启用: 数据库不可用"), nil
			}
			entries, total, err := pg.ListVulnKB(q, "", 0, 8)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("查询失败: %v", err)), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "命中 %d 条（库内），展示前 %d 条：\n", total, len(entries))
			for i, e := range entries {
				fmt.Fprintf(&b, "\n[%d] %s\n", i+1, e.Title)
				fmt.Fprintf(&b, "产品: %s | 类型: %s | CVE: %s\n", e.Product, e.VulnType, orDash(e.CVE))
				if e.Fingerprint != "" {
					fmt.Fprintf(&b, "指纹: %s\n", e.Fingerprint)
				}
				if e.RequestLine != "" {
					fmt.Fprintf(&b, "请求: %s\n", e.RequestLine)
				}
				if e.Payload != "" {
					payload := e.Payload
					if len(payload) > 800 {
						payload = payload[:800] + "…(截断)"
					}
					fmt.Fprintf(&b, "Payload:\n%s\n", payload)
				}
				if e.ResponseSig != "" {
					fmt.Fprintf(&b, "响应特征: %s\n", e.ResponseSig)
				}
			}
			if len(entries) == 0 {
				b.WriteString("（无命中——换产品别名或英文产品名再试）")
			}
			return actool.Text(b.String()), nil
		},
	)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
