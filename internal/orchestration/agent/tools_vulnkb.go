package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capability/recon/fingerprint"
	"github.com/c1ayooo/4zrec/internal/domain/db"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// searchVulnKB lets an agent search the 1day exploit knowledge base by product
// (fingerprint hit) / CVE / keyword. This is the payoff of the fingerprint
// pipeline: recognize a technology → ask what is known to work against it →
// get a ready request+payload instead of deriving an exploit from scratch.
//
// The lookup is gated on real fingerprint evidence: either the target passed by
// the caller already has technologies in the asset store, or the current task
// has at least one recognized technology. This prevents blind "search every
// product" behavior.
func (t *ToolSet) searchVulnKB() actool.CoreTool {
	return readTool(
		"search_vuln_kb",
		"检索 1day 漏洞知识库 + 情报流（指纹命中后的打击面查询）：按产品名/CVE/关键词搜索已知漏洞，返回指纹表达式、请求行与 Payload；"+
			"同时检索情报流，返回 Github POC 仓库、source_url 和参考链接。\n"+
			"必须先有真实指纹证据：传入已识别的 target，或当前任务已有 fingerprint_scan/enrich 写入的 technologies；"+
			"否则拒绝检索，防止无识别乱查。产品名查询会与已识别技术做匹配，CVE 查询在有识别证据的前提下放行。\n"+
			"典型用法：资产指纹识别出某产品（如 通达OA、Shiro、若依）后，先查本库拿到现成的验证请求与 Payload/POC，再决定是否尝试；不要凭记忆构造利用，先查库。\n"+
			"返回字段：1day 为 title/product/vuln_type/cve/fingerprint/request_line/payload/response_sig；情报流为 title/severity/cve/source_url/github_poc/refs。",
		obj(map[string]any{
			"q":      str("必填。产品名 / CVE 编号 / 关键词（模糊匹配标题、产品、CVE、指纹表达式）"),
			"target": str("可选。已识别的目标 URL；提供后从资产库读取该目标的 technologies 作为指纹证据"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("search_vuln_kb 未启用: AssetStore 未初始化"), nil
			}
			var a struct {
				Q      string `json:"q"`
				Target string `json:"target"`
			}
			_ = json.Unmarshal(in, &a)
			q := strings.TrimSpace(a.Q)
			target := strings.TrimSpace(a.Target)
			if q == "" {
				return actool.Errorf("q 不能为空：给产品名 / CVE / 关键词"), nil
			}
			pg := t.as.DB()
			if pg == nil {
				return actool.Errorf("search_vuln_kb 未启用: 数据库不可用"), nil
			}

			var techs []string
			if target != "" {
				evidence, err := t.as.TechnologiesForTargets([]string{target})
				if err != nil {
					return actool.Errorf("读取目标指纹证据失败: " + err.Error()), nil
				}
				techs = evidence[target]
				if len(techs) == 0 {
					return actool.Errorf(fmt.Sprintf("拒绝无指纹识别的漏洞库检索：目标 %s 没有 technologies 证据。请先调用 fingerprint_scan（或 enrich）完成识别", target)), nil
				}
			} else {
				ri := RunInfoFrom(ctx)
				scope, err := t.as.TechnologiesForScope(ri.TaskID, 0)
				if err != nil {
					return actool.Errorf("读取任务指纹证据失败: " + err.Error()), nil
				}
				if len(scope) == 0 {
					return actool.Errorf("拒绝无指纹识别的漏洞库检索：当前任务没有 technologies 证据。请先调用 fingerprint_scan（或 enrich），或传入已识别的 target"), nil
				}
				techs = scope
			}
			techs = fingerprint.UniqueTechnologies(techs)
			if !fingerprint.QueryMatches(techs, q) && !strings.Contains(strings.ToUpper(q), "CVE-") {
				return actool.Errorf(fmt.Sprintf("关键词「%s」不在已识别指纹中；当前已识别: %s。请用识别出的产品名重试", q, strings.Join(techs, ", "))), nil
			}

			entries, total, err := pg.ListVulnKB(q, "", 0, 8)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("查询失败: %v", err)), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "基于指纹证据: %s\n", strings.Join(techs, ", "))
			fmt.Fprintf(&b, "1day 库命中 %d 条（展示前 %d 条）：\n", total, len(entries))
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

			intelEntries, intelTotal, intelErr := pg.ListVulnIntel(q, "", 0, 5)
			if intelErr != nil {
				fmt.Fprintf(&b, "\n情报流查询失败: %v\n", intelErr)
			} else if len(intelEntries) > 0 {
				fmt.Fprintf(&b, "\n情报流命中 %d 条（含 POC/参考，展示前 %d 条）：\n", intelTotal, len(intelEntries))
				for i, e := range intelEntries {
					fmt.Fprintf(&b, "\n[I%d] %s\n", i+1, e.Title)
					meta := []string{}
					if e.Severity != "" {
						meta = append(meta, e.Severity)
					}
					if e.CVE != "" {
						meta = append(meta, e.CVE)
					}
					if e.Source != "" {
						meta = append(meta, e.Source)
					}
					if len(meta) > 0 {
						fmt.Fprintf(&b, "等级/编号/来源: %s\n", strings.Join(meta, " | "))
					}
					if e.SourceURL != "" {
						fmt.Fprintf(&b, "来源: %s\n", e.SourceURL)
					}
					if e.LabOnly {
						b.WriteString("标记: 仅实验室/暂无可利用 PoC\n")
					}
					if pocs := parsePOCs(e.GithubPoc); len(pocs) > 0 {
						b.WriteString("POC 仓库:\n")
						for j, p := range pocs {
							if j >= 3 {
								break
							}
							extra := ""
							if p.Stars > 0 {
								extra += fmt.Sprintf(" ★%d", p.Stars)
							}
							if p.Verdict != "" {
								extra += " [" + p.Verdict + "]"
							}
							fmt.Fprintf(&b, "  - %s%s\n", p.URL, extra)
						}
					} else {
						b.WriteString("POC 仓库: 无\n")
					}
					if refs := parseRefs(e.Refs); len(refs) > 0 {
						b.WriteString("参考:\n")
						for j, r := range refs {
							if j >= 3 {
								break
							}
							fmt.Fprintf(&b, "  - %s\n", r)
						}
					}
				}
			}

			if len(entries) == 0 && len(intelEntries) == 0 {
				b.WriteString("\n（无命中——换产品别名或英文产品名再试）")
			} else {
				b.WriteString("\n下一步（定向验证，禁止扩大范围）：\n")
				if len(entries) > 0 {
					first := entries[0]
					if first.CVE != "" {
						fmt.Fprintf(&b, "- CVE 优先: nuclei_template_search(q=%q) 或 nuclei_scan(based_on_cve=%q, targets=[已识别目标])\n", first.CVE, first.CVE)
					}
					if first.Product != "" {
						fmt.Fprintf(&b, "- 按产品: nuclei_template_search(product=%q, targets=[已识别目标]) → nuclei_scan(based_on_product=%q, templates=[模板ID], targets=[已识别目标])\n", first.Product, first.Product)
					}
				} else if len(intelEntries) > 0 {
					first := intelEntries[0]
					if first.CVE != "" {
						fmt.Fprintf(&b, "- CVE 优先: nuclei_template_search(q=%q) 或 nuclei_scan(based_on_cve=%q, targets=[已识别目标])\n", first.CVE, first.CVE)
					}
					b.WriteString("- 先阅读 POC 仓库并做 http_probe/流量复核，再决定是否用 nuclei 模板验证。\n")
				}
				b.WriteString("- nuclei 命中只是候选；需 http_probe/流量证据复核后再 report_finding。\n")
			}
			return actool.Text(b.String()), nil
		},
	)
}

func parsePOCs(raw string) []db.VulnIntelPOC {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []db.VulnIntelPOC
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func parseRefs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
