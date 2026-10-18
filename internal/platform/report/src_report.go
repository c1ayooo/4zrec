package report

// Consolidated SRC report: merge several findings' four-section SRC reports into
// one document (一、描述/发现/危害；二、复现过程；三、测试源信息；四、修复方案),
// matching the format used for SRC submissions.

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

var reSubHeading = regexp.MustCompile(`(?m)^### `)

// SRCAsset is one asset row shown in the consolidated report's business context.
type SRCAsset struct {
	Label string
	Type  string
	Role  string
}

// BuildSRCMarkdown merges the stored per-finding reports into one SRC report.
func BuildSRCMarkdown(findings []*db.DBFinding, title string) string {
	return BuildSRCMarkdownWithAssets(findings, title, nil, "")
}

// BuildSRCMarkdownWithAssets also renders the asset-relationship / business-flow
// context used when several findings sit on the same business chain.
func BuildSRCMarkdownWithAssets(findings []*db.DBFinding, title string, assets []SRCAsset, flow string) string {
	return BuildSRCMarkdownWithChains(findings, title, assets, flow, nil)
}

// BuildSRCMarkdownWithChains also renders exploit-chain groups: multiple related
// findings are presented as one path instead of a flat list.
func BuildSRCMarkdownWithChains(findings []*db.DBFinding, title string, assets []SRCAsset, flow string, chains []SRCChain) string {
	if strings.TrimSpace(title) == "" {
		title = "SRC 漏洞挖掘报告"
	}
	var b strings.Builder
	b.WriteString("# " + title + "\n\n")

	// Business context: assets + normal flow + how the findings relate.
	if len(assets) > 0 || strings.TrimSpace(flow) != "" {
		b.WriteString("## 测试范围与业务关系\n\n")
		if len(assets) > 0 {
			b.WriteString("| 资产 | 类型 | 角色/说明 |\n|---|---|---|\n")
			for _, a := range assets {
				b.WriteString("| " + a.Label + " | " + a.Type + " | " + a.Role + " |\n")
			}
			b.WriteString("\n")
		}
		if strings.TrimSpace(flow) != "" {
			b.WriteString("**业务链路**：" + strings.TrimSpace(flow) + "\n\n")
		}
		b.WriteString(fmt.Sprintf("本次报告包含 %d 个漏洞，涉及 %d 个资产；同一业务链路上的漏洞按“描述 → 复现 → 测试源 → 修复”统一组织，关联关系见上表。\n\n", len(findings), len(assets)))
	}

	// Test scope: unique task descriptions (one per engagement).
	seen := map[string]bool{}
	var scopes []string
	for _, f := range findings {
		d := strings.TrimSpace(f.TaskDescription)
		if d != "" && !seen[d] {
			seen[d] = true
			scopes = append(scopes, d)
		}
	}
	if len(scopes) > 0 {
		b.WriteString("## 测试范围\n\n")
		for _, s := range scopes {
			b.WriteString("- " + s + "\n")
		}
		b.WriteString("\n")
	}

	// Exploit chains: group related findings and show the path.
	if len(chains) > 0 {
		b.WriteString("## 利用链与漏洞分组\n\n")
		byID := map[int64]*db.DBFinding{}
		idSet := map[int64]bool{}
		for _, f := range findings {
			byID[f.ID] = f
			idSet[f.ID] = true
		}
		stripID := func(s string) string {
			for id := range idSet {
				s = strings.ReplaceAll(s, fmt.Sprintf("（%d）", id), "")
				s = strings.ReplaceAll(s, fmt.Sprintf("(%d)", id), "")
				s = strings.ReplaceAll(s, fmt.Sprintf("#%d", id), "")
			}
			return strings.TrimSpace(s)
		}
		for i, ch := range chains {
			fmt.Fprintf(&b, "### 链路 %d：%s\n\n", i+1, stripID(ch.Title))
			if strings.TrimSpace(ch.Summary) != "" {
				b.WriteString(stripID(ch.Summary) + "\n\n")
			}
			for j, step := range ch.Steps {
				fmt.Fprintf(&b, "%d. %s\n", j+1, stripID(step))
			}
			b.WriteString("\n")
			var names []string
			for _, id := range ch.FindingIDs {
				if f := byID[id]; f != nil {
					names = append(names, srcFindingTitle(f))
				}
			}
			if len(names) > 0 {
				b.WriteString("包含漏洞：" + strings.Join(names, "、") + "\n\n")
			}
		}
	}

	sectionTitles := []struct{ key, title string }{
		{"d1", "一、漏洞描述、发现过程与危害"},
		{"d2", "二、复现过程"},
		{"d3", "三、测试源信息"},
		{"d4", "四、修复方案"},
	}
	for _, sec := range sectionTitles {
		b.WriteString("## " + sec.title + "\n\n")
		n := 0
		for _, g := range srcFindingGroups(findings, chains) {
			if len(chains) > 0 && g.Title != "" {
				b.WriteString("### " + g.Title + "\n\n")
			}
			for _, f := range g.Findings {
				parts := srcSectionsOf(f.Report)
				fallback := srcFallbackSections(f)
				body := strings.TrimSpace(parts[sec.key])
				if body == "" {
					body = strings.TrimSpace(fallback[sec.key])
				}
				// report 为空时至少让漏洞出现在「描述」段，避免整条记录被静默跳过。
				if body == "" && sec.key == "d1" {
					body = fmt.Sprintf("**%s**\n\n%s", srcFindingTitle(f),
						nz(strings.TrimSpace(f.Summary), "（该漏洞未附详细报告与证据，请人工补充。）"))
				}
				if body == "" {
					continue
				}
				n++
				if len(chains) > 0 {
					fmt.Fprintf(&b, "#### %d. %s（%s）\n\n", n, srcFindingTitle(f), severityCN(f.Severity))
				} else {
					fmt.Fprintf(&b, "### %d. %s（%s）\n\n", n, srcFindingTitle(f), severityCN(f.Severity))
				}
				if meta := srcFindingMetaLine(f); meta != "" {
					b.WriteString(meta + "\n\n")
				}
				b.WriteString(reSubHeading.ReplaceAllString(body, "#### "))
				b.WriteString("\n\n")
			}
		}
		if n == 0 {
			b.WriteString("（本次导出未包含该部分内容。）\n\n")
		}
	}
	return strings.TrimSpace(SanitizeForExport(b.String()))
}

type srcFindingGroup struct {
	Title    string
	Findings []*db.DBFinding
}

func srcFindingGroups(findings []*db.DBFinding, chains []SRCChain) []srcFindingGroup {
	if len(chains) == 0 {
		return []srcFindingGroup{{Findings: findings}}
	}
	byID := map[int64]*db.DBFinding{}
	for _, f := range findings {
		byID[f.ID] = f
	}
	used := map[int64]bool{}
	var groups []srcFindingGroup
	for i, ch := range chains {
		var fs []*db.DBFinding
		for _, id := range ch.FindingIDs {
			if f := byID[id]; f != nil && !used[id] {
				used[id] = true
				fs = append(fs, f)
			}
		}
		if len(fs) > 0 {
			groups = append(groups, srcFindingGroup{Title: fmt.Sprintf("链路 %d：%s", i+1, ch.Title), Findings: fs})
		}
	}
	var rest []*db.DBFinding
	for _, f := range findings {
		if !used[f.ID] {
			rest = append(rest, f)
		}
	}
	if len(rest) > 0 {
		groups = append(groups, srcFindingGroup{Title: "其他漏洞", Findings: rest})
	}
	return groups
}

// srcSectionsOf extracts the four SRC sections from one finding report.
func srcSectionsOf(md string) map[string]string {
	out := map[string]string{}
	current := ""
	var buf []string
	flush := func() {
		if current != "" {
			out[current] = strings.TrimSpace(strings.Join(buf, "\n"))
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "## ") {
			flush()
			head := strings.TrimSpace(strings.TrimPrefix(line, "## "))
			switch {
			case strings.HasPrefix(head, "1."):
				current = "d1"
			case strings.HasPrefix(head, "2."):
				current = "d2"
			case strings.HasPrefix(head, "3."):
				current = "d3"
			case strings.HasPrefix(head, "4."):
				current = "d4"
			default:
				current = ""
			}
			buf = nil
			continue
		}
		if current != "" {
			buf = append(buf, line)
		}
	}
	flush()
	return out
}

func srcFindingTitle(f *db.DBFinding) string {
	if s := strings.TrimSpace(f.Name); s != "" {
		return s
	}
	if s := strings.TrimSpace(f.VulnClass); s != "" {
		return s
	}
	return fmt.Sprintf("漏洞 #%d", f.ID)
}

func severityCN(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		return s
	}
}

// srcFallbackSections keeps a finding visible when the reporter's Markdown report
// is missing: summary feeds the description section, evidence/reproduction feeds
// the reproduction section. This prevents a confirmed finding from silently
// disappearing from the consolidated report.
func srcFallbackSections(f *db.DBFinding) map[string]string {
	out := map[string]string{}
	if s := strings.TrimSpace(f.Summary); s != "" {
		out["d1"] = s
	}
	if s := strings.TrimSpace(f.Evidence); s != "" {
		out["d2"] = s
	} else if len(f.Reproduction) > 2 && string(f.Reproduction) != "null" {
		out["d2"] = "```json\n" + string(f.Reproduction) + "\n```"
	}
	return out
}

// srcFindingMetaLine renders the structured evidence/triage/retest labels that
// used to be invisible in the SRC report.
func srcFindingMetaLine(f *db.DBFinding) string {
	var parts []string
	if c := confidenceCN(f.Confidence); c != "" {
		parts = append(parts, "证据等级："+c)
	}
	if s := findingStatusCN(f.Status); s != "" {
		parts = append(parts, "处置状态："+s)
	}
	if r := retestVerdictCN(f.RetestVerdict); r != "" {
		line := "复测结论：" + r
		if f.RetestFinishedAt != nil {
			line += "（" + f.RetestFinishedAt.Format("2006-01-02") + "）"
		}
		if s := strings.TrimSpace(f.RetestSummary); s != "" {
			line += "；" + s
		}
		parts = append(parts, line)
	}
	if len(parts) == 0 {
		return ""
	}
	return "> " + strings.Join(parts, "；")
}

func confidenceCN(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "verified":
		return "已验证"
	case "partial":
		return "部分验证"
	case "inferred":
		return "推断"
	default:
		return ""
	}
}

func findingStatusCN(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pending":
		return "待处理"
	case "in_progress":
		return "处理中"
	case "confirmed":
		return "已确认"
	case "resolved":
		return "已处理"
	case "fixed":
		return "已修复"
	case "risk_accepted":
		return "风险接受"
	case "false_positive":
		return "误报"
	case "ignored":
		return "忽略"
	case "duplicate":
		return "重复"
	default:
		return ""
	}
}

func retestVerdictCN(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "reproduced":
		return "仍可复现"
	case "fixed":
		return "已修复"
	case "inconclusive":
		return "无法确认"
	default:
		return ""
	}
}
