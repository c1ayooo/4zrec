package toolparse

import (
	"fmt"
	"strings"
)

// ── confidence 规则（§4.5 规则 3 的单点实现）──
//
// 只允许升/降两个方向：
//   tentative → confirmed（第二次独立证据或复核工具确认）
//   confirmed → deprecated（资产消失/服务变更，走 DeprecateProjectFact，不删除）
//   deprecated → confirmed（恢复，走 RestoreProjectFact）
//
// 解析器只声明"观测到的事实状态"，不得直接写升级判定；升级判定全部集中在这里。
// 观测类（nmap 存活/httpx 响应）解析器直接给 confirmed（连通实证，rule 3 允许）；
// 工具命中的结论类一律 tentative 起步，confirmed 只留给复核链路或模型。

// mergeConfidence 计算候选置信度与既有置信度的合并结果（幂等、只升不降）。
//   - 无既有 → 用候选值
//   - 既有 deprecated → 候选非 deprecated 即恢复为候选值（走 Restore，落库层处理）
//   - 既有 tentative + 候选 confirmed → confirmed（第二次独立证据）
//   - 既有 tentative + 候选 tentative → tentative（保持）
//   - 既有 confirmed + 任何候选 → confirmed（不让低置信降级已验证事实）
//   - 候选 deprecated → deprecated（仅解析器明确判资产消失时，本轮无解析器产生）
func mergeConfidence(existing, candidate string) string {
	switch existing {
	case "":
		return candidate
	case "deprecated":
		if candidate == "" || candidate == "deprecated" {
			return "deprecated"
		}
		return candidate // 恢复（RestoreProjectFact 语义由落库层按此实现）
	case "confirmed":
		return "confirmed"
	case "tentative":
		if candidate == "confirmed" {
			return "confirmed"
		}
		return "tentative"
	default:
		return candidate
	}
}

// NormalizeFact 落库前规范化：校验 fact_key/category/confidence 合法值，裁剪异常字段。
// 返回规范化后的候选；不合格返回 error（fail-closed：宁可不落，不错落）。
func NormalizeFact(f FactCandidate) (FactCandidate, error) {
	if err := ValidateFactKey(f.FactKey); err != nil {
		return f, err
	}
	switch f.Confidence {
	case "tentative", "confirmed", "deprecated", "":
		// ok
	default:
		return f, fmt.Errorf("fact %q 的 confidence %q 非法", f.FactKey, f.Confidence)
	}
	if f.Confidence == "" {
		f.Confidence = "tentative"
	}
	f.Summary = strings.TrimSpace(f.Summary)
	f.Body = strings.TrimSpace(f.Body)
	if f.Summary == "" || f.Body == "" {
		// 摘要/正文缺失则用默认兜底（避免空事实污染黑板）
		if f.Summary == "" {
			f.Summary = "工具观测: " + f.FactKey
		}
		if f.Body == "" {
			f.Body = "原始证据见 raw_ref"
		}
	}
	seen := map[string]bool{}
	links := make([]FactLink, 0, len(f.Links))
	for _, l := range f.Links {
		l.From = strings.TrimSpace(l.From)
		l.Type = strings.TrimSpace(l.Type)
		if l.From == "" || l.Type == "" || l.From == f.FactKey {
			continue // 自指/空边丢弃
		}
		if seen[l.From+"|"+l.Type] {
			continue // 去重
		}
		seen[l.From+"|"+l.Type] = true
		links = append(links, l)
	}
	f.Links = links
	return f, nil
}
