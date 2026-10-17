package report

// Exploit-chain grouping for consolidated SRC reports. Related findings are
// grouped and rendered as a path (step 1 → step 2 → ...) instead of a flat list.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/db"
)

// SRCChain is one exploit chain / related-finding group.
type SRCChain struct {
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	Steps      []string `json:"steps"`
	FindingIDs []int64  `json:"finding_ids"`
}

// GenerateSRCChains asks the active LLM to group related findings into exploit
// chains. If the model is unavailable or returns nothing usable, it falls back
// to grouping findings that share assets.
func GenerateSRCChains(ctx context.Context, pg *db.DB, findings []*db.DBFinding) []SRCChain {
	return GenerateSRCChainsWithAssets(ctx, pg, findings, nil, nil)
}

// GenerateSRCChainsWithAssets lets the caller pass asset types/labels so the
// fallback groups findings by business role (gateway vs object storage) instead
// of connecting everything through a shared root domain.
func GenerateSRCChainsWithAssets(ctx context.Context, pg *db.DB, findings []*db.DBFinding, assetTypes, assetLabels map[int64]string) []SRCChain {
	if len(findings) < 2 {
		return nil
	}
	var lines []string
	for _, f := range findings {
		summary := strings.TrimSpace(f.Summary)
		if len([]rune(summary)) > 700 {
			summary = string([]rune(summary)[:700])
		}
		excerpt := strings.TrimSpace(f.Report)
		if len([]rune(excerpt)) > 1800 {
			excerpt = string([]rune(excerpt)[:1800])
		}
		lines = append(lines, fmt.Sprintf("id=%d | 名称=%s | 等级=%s | 摘要=%s | 报告片段=%s",
			f.ID, srcFindingTitle(f), f.Severity, summary, excerpt))
	}
	system := "你是 SRC 漏洞报告分析员，负责把相关漏洞整理成利用链。只输出 JSON，不要 markdown 代码块。"
	user := `下面是本次报告的全部漏洞。请识别哪些漏洞属于同一条利用链/关联漏洞组。

判断原则：
- 只有前一个漏洞为后一个提供凭据、入口、权限、数据或前置条件时，才算同一条链；仅共享域名不算。
- 每条链给出 title、summary、steps（按攻击顺序，每步一句话，写清利用了什么漏洞、得到什么能力）、finding_ids。
- steps 必须基于给定信息，不得编造不存在的接口或能力。
- steps/title/summary 中不要写漏洞编号或 ID；编号只放在 finding_ids 数组里，必须是数字数组，例如 [273,282]。
- 独立漏洞不要放进 groups。

只输出 JSON：{"groups":[{"title":"...","summary":"...","steps":["..."],"finding_ids":[1,2]}]}

漏洞列表：
` + strings.Join(lines, "\n\n")

	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := complete(cctx, pg, system, user, 5000)
	if err != nil || strings.TrimSpace(out) == "" {
		log.Printf("[src-chain] LLM 首次返回为空/失败: err=%v raw=%q，使用精简提示重试", err, truncRunes(out, 200))
		var shortLines []string
		for _, f := range findings {
			shortLines = append(shortLines, fmt.Sprintf("id=%d | %s | %s | %s",
				f.ID, srcFindingTitle(f), f.Severity, truncRunes(strings.TrimSpace(f.Summary), 300)))
		}
		shortUser := `识别下列漏洞中属于同一利用链的组。只有前一步为后一步提供凭据/入口/权限/数据时才归为一组；仅共享域名不算。
steps 按攻击顺序写，每步一句话；steps/title/summary 不写编号，编号只放 finding_ids 数字数组。
只输出 JSON：{"groups":[{"title":"...","summary":"...","steps":["..."],"finding_ids":[1,2]}]}
漏洞：
` + strings.Join(shortLines, "\n")
		out, err = complete(cctx, pg, system, shortUser, 3000)
	}
	if err != nil {
		log.Printf("[src-chain] LLM 调用失败: %v", err)
		return fallbackSRCChains(findings, assetTypes, assetLabels)
	}
	var parsed struct {
		Groups []SRCChain `json:"groups"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		log.Printf("[src-chain] JSON 解析失败: %v raw=%s", err, truncRunes(out, 800))
		return fallbackSRCChains(findings, assetTypes, assetLabels)
	}
	valid := map[int64]bool{}
	for _, f := range findings {
		valid[f.ID] = true
	}
	var groups []SRCChain
	for _, g := range parsed.Groups {
		seen := map[int64]bool{}
		var ids []int64
		for _, id := range g.FindingIDs {
			if valid[id] && !seen[id] {
				ids = append(ids, id)
				seen[id] = true
			}
		}
		if len(ids) < 2 {
			continue
		}
		g.FindingIDs = ids
		if strings.TrimSpace(g.Title) == "" {
			g.Title = "关联漏洞组"
		}
		groups = append(groups, g)
	}
	if len(groups) == 0 {
		log.Printf("[src-chain] LLM 未返回有效分组 raw=%s", truncRunes(out, 800))
		return fallbackSRCChains(findings, assetTypes, assetLabels)
	}
	return dedupeChains(groups)
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// fallbackSRCChains groups findings by business role on specific assets:
// gateway chains (credential → upload → sign) and storage chains (write → read).
// It avoids the single giant component produced by a shared root domain.
func fallbackSRCChains(findings []*db.DBFinding, assetTypes, assetLabels map[int64]string) []SRCChain {
	byAsset := map[int64][]*db.DBFinding{}
	seenPair := map[string]bool{}
	for _, f := range findings {
		for _, aid := range f.AssetIDs {
			if t := assetTypes[aid]; t == "root_domain" {
				continue
			}
			key := fmt.Sprintf("%d-%d", aid, f.ID)
			if seenPair[key] {
				continue
			}
			seenPair[key] = true
			byAsset[aid] = append(byAsset[aid], f)
		}
	}
	var assetIDs []int64
	for aid := range byAsset {
		assetIDs = append(assetIDs, aid)
	}
	sort.Slice(assetIDs, func(i, j int) bool { return assetIDs[i] < assetIDs[j] })
	var groups []SRCChain
	for _, aid := range assetIDs {
		fs := byAsset[aid]
		if len(fs) < 2 {
			continue
		}
		label := strings.ToLower(assetLabels[aid])
		kind := ""
		switch {
		case strings.Contains(label, "minio") || strings.Contains(label, "oss") || strings.Contains(label, "s3"):
			kind = "对象存储链"
		case strings.Contains(label, "api") || strings.Contains(label, "finance"):
			kind = "业务网关链"
		}
		if kind == "" {
			continue
		}
		roleSet := map[int]bool{}
		for _, f := range fs {
			p, _ := findingRole(f)
			roleSet[p] = true
		}
		if len(roleSet) < 2 {
			continue
		}
		sort.SliceStable(fs, func(a, b int) bool {
			pa, _ := findingRole(fs[a])
			pb, _ := findingRole(fs[b])
			if pa != pb {
				return pa < pb
			}
			return fs[a].ID < fs[b].ID
		})
		var ids []int64
		var steps []string
		var roles []string
		lastRole := -1
		for _, f := range fs {
			p, role := findingRole(f)
			if p != lastRole {
				roles = append(roles, role)
				lastRole = p
			}
			ids = append(ids, f.ID)
			steps = append(steps, fmt.Sprintf("[%s] %s", role, srcFindingTitle(f)))
		}
		title := fmt.Sprintf("%s：%s", kind, strings.Join(roles, " → "))
		groups = append(groups, SRCChain{
			Title:      title,
			Summary:    "以下漏洞按角色顺序组合，形成一条可复现的利用路径；详细步骤见各漏洞条目。",
			Steps:      steps,
			FindingIDs: ids,
		})
	}
	return dedupeChains(groups)
}

// dedupeChains drops chains whose finding set is a subset of another chain's
// set (duplicate asset IDs for the same host would otherwise produce copies).
func dedupeChains(groups []SRCChain) []SRCChain {
	var out []SRCChain
	for i, g := range groups {
		subset := false
		for j, h := range groups {
			if i == j {
				continue
			}
			if isIDSubset(g.FindingIDs, h.FindingIDs) {
				if len(g.FindingIDs) < len(h.FindingIDs) || (len(g.FindingIDs) == len(h.FindingIDs) && j < i) {
					subset = true
					break
				}
			}
		}
		if !subset {
			out = append(out, g)
		}
	}
	return out
}

func isIDSubset(a, b []int64) bool {
	set := map[int64]bool{}
	for _, id := range b {
		set[id] = true
	}
	for _, id := range a {
		if !set[id] {
			return false
		}
	}
	return true
}

// findingRole classifies a finding's place in a chain: lower priority numbers
// run earlier (credentials first, data read last). The name is authoritative;
// the summary is only a fallback (it often contains "无凭据" and would otherwise
// classify every finding as a credential finding).
func findingRole(f *db.DBFinding) (int, string) {
	// Name only: summaries often mention related credentials/objects and would
	// drag unrelated findings into the same chain.
	if p, role := roleFromString(strings.ToLower(f.Name)); p > 0 {
		return p, role
	}
	return 6, "其他"
}

func roleFromString(s string) (int, string) {
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(s, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("oauth", "硬编码", "client_secret", "client_id"):
		return 1, "凭据获取"
	case has("cookie", "会话", "postmessage"):
		return 2, "会话窃取"
	case has("上传", "写入", "可写", "可删", "multipart", "putobject"):
		return 3, "写入"
	case has("预签名", "预览", "file-preview", "签名"):
		return 4, "签名/预览"
	case has("匿名可读", "匿名可列", "listbucket", "getobject", "对象存储", "桶"):
		return 5, "读取/枚举"
	}
	return 0, ""
}

// DetectSRCChains returns deterministic business-role chains without calling an
// LLM. It is used by the export preflight to warn when a selection only covers
// part of a chain.
func DetectSRCChains(findings []*db.DBFinding, assetTypes, assetLabels map[int64]string) []SRCChain {
	return dedupeChains(fallbackSRCChains(findings, assetTypes, assetLabels))
}

// FindingRole exposes the chain role classifier to the export preflight.
func FindingRole(f *db.DBFinding) (int, string) { return findingRole(f) }
