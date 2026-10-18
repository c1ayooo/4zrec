package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capability/recon/fingerprint"
	"github.com/c1ayooo/4zrec/internal/capability/vuln/nuclei"
	"github.com/c1ayooo/4zrec/internal/domain/db"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// toolFingerprintVerify 生成“指纹 → 漏洞库/情报 POC → 模板”的定向验证计划。
// 默认 plan-only；execute=true 时按识别出的产品分组调用 nuclei_scan，仍走
// 模板级门禁（based_on_product + 相关模板），不会退化成全量漏扫。
func (s *Server) toolFingerprintVerify() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "fingerprint_verify",
		Description: "基于真实指纹生成定向验证计划：读取目标 technologies，查 1day 漏洞库、情报流 POC 和 nuclei 模板，" +
			"只返回与识别结果相关的候选。默认只出计划，不执行扫描；execute=true 时按产品分组调用 nuclei_scan，" +
			"仍受模板级门禁约束（只跑相关模板，禁用 automatic/纯 tags 扫描）。" +
			"目标必须先完成 fingerprint_scan（或 enrich）；没有 technologies 时直接拒绝。",
		Schema: objSchema(map[string]any{
			"targets": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "已识别的目标 URL（单次最多 50 个）",
			},
			"project_id": map[string]any{"type": "integer", "description": "项目上下文（可选）"},
			"max_templates": map[string]any{
				"type": "integer", "description": "计划中最多包含的模板数（默认 10，最大 20）",
			},
			"execute": map[string]any{
				"type": "boolean", "description": "默认 false=只生成计划；true=按计划分组执行 nuclei_scan",
			},
		}, "targets"),
		ReadOnly: func(raw json.RawMessage) bool { return !fingerprintVerifyExecute(raw) },
		Concurrent: func(raw json.RawMessage) bool {
			return !fingerprintVerifyExecute(raw)
		},
		Permissions: func(_ context.Context, raw json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				Targets []string `json:"targets"`
				Execute bool     `json:"execute"`
			}
			_ = json.Unmarshal(raw, &in)
			if in.Execute {
				return actool.AskUser(fmt.Sprintf("指纹定向验证并执行 nuclei：%d 个目标", len(in.Targets)))
			}
			return actool.AskUser(fmt.Sprintf("生成指纹定向验证计划：%d 个目标", len(in.Targets)))
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Targets      []string `json:"targets"`
				ProjectID    int64    `json:"project_id"`
				MaxTemplates int      `json:"max_templates"`
				Execute      bool     `json:"execute"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if len(in.Targets) == 0 {
				return actool.Errorf("targets 不能为空"), nil
			}
			if len(in.Targets) > 50 {
				return actool.Errorf(fmt.Sprintf("单次最多 50 个目标，当前 %d 个", len(in.Targets))), nil
			}

			targetURLs := make([]string, 0, len(in.Targets))
			for _, target := range in.Targets {
				u, err := nucleiTargetURL(target)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if msg := s.webreconRoE(ctx, in.ProjectID, u); msg != "" {
					return actool.Errorf(strings.TrimSpace(msg)), nil
				}
				targetURLs = append(targetURLs, u)
			}

			evidence, err := s.requireTargetFingerprints(targetURLs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			techs := fingerprintTechnologies(evidence)
			if len(techs) == 0 {
				return actool.Errorf("没有可用的指纹证据；请先调用 fingerprint_scan（或 enrich）"), nil
			}
			maxTemplates := in.MaxTemplates
			if maxTemplates <= 0 {
				maxTemplates = 10
			}
			if maxTemplates > 20 {
				maxTemplates = 20
			}

			pg := s.m.PG()
			if pg == nil {
				return actool.Errorf("数据库不可用，无法查询漏洞库/情报流"), nil
			}
			mgr := s.nucleiManager()
			idx := mgr.Index()

			var kb []db.VulnKBEntry
			seenKB := map[int64]bool{}
			for _, tech := range techs {
				entries, _, err := pg.ListVulnKB(tech, "", 0, 3)
				if err != nil {
					continue
				}
				for _, e := range entries {
					if seenKB[e.ID] {
						continue
					}
					seenKB[e.ID] = true
					kb = append(kb, e)
					if len(kb) >= 5 {
						break
					}
				}
				if len(kb) >= 5 {
					break
				}
			}

			var intel []db.EnrichedVulnIntel
			seenIntel := map[int64]bool{}
			for _, tech := range techs {
				entries, _, err := pg.ListVulnIntel(tech, "", 0, 2)
				if err != nil {
					continue
				}
				for _, e := range entries {
					if seenIntel[e.ID] {
						continue
					}
					seenIntel[e.ID] = true
					intel = append(intel, e)
					if len(intel) >= 5 {
						break
					}
				}
				if len(intel) >= 5 {
					break
				}
			}

			var templates []nuclei.TemplateMeta
			seenTpl := map[string]bool{}
			for _, tech := range techs {
				found, _, err := idx.Search(tech, nuclei.Filters{}, 20)
				if err != nil {
					continue
				}
				for _, meta := range found {
					if seenTpl[meta.ID] || isDestructiveTemplate(meta) || !templateMatchesProduct(meta, tech, techs) {
						continue
					}
					seenTpl[meta.ID] = true
					templates = append(templates, meta)
					if len(templates) >= maxTemplates {
						break
					}
				}
				if len(templates) >= maxTemplates {
					break
				}
			}
			if len(kb) == 0 && len(intel) == 0 && len(templates) == 0 {
				return actool.Errorf("没有找到与识别结果相关的漏洞库/模板候选；不要扩大范围乱扫"), nil
			}
			if in.Execute && len(templates) == 0 {
				return actool.Errorf("没有与识别结果相关的模板可执行；不要扩大范围乱扫"), nil
			}

			var b strings.Builder
			b.WriteString("指纹定向验证计划\n")
			fmt.Fprintf(&b, "目标: %s\n", strings.Join(targetURLs, ", "))
			fmt.Fprintf(&b, "指纹: %s\n", strings.Join(techs, ", "))

			if len(kb) > 0 {
				b.WriteString("\n1day 漏洞库候选:\n")
				for _, e := range kb {
					fmt.Fprintf(&b, "- [%s] %s | %s", e.Product, e.Title, e.VulnType)
					if e.CVE != "" {
						fmt.Fprintf(&b, " | %s", e.CVE)
					}
					b.WriteString("\n")
					if e.RequestLine != "" {
						fmt.Fprintf(&b, "    请求: %s\n", e.RequestLine)
					}
				}
			}

			if len(intel) > 0 {
				b.WriteString("\n情报/POC 候选:\n")
				for _, e := range intel {
					meta := []string{}
					if e.Severity != "" {
						meta = append(meta, e.Severity)
					}
					if e.CVE != "" {
						meta = append(meta, e.CVE)
					}
					fmt.Fprintf(&b, "- %s", e.Title)
					if len(meta) > 0 {
						fmt.Fprintf(&b, " (%s)", strings.Join(meta, " | "))
					}
					b.WriteString("\n")
					for j, p := range parseVulnIntelPOCs(e.GithubPoc) {
						if j >= 2 {
							break
						}
						fmt.Fprintf(&b, "    POC: %s\n", p.URL)
					}
					if e.SourceURL != "" {
						fmt.Fprintf(&b, "    来源: %s\n", e.SourceURL)
					}
				}
			}

			if len(templates) > 0 {
				b.WriteString("\n模板候选:\n")
				for _, t := range templates {
					fmt.Fprintf(&b, "- %s [%s] %s\n", t.ID, t.Severity, t.Name)
				}
				for _, tech := range techs {
					ids := []string{}
					for _, t := range templates {
						if templateMatchesProduct(t, tech, techs) {
							ids = append(ids, t.ID)
						}
					}
					if len(ids) > 0 {
						fmt.Fprintf(&b, "\n建议执行: nuclei_scan(targets=[已识别目标], based_on_product=%q, templates=%s)\n", tech, quoteStringList(ids))
						break
					}
				}
			}
			b.WriteString("\n注意: 本计划只包含与已识别指纹相关的候选；nuclei 命中仍需 http_probe/流量证据复核。\n")

			if !in.Execute {
				return actool.Text(b.String()), nil
			}

			b.WriteString("\n执行结果:\n")
			executed := map[string]bool{}
			for _, tech := range techs {
				ids := []string{}
				for _, t := range templates {
					if executed[t.ID] || !templateMatchesProduct(t, tech, techs) {
						continue
					}
					ids = append(ids, t.ID)
				}
				if len(ids) == 0 {
					continue
				}
				targets := []string{}
				for _, target := range targetURLs {
					if fingerprint.QueryMatches(evidence[target], tech) {
						targets = append(targets, target)
					}
				}
				if len(targets) == 0 {
					continue
				}
				for _, id := range ids {
					executed[id] = true
				}
				scanInput, _ := json.Marshal(map[string]any{
					"targets": targets, "based_on_product": tech, "templates": ids, "project_id": in.ProjectID,
				})
				res, err := s.toolNucleiScan().Call(ctx, scanInput, nil)
				if err != nil {
					fmt.Fprintf(&b, "\n## %s\n执行失败: %v\n", tech, err)
					continue
				}
				fmt.Fprintf(&b, "\n## %s\n%s\n", tech, res.Flatten())
			}
			return actool.Text(b.String()), nil
		},
	})
}

func fingerprintVerifyExecute(raw json.RawMessage) bool {
	var in struct {
		Execute bool `json:"execute"`
	}
	_ = json.Unmarshal(raw, &in)
	return in.Execute
}

// bindFingerprintVerifyTool 是新增工具的一次性绑定迁移：nuclei_tools_bind_v1
// 的守卫早已置位，旧库不会自动绑定新工具。
func (s *Server) bindFingerprintVerifyTool(agents []string) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	const flag = "fingerprint_verify_bind_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, key := range agents {
		if a, _ := s.m.pg.GetAgentByKey(key); a == nil {
			continue
		}
		if err := s.m.pg.AddAgentToToolBinding(key, []string{"fingerprint_verify"}); err != nil {
			log.Printf("[nuclei] 绑定 fingerprint_verify → %s 失败: %v", key, err)
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// bindSearchVulnKB 把 search_vuln_kb 从 planner 扩到真正做指纹识别的 agent，
// 否则 recon 识别完产品后无法直接查 1day 库/情报 POC。
func (s *Server) bindSearchVulnKB() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	const flag = "search_vuln_kb_bind_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, key := range []string{"recon", "worker", "pentest", "auto"} {
		if a, _ := s.m.pg.GetAgentByKey(key); a == nil {
			continue
		}
		if err := s.m.pg.AddAgentToToolBinding(key, []string{"search_vuln_kb"}); err != nil {
			log.Printf("[nuclei] 绑定 search_vuln_kb → %s 失败: %v", key, err)
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

func parseVulnIntelPOCs(raw string) []db.VulnIntelPOC {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []db.VulnIntelPOC
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func quoteStringList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, s := range items {
		quoted = append(quoted, fmt.Sprintf("%q", s))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
