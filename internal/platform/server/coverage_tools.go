// coverage_tools.go 项目级覆盖度缺口查询:授权范围内的资产盘子、已测/未测分布、
// 未测样本(任务级 list_untested_assets 的项目级对齐件,4zreco query_assets/
// lineage_gap 的语义在本仓收敛为「范围有、事实没锚」)。读侧与项目授权范围
// 求交(查询本身以项目为锚,读不出范围外)。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// toolProjectCoverage 项目覆盖度总览。
func (s *Server) toolProjectCoverage() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "project_coverage",
		Description: "项目覆盖度总览(只读):授权范围内的资产盘子(按类型)、已测/未测分布与未测样本清单——" +
			"「范围有什么、测过什么、还缺什么」的一页答案。已测口径=存在事实锚点(与任务级 list_untested_assets 一致);" +
			"查询以项目为锚,天然读不出授权范围外。适合规划下一步补测方向与 recon agent 清扫后的验收。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"project_id": map[string]any{"type": "integer", "description": "目标项目(挂项目任务自动取上下文)"},
			},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				ProjectID int64 `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			projectID := s.roeProjectID(ctx, in.ProjectID)
			if projectID <= 0 {
				return actool.Errorf("需要项目上下文:传 project_id 或在挂项目的任务/会话中调用"), nil
			}
			cov, err := s.m.pg.ProjectCoverageOverview(ctx, projectID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "项目 %d 覆盖度:范围规则 %d 条,盘子资产 %d(已测 %d / 未测 %d)\n",
				projectID, cov.ScopeRules, cov.InScope, cov.Tested, cov.Untested)
			if len(cov.ByType) > 0 {
				var parts []string
				for t, n := range cov.ByType {
					parts = append(parts, fmt.Sprintf("%s:%d", t, n))
				}
				fmt.Fprintf(&b, "类型分布: %s\n", strings.Join(parts, " "))
			}
			if len(cov.Sample) > 0 {
				fmt.Fprintf(&b, "未测样本(前 %d):\n", len(cov.Sample))
				for _, it := range cov.Sample {
					fmt.Fprintf(&b, "- [%s] %s\n", it.Type, it.Label)
				}
				if cov.Untested > len(cov.Sample) {
					fmt.Fprintf(&b, "…等 %d 个未测资产\n", cov.Untested)
				}
			}
			b.WriteString("\n补测走 list_untested_assets(任务级细化)或建任务锚定缺口方向。")
			return actool.Text(b.String()), nil
		},
	})
}

// coverageTools 覆盖度工具族。
func (s *Server) coverageTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolProjectCoverage()}
}
