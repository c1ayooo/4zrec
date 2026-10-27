// zreark_collect_tools.go 4zreark 增强通道的本地侧工具:zreark_sync_results。
// agent 经 MCP 直调 4zreark 的 create_task/start_task/wait_task 完成采集后,
// 用本工具把该任务的结果(subdomain/port/service/crawler)拉回 4zrec 资产库。
// 未配置 4zreark 连接时返回明确提示,agent 改用本地保底工具(web_crawl 等)。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// toolZrearkSyncResults 按 4zreark 任务 ID 拉取结果并入库。
func (s *Server) toolZrearkSyncResults() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "zreark_sync_results",
		Description: "把 4zreark 采集任务的结果导入本平台资产库(增强通道,需已配置 4zreark 连接):" +
			"子域(subdomain)走项目范围状态机、端口(port)建 IP/服务资产、指纹(service)并入站点技术栈、" +
			"爬虫路由(crawler)落 endpoint。典型链路:经 MCP 调 4zreark 的 create_task→start_task→wait_task(完成)," +
			"再调本工具同步;未配置 4zreark 时用本地 web_crawl/subdomain_enum/port_scan 等。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"task_id":           map[string]any{"type": "string", "description": "4zreark 任务 ID(create_task 返回的 id)"},
				"include":           map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"subdomain", "port", "service", "crawler"}}, "description": "要同步的结果类型(缺省全部)"},
				"target_project_id": map[string]any{"type": "integer", "description": "入库归属项目(可选;缺省取任务/会话挂载)"},
				"limit":             map[string]any{"type": "integer", "description": "最多同步条数(默认 10000)"},
			},
			"required": []string{"task_id"},
		},
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				TaskID          string   `json:"task_id"`
				Include         []string `json:"include"`
				TargetProjectID int64    `json:"target_project_id"`
				Limit           int      `json:"limit"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			in.TaskID = strings.TrimSpace(in.TaskID)
			if in.TaskID == "" {
				return actool.Errorf("task_id 必填"), nil
			}
			include := map[string]bool{}
			for _, k := range in.Include {
				k = strings.TrimSpace(k)
				if zrearkSyncTypes[k] {
					include[k] = true
				}
			}
			if len(include) == 0 {
				for k := range zrearkSyncTypes {
					include[k] = true
				}
			}
			caller, err := s.zrearkCallerFromRequest("", "")
			if err != nil {
				return actool.Errorf("4zreark 未配置或不可用(" + err.Error() + ");请改用本地工具 subdomain_enum/web_crawl/port_scan/dir_scan"), nil
			}
			projectID := s.roeProjectID(ctx, in.TargetProjectID)
			result := &zrearkTaskResultsResult{TaskID: in.TaskID, Errors: []string{}}
			if err := s.zrearkSyncCore(ctx, caller, zrearkTaskSyncParams{
				TaskID:          in.TaskID,
				Include:         include,
				TargetProjectID: projectID,
				Limit:           in.Limit,
			}, result); err != nil {
				return actool.Errorf("同步失败: " + err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "任务 %s 同步完成:读取 %d 条 → 子域 %d、端口 %d、服务(指纹) %d、路由 %d,归属项目 %d 条",
				result.TaskID, result.Fetched, result.Subdomains, result.Ports, result.Services, result.Endpoints, result.Assigned)
			if result.Skipped > 0 {
				fmt.Fprintf(&b, ";跳过 %d", result.Skipped)
			}
			b.WriteString("\n")
			for _, e := range result.Errors {
				b.WriteString("- " + e + "\n")
			}
			return actool.Text(b.String()), nil
		},
	})
}

// zrearkCollectTools 4zreark 增强通道的本地工具族。
func (s *Server) zrearkCollectTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolZrearkSyncResults()}
}
