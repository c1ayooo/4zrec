// zreark_dispatch.go 向 4zreark 下发资产收集任务并查看远端任务状态。
// 走 4zreark 的 MCP 任务工具：create_task → start_task，状态用 list_tasks 轮询。
// 只暴露资产收集类任务类型；攻击性验证（vuln_scan 等）不在此入口。
package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

// zrearkTaskTypes 允许下发的任务类型（4zreark models/task.go 枚举的资产收集子集）。
var zrearkTaskTypes = map[string]string{
	"asset_discovery": "资产发现",
	"full":            "综合采集",
	"subdomain":       "子域名枚举",
	"port_scan":       "端口扫描",
	"fingerprint":     "指纹识别",
	"crawler":         "Web 爬虫",
	"dir_scan":        "目录扫描",
}

// zrearkTargetTypes create_task 支持的目标形态。
var zrearkTargetTypes = map[string]bool{"domain": true, "ip": true, "url": true, "cidr": true}

// zrearkTaskStatuses list_tasks 的状态过滤枚举。
var zrearkTaskStatuses = map[string]bool{
	"pending": true, "running": true, "paused": true,
	"completed": true, "failed": true, "cancelled": true,
}

// zrearkDispatchRequest 下发请求。连接信息可缺省（回落持久化配置）。
type zrearkDispatchRequest struct {
	BaseURL         string   `json:"base_url"`
	APIKey          string   `json:"api_key"`
	SourceProjectID int64    `json:"source_project_id"`
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Targets         []string `json:"targets"`
	TargetType      string   `json:"target_type"`
	Description     string   `json:"description"`
	AutoStart       *bool    `json:"auto_start"`
}

// zrearkDispatch 下发资产收集任务：create_task（4zreark 侧校验目标是否落在
// 项目站点/种子范围内，越界原样透传其报错）→ 默认自动 start_task。
func (s *Server) zrearkDispatch(w http.ResponseWriter, r *http.Request) {
	var req zrearkDispatchRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if _, ok := zrearkTaskTypes[strings.TrimSpace(req.Type)]; !ok {
		writeErr(w, http.StatusBadRequest, "不支持的任务类型，允许: asset_discovery/full/subdomain/port_scan/fingerprint/crawler/dir_scan")
		return
	}
	if !zrearkTargetTypes[strings.TrimSpace(req.TargetType)] {
		writeErr(w, http.StatusBadRequest, "target_type 只支持 domain/ip/url/cidr")
		return
	}
	targets := make([]string, 0, len(req.Targets))
	seen := map[string]bool{}
	for _, t := range req.Targets {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		writeErr(w, http.StatusBadRequest, "targets 不能为空")
		return
	}
	if req.SourceProjectID <= 0 {
		writeErr(w, http.StatusBadRequest, "source_project_id 必填：4zreark 任务必须落在具体项目内")
		return
	}
	caller, err := s.zrearkCallerFromRequest(req.BaseURL, req.APIKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	args := map[string]any{
		"project_id":  req.SourceProjectID,
		"name":        strings.TrimSpace(req.Name),
		"type":        strings.TrimSpace(req.Type),
		"targets":     targets,
		"target_type": strings.TrimSpace(req.TargetType),
	}
	if desc := strings.TrimSpace(req.Description); desc != "" {
		args["description"] = desc
	}
	raw, err := caller.call(r.Context(), "create_task", args)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var created struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &created); err != nil || created.ID == "" {
		writeErr(w, http.StatusBadGateway, "解析 create_task 返回失败: "+err.Error())
		return
	}

	out := map[string]any{
		"task_id": created.ID,
		"status":  created.Status,
		"targets": len(targets),
	}
	if autoStart := req.AutoStart; autoStart == nil || *autoStart {
		startArgs := map[string]any{"task_id": created.ID}
		if _, err := caller.call(r.Context(), "start_task", startArgs); err != nil {
			// 任务已创建、仅启动失败：不算整体失败，前端可展示后去 4zreark 手动启动。
			out["started"] = false
			out["start_error"] = err.Error()
		} else {
			out["started"] = true
			out["status"] = "running"
		}
	} else {
		out["started"] = false
	}
	writeJSON(w, http.StatusOK, out)
}

// zrearkTask 是 list_tasks 返回行的归一化视图（前端列表用）。
type zrearkTask struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Status           string `json:"status"`
	Progress         int    `json:"progress"`
	TargetCount      int    `json:"target_count"`
	TargetType       string `json:"target_type"`
	DiscoveredAssets int    `json:"discovered_assets"`
	DiscoveredPorts  int    `json:"discovered_ports"`
	LastError        string `json:"last_error,omitempty"`
	CreatedAt        string `json:"created_at,omitempty"`
	CompletedAt      string `json:"completed_at,omitempty"`
}

// zrearkTasks 拉取 4zreark 任务列表（默认最近 20 条）。
func (s *Server) zrearkTasks(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseURL         string `json:"base_url"`
		APIKey          string `json:"api_key"`
		SourceProjectID int64  `json:"source_project_id"`
		Status          string `json:"status"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	caller, err := s.zrearkCallerFromRequest(req.BaseURL, req.APIKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	args := map[string]any{"page": 1, "page_size": 20}
	if req.SourceProjectID > 0 {
		args["project_id"] = req.SourceProjectID
	}
	if status := strings.TrimSpace(req.Status); status != "" {
		if !zrearkTaskStatuses[status] {
			writeErr(w, http.StatusBadRequest, "status 只支持 pending/running/paused/completed/failed/cancelled")
			return
		}
		args["status"] = status
	}
	raw, err := caller.call(r.Context(), "list_tasks", args)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var page struct {
		Items []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Type        string `json:"type"`
			Status      string `json:"status"`
			Progress    int    `json:"progress"`
			Targets     []any  `json:"targets"`
			TargetType  string `json:"target_type"`
			LastError   string `json:"last_error"`
			CreatedAt   string `json:"created_at"`
			CompletedAt string `json:"completed_at"`
			ResultStats struct {
				DiscoveredAssets int `json:"discovered_assets"`
				DiscoveredPorts  int `json:"discovered_ports"`
			} `json:"result_stats"`
		} `json:"items"`
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		writeErr(w, http.StatusBadGateway, "解析 4zreark 任务列表失败: "+err.Error())
		return
	}
	tasks := make([]zrearkTask, 0, len(page.Items))
	for _, it := range page.Items {
		tasks = append(tasks, zrearkTask{
			ID:               it.ID,
			Name:             it.Name,
			Type:             it.Type,
			Status:           it.Status,
			Progress:         it.Progress,
			TargetCount:      len(it.Targets),
			TargetType:       it.TargetType,
			DiscoveredAssets: it.ResultStats.DiscoveredAssets,
			DiscoveredPorts:  it.ResultStats.DiscoveredPorts,
			LastError:        strings.TrimSpace(it.LastError),
			CreatedAt:        it.CreatedAt,
			CompletedAt:      it.CompletedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": tasks, "total": page.Total})
}
