package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/toolface/guard"
)

// --- 项目管理 API ---
//
// 项目 = 一次渗透委托的授权根:持有 project_scope(授权范围),作为任务/对话/
// 资产的归属父级。资产围栏(执行侧授权闸门)的白名单来自这里——见 db/projects.go
// 与 guard/fence.go。公司仍是客户主体,项目可选挂在公司下。

type projectReq struct {
	Name        string `json:"name"`
	CompanyID   *int64 `json:"company_id"`
	Description string `json:"description"`
	Status      string `json:"status"` // active|archived(PATCH 用)
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	projects, err := pg.Projects().ListProjects()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 项目级 API Key 只看到自己绑定的项目。
	if pid := scopedProjectID(r.Context()); pid > 0 {
		filtered := make([]db.Project, 0, 1)
		for _, p := range projects {
			if p.ID == pid {
				filtered = append(filtered, p)
			}
		}
		projects = filtered
	}
	if projects == nil {
		projects = []db.Project{}
	}
	writeJSON(w, 200, map[string]any{"projects": projects})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req projectReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, 400, "项目名称不能为空")
		return
	}
	p, err := pg.Projects().CreateProject(name, req.CompanyID, strings.TrimSpace(req.Description))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid project id")
		return
	}
	var req projectReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, 400, "项目名称不能为空")
		return
	}
	status := req.Status
	if status == "" {
		status = "active"
	}
	if status != "active" && status != "archived" {
		writeErr(w, 400, "status 只能是 active|archived")
		return
	}
	// PATCH 不改 company:需显式传,缺省保持原值由前端回填;为简化,company_id
	// 非 nil 才更新(含指向 0=取消关联)。
	p, err := pg.Projects().UpdateProject(id, name, req.CompanyID, strings.TrimSpace(req.Description), status)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid project id")
		return
	}
	q := r.URL.Query()
	deleteTasks := q.Get("delete_tasks") == "1" || q.Get("delete_tasks") == "true"
	deleteAssets := q.Get("delete_assets") == "1" || q.Get("delete_assets") == "true"

	deletedTasks := 0
	if deleteTasks {
		ids, err := pg.TaskIDsByProject(id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		for _, tid := range ids {
			_, derr := s.deleteTaskInternal(r.Context(), strconv.FormatInt(tid, 10), DeleteTaskOptions{})
			if derr != nil {
				var committed *taskDeleteCommittedError
				if errors.As(derr, &committed) {
					deletedTasks++ // DB 已删,仅清理告警
					continue
				}
				writeErr(w, 500, fmt.Sprintf("删除任务 #%d 失败: %v（项目未删除，可重试）", tid, derr))
				return
			}
			deletedTasks++
		}
	}

	deletedAssets := int64(0)
	if deleteAssets {
		n, aerr := pg.Assets().DeleteByProject(id)
		if aerr != nil {
			writeErr(w, 500, aerr.Error())
			return
		}
		deletedAssets = n
	}

	// 项目行删除:project_scope 与项目级 api_keys 走 ON DELETE CASCADE;
	// 未勾选删除的任务/资产保留,project_id 置 NULL(解除归属)。
	if err := pg.Projects().DeleteProject(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "deleted_tasks": deletedTasks, "deleted_assets": deletedAssets,
	})
}

type projectScopeReq struct {
	Scope  string `json:"scope"` // 多行文本,一行一条
	Reason string `json:"reason"`
}

func (s *Server) addProjectScope(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid project id")
		return
	}
	if !s.checkProjectScope(w, r, id) {
		return
	}
	var req projectScopeReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	lines := strings.Split(req.Scope, "\n")
	added, skipped, invalid, errMsgs := pg.Projects().AddProjectScope(id, lines, req.Reason)
	// 范围命中即授权:把存量未归属资产认领进项目(只升不降),同步进来的
	// 资产靠这步进项目。失败不吞——范围已保存,但要让用户知道认领没成。
	claimed, cerr := pg.Projects().RecomputeProjectAttribution()
	if cerr != nil {
		errMsgs = append(errMsgs, "范围已保存,但存量资产认领失败: "+cerr.Error())
		claimed = 0
	}
	p, _ := pg.Projects().GetProject(id)
	writeJSON(w, 200, map[string]any{
		"added": added, "skipped": skipped, "invalid": invalid,
		"errors": errMsgs, "project": p, "claimed": claimed,
	})
}

func (s *Server) deleteProjectScope(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid project id")
		return
	}
	if !s.checkProjectScope(w, r, id) {
		return
	}
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil || sid <= 0 {
		writeErr(w, 400, "invalid scope id")
		return
	}
	if err := pg.Projects().DeleteProjectScope(id, sid); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// scopeCandidates 从项目资产自动生成授权范围候选(GET /api/projects/{id}/scope/candidates)。
// 只读预览:前端展示勾选,导入走下面批量接口。两个来源合并——资产实证反推
// (assets 计数排序)与 LLM 建议(worker 收尾时 suggest_scope 提名,带依据);
// LLM 建议可能是资产里还没出现的根域,也可能与资产候选重合(取并集,重合的
// 标注双方来源)。
func (s *Server) scopeCandidates(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid project id")
		return
	}
	if !s.checkProjectScope(w, r, id) {
		return
	}
	candidates, err := pg.ProjectScopeCandidates(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 合并 LLM 建议:pending 的进入候选(带 reason),已 imported/dismissed 的不重复出现。
	suggestions, err := pg.ScopeSuggestions(id, "pending")
	if err == nil {
		index := map[string]map[string]any{}
		for _, c := range candidates {
			index[c["domain"].(string)] = c
		}
		for _, sug := range suggestions {
			dom, _ := sug["domain"].(string)
			if c, ok := index[dom]; ok {
				c["llm_reason"] = sug["reason"]
				continue
			}
			entry := map[string]any{"domain": dom, "assets": 0, "llm_reason": sug["reason"]}
			candidates = append(candidates, entry)
			index[dom] = entry
		}
	}
	writeJSON(w, 200, map[string]any{"candidates": candidates})
}

type importScopeReq struct {
	Domains []string `json:"domains"` // 勾选的候选根域
	Reason  string   `json:"reason"`
}

// importScope 把勾选的候选根域写入 project_scope,并立即触发范围认领——
// 命中的 pending 资产自动提为 approved,待审批队列随之清空(响应带认领数)。
func (s *Server) importScope(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid project id")
		return
	}
	if !s.checkProjectScope(w, r, id) {
		return
	}
	var req importScopeReq
	if err := decode(r, &req); err != nil || len(req.Domains) == 0 {
		writeErr(w, 400, "domains 不能为空")
		return
	}
	added, skipped, invalid, errMsgs := pg.ImportProjectScope(id, req.Domains, req.Reason)
	// 建议池状态同步:已导入的建议标 imported(下次候选不再重复出现)。
	if err := pg.ResolveScopeSuggestions(id, req.Domains, "imported"); err != nil {
		log.Printf("[projects] 建议状态同步失败(项目 %d): %v", id, err)
	}
	claimed, cerr := pg.Projects().RecomputeProjectAttribution()
	if cerr != nil {
		errMsgs = append(errMsgs, "范围已保存,但存量资产认领失败: "+cerr.Error())
		claimed = 0
	}
	p, _ := pg.Projects().GetProject(id)
	writeJSON(w, 200, map[string]any{
		"added": added, "skipped": skipped, "invalid": invalid,
		"errors": errMsgs, "project": p, "claimed": claimed,
	})
}

// --- 资产授权状态(待审批队列) ---

// listPendingAssets 返回待审批资产;project_id>0 时按项目过滤,0=全部。
func (s *Server) listPendingAssets(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	projectID, _ := strconv.ParseInt(r.URL.Query().Get("project_id"), 10, 64)
	if scopeProject := scopedProjectID(r.Context()); scopeProject > 0 {
		projectID = scopeProject // 项目级 key 强制只看本项目
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	assets, total, err := pg.Assets().ListPendingAssets(projectID, limit, offset)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if assets == nil {
		assets = []*db.Asset{}
	}
	writeJSON(w, 200, map[string]any{"assets": assets, "total": total})
}

type assetAuthzReq struct {
	IDs       []int64 `json:"ids"`
	Action    string  `json:"action"`     // approve|reject|pending
	ProjectID int64   `json:"project_id"` // approve 时可同时归属项目(可选)
}

// setAssetAuthz 批量设置资产授权状态(待审批队列的批准/拒绝动作)。
func (s *Server) setAssetAuthz(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req assetAuthzReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, 400, "ids 不能为空")
		return
	}
	if scopeProject := scopedProjectID(r.Context()); scopeProject > 0 {
		if req.ProjectID > 0 && req.ProjectID != scopeProject {
			writeErr(w, 403, "项目级 API Key 只能操作本项目资产")
			return
		}
		req.ProjectID = scopeProject
		outside, err := pg.AssetsOutsideProject(req.IDs, scopeProject)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if len(outside) > 0 {
			writeErr(w, 403, "ids 包含其他项目的资产")
			return
		}
	}
	switch req.Action {
	case "approve":
		if err := pg.Assets().ApproveAssetsWithProject(req.IDs, req.ProjectID); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		// 资产批准联动围栏:因这些目标挂起(等待审批)的围栏调用自动按允许
		// 放行——用户在待审批队列批了资产,不必再去审批记录页点第二次。
		if n := s.m.interceptor.ReleaseAsks(guard.NewAssetFence(pg).AskAuthorized); n > 0 {
			log.Printf("[fence] 资产批准联动放行 %d 条挂起的围栏审批", n)
		}
	case "reject", "pending":
		if err := pg.Assets().SetAssetAuthz(req.IDs, req.Action); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	default:
		writeErr(w, 400, "action 只能是 approve|reject|pending")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "updated": len(req.IDs)})
}

// assetsBind 手工批量认领:把未归属(或本项目)的存量资产绑到指定项目。
// 语义与手工认领一致:只认领未归属资产(不抢他项目),授权随范围判定
// (命中范围 approved、范围外 pending 待审批)。
func (s *Server) assetsBind(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	as := pg.Assets()
	var in struct {
		ProjectID int64   `json:"project_id"`
		IDs       []int64 `json:"ids"`
	}
	if err := decode(r, &in); err != nil || in.ProjectID <= 0 || len(in.IDs) == 0 {
		writeErr(w, 400, "project_id 与 ids 必填")
		return
	}
	if scopeProject := scopedProjectID(r.Context()); scopeProject > 0 {
		if in.ProjectID != scopeProject {
			writeErr(w, 403, "项目级 API Key 只能操作本项目资产")
			return
		}
		outside, err := pg.AssetsOutsideProject(in.IDs, scopeProject)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if len(outside) > 0 {
			writeErr(w, 403, "ids 包含其他项目的资产")
			return
		}
	}
	if in.ProjectID > 0 {
		if _, err := pg.Projects().GetProject(in.ProjectID); err != nil {
			writeErr(w, 404, "项目不存在")
			return
		}
	}
	// 手工归属 = 操作者的人工授权决定:直接 approved,不再进待审批二次确认。
	for _, id := range in.IDs {
		_, _ = as.StampDiscoveredAsset(id, in.ProjectID)
		_ = as.SetAssetAuthz([]int64{id}, "approved")
	}
	bound := len(in.IDs)
	// 子资产跟随归属:所选资产(根域名/子域名)的同根 IP/子域名/服务一并归属
	// (只认领未归属,不抢他项目),并同样直接 approved。
	// 子资产根集合:逐 id 查询(数量小)。
	rootsSet := map[string]bool{}
	for _, id := range in.IDs {
		var r string
		if err := pg.QueryRowContext(context.Background(), `SELECT COALESCE(NULLIF(root_domain,''), '') FROM assets WHERE id=$1`, id).Scan(&r); err == nil && r != "" {
			rootsSet[r] = true
		}
	}
	if len(rootsSet) > 0 {
		roots := make([]string, 0, len(rootsSet))
		for r := range rootsSet {
			roots = append(roots, r)
		}
		ph := make([]string, 0, len(roots))
		args := []any{in.ProjectID}
		for _, r := range roots {
			args = append(args, r)
			ph = append(ph, fmt.Sprintf("$%d", len(args)))
		}
		_, _ = pg.ExecContext(context.Background(), `
UPDATE assets SET project_id=COALESCE(project_id,$1), authz='approved', updated_at=now()
WHERE root_domain IN (`+strings.Join(ph, ",")+`) AND (project_id IS NULL OR project_id=$1)`, args...)
	}
	if bound > 0 {
		_, _ = pg.Projects().RecomputeProjectAttribution()
	}
	writeJSON(w, 200, map[string]any{"bound": bound, "approved": bound, "pending": 0})
}
