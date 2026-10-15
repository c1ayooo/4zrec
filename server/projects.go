package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
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
	if err := pg.Projects().DeleteProject(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
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

// --- 资产授权状态(待审批队列) ---

// listPendingAssets 返回待审批资产;project_id>0 时按项目过滤,0=全部。
func (s *Server) listPendingAssets(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	projectID, _ := strconv.ParseInt(r.URL.Query().Get("project_id"), 10, 64)
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
	Action    string  `json:"action"`    // approve|reject|pending
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
	switch req.Action {
	case "approve":
		if err := pg.Assets().ApproveAssetsWithProject(req.IDs, req.ProjectID); err != nil {
			writeErr(w, 500, err.Error())
			return
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
