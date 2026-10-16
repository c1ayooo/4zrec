package server

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/db"
	"github.com/c1ayooo/4zrec/guard"
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
