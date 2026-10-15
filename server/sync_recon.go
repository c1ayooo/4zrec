package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mcphttp"
	"github.com/Autumn-27/artex/notify"
)

// 资产同步（4zrecon 数据源）。
//
// 4zrecon 是一个 ASM 资产测绘平台，通过其 MCP 接口按【项目】/【任务】两个维度
// 拉取子域名、Web 应用、服务等资产，映射为 ARTEX 的公司 + 资产模型。数据源本身是
// 一个名为 "4zrecon" 的 http 传输 MCP 行（url + X-API-Key 头保存在 mcp_servers）。
//
// 与 agent 工具层不同，这里用 mcphttp.Client.Call 直接调用 MCP 工具、拿原始 JSON，
// 不触发 AskUser 权限弹窗（后台批量同步）。

const (
	reconMCPName    = "4zrecon" // MCP 行名（工具展开为 mcp__4zrecon__*）；旧座行名由 schema.sql 启动迁移
	syncMaxPerType  = 5000      // 单目标单类型的入库保护上限
	syncDefaultPage = 100

	// settingReconGrantsSeeded 标记只读工具授权已播过种。播种是一次性的：之后用户在
	// 可见性页对这几行的删改以用户为准，重启不复活（与 seedPrompts 的仅空时播种同语义）。
	settingReconGrantsSeeded = "4zrecon_readonly_grants_seeded"

	// settingSSLastReconcile 每日对账的时间戳（RFC3339）。对账是施工单变更1的
	// 兜底：list_assets 按 time 倒序返回是上游实现细节而非 API 承诺——上游若改
	// 排序，增量会静默失明。对账用 count_assets 快照对比发现失明，自愈手段是
	// 清水位（下一轮自动退化首刷全量，幂等 upsert 吸收）。
	settingSSLastReconcile = "sync_last_reconcile_at"
	syncReconcileEvery     = 24 * time.Hour
	syncReconcileGrowth    = 200 // 上游 24h 净增长超过此值而增量入库停滞才判失明

	// settingSyncProjects 增量同步的项目范围（JSON 字符串数组，元素为上游项目
	// ObjectID）。上游实例常混杂多项目数据，无范围的全局增量会把未选择项目的
	// 资产灌进来；空/未设置 = 不同步（增量是显式 opt-in，手动目标全量不受影响）。
	settingSyncProjects = "sync.selected_projects"

	// 上游原生时间格式（"2006-01-02 15:04:05"，节点时区、无 tz 标记）。水位一律
	// 取响应体同源 time 做字符串比较，禁用本地时钟生成水位。
	syncTimeLayout = "2006-01-02 15:04:05"
	// syncWatermarkLag 是水位回拨量：同一秒内的上游写入会落在上一轮水位上被跳过，
	// 回拨 60s 防边界丢数（重复拉取由入库幂等 upsert 吸收）。
	syncWatermarkLag = 60 * time.Second
)

// reconTypeMap：本仓资产类型键 → 4zrecon MCP 的 asset_type 取值（区分大小写，如
// RootDomain）。ip/UrlScan/SensitiveResult/vulnerability 不进默认同步：UrlScan
// 7.6 万条按任务 opt-in，Sensitive/vuln 走交互查询（findings 挂 task_id 语义不合）。
var reconTypeMap = map[string]string{
	"subdomain":   "subdomain",
	"root_domain": "RootDomain",
	"service":     "asset",
	"app":         "app",
}

// reconDefaultTypes 是增量与缺省全量的类型集合（RootDomain 默认纳入，量小自然补全）。
var reconDefaultTypes = []string{"subdomain", "root_domain", "service", "app"}

// reconReadOnlyTools 是同步数据源默认授权给 planner/worker 的只读 MCP 工具
// （裸工具名，运行时展开为 mcp__4zrecon__*）。写操作类（create_scan_task、
// add_asset_tag 等）默认不授，需要时在可见性页手动开启。
var reconReadOnlyTools = []string{"list_assets", "count_assets", "get_asset_detail", "list_tasks"}

// seedReconGrants 数据源启用后把 4 个只读工具授权给 planner/worker（交互通道
// 通电）。仅在数据源已配置启用时播种；失败只记日志，不阻塞调用方。
func (s *Server) seedReconGrants() {
	pg := s.m.pg
	if pg == nil {
		return
	}
	if _, ok, _ := pg.GetSetting(settingReconGrantsSeeded); ok {
		return
	}
	m, err := s.findMCPByName(reconMCPName)
	if err != nil || m == nil || !m.Enabled {
		return // 未配置/未启用：等 POST datasource 成功后由那边补播
	}
	granted := 0
	for _, key := range []string{"planner", "worker"} {
		a, err := pg.GetAgentByKey(key)
		if err != nil || a == nil {
			continue
		}
		if err := pg.GrantMCPTools(a.ID, m.ID, reconReadOnlyTools); err != nil {
			log.Printf("[sync] %s 只读工具授权失败: %v", key, err)
			return
		}
		granted++
	}
	if granted == 0 {
		return
	}
	_ = pg.SetSetting(settingReconGrantsSeeded, time.Now().Format(time.RFC3339))
	log.Printf("[sync] 已授权 planner/worker 访问 %s 只读工具: %v", reconMCPName, reconReadOnlyTools)
}

// findMCPByName returns the MCP server row with the given name, or nil.
func (s *Server) findMCPByName(name string) (*db.MCPServer, error) {
	all, err := s.m.pg.ListMCP()
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if m.Name == name {
			return m, nil
		}
	}
	return nil, nil
}

// reconClient dials the configured 4zrecon MCP (http transport). The env
// map doubles as HTTP headers (X-API-Key). Callers must Close the client.
func (s *Server) reconClient(ctx context.Context) (*mcphttp.Client, error) {
	m, err := s.findMCPByName(reconMCPName)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("数据源 %s 不存在，请先创建", reconMCPName)
	}
	if m.URL == "" {
		return nil, fmt.Errorf("数据源 %s 未配置 URL，请先配置", reconMCPName)
	}
	return mcphttp.New(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure)
}

// envHasValue reports whether the env/header map has any non-empty value
// (i.e. an API key / Authorization header was filled in).
func envHasValue(raw json.RawMessage) bool {
	for _, v := range jsonStrMap(raw) {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// ---------- GET /api/sync/4zrecon/status ----------

func (s *Server) syncReconStatus(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	m, err := s.findMCPByName(reconMCPName)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	resp := map[string]any{
		"exists":     m != nil,
		"configured": false,
		"enabled":    false,
		"reachable":  false,
		"tools":      []string{},
	}
	if m == nil {
		writeJSON(w, 200, resp)
		return
	}
	configured := m.URL != "" && envHasValue(m.Env)
	resp["configured"] = configured
	resp["enabled"] = m.Enabled
	resp["url"] = m.URL
	if m.Tools != nil {
		resp["tools"] = m.Tools
	}
	// 各类型水位/最近轮次（状态卡片展示增量健康度）。
	if states, serr := s.m.pg.ListSyncState(r.Context(), m.ID); serr == nil {
		resp["sync_state"] = states
	}
	// Light reachability probe only when it can actually connect.
	if configured && m.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		if cl, cerr := mcphttp.New(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure); cerr == nil {
			if _, terr := cl.Tools(ctx); terr == nil {
				resp["reachable"] = true
			}
			_ = cl.Close()
		}
	}
	writeJSON(w, 200, resp)
}

// ---------- POST /api/sync/4zrecon/datasource ----------
// Creates the placeholder row if missing, and/or sets URL + API key and enables it.

func (s *Server) syncReconDatasource(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var body struct {
		URL    string `json:"url"`
		APIKey string `json:"api_key"`
	}
	_ = decode(r, &body) // empty body = just create the placeholder
	body.URL = strings.TrimSpace(body.URL)
	body.APIKey = strings.TrimSpace(body.APIKey)

	m, err := s.findMCPByName(reconMCPName)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if m == nil {
		m = &db.MCPServer{Name: reconMCPName, Transport: "http", Env: json.RawMessage(`{"X-API-Key":""}`)}
	}
	if body.URL != "" {
		m.URL = body.URL
	}
	if body.APIKey != "" {
		env, _ := json.Marshal(map[string]string{"X-API-Key": body.APIKey})
		m.Env = env
	}
	// Enable only once it can actually be used.
	m.Enabled = m.URL != "" && envHasValue(m.Env)

	id, err := pg.SaveMCP(m)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	m.ID = id
	// Best-effort tool discovery so the status card shows tools right away.
	if m.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		_ = s.discoverAndCacheMCP(ctx, m)
		cancel()
		// 交互通道通电：数据源刚启用，顺手把只读工具授权播种掉（幂等，一次性）。
		s.seedReconGrants()
	}
	writeJSON(w, 200, map[string]any{"id": id, "enabled": m.Enabled})
}

// ---------- GET /api/sync/4zrecon/projects ----------

func (s *Server) syncReconProjects(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	cl, err := s.reconClient(ctx)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	defer cl.Close()

	args := map[string]any{
		"pageIndex": queryInt(r, "page", 1),
		"pageSize":  queryInt(r, "size", 50),
	}
	if q := r.URL.Query().Get("search"); q != "" {
		args["search"] = q
	}
	text, err := cl.Call(ctx, "list_projects_data", args)
	if err != nil {
		writeErr(w, 502, "list_projects_data 失败: "+err.Error())
		return
	}
	// {result:{All:[{id,name,logo,AssetCount,tag}], <tag>:[...]}, tag:{...}}
	var env struct {
		Result map[string]json.RawMessage `json:"result"`
		Tag    map[string]int             `json:"tag"`
	}
	if err := json.Unmarshal([]byte(text), &env); err != nil {
		writeErr(w, 502, "解析项目列表失败: "+err.Error())
		return
	}
	projects := json.RawMessage("[]")
	if raw, ok := env.Result["All"]; ok && len(raw) > 0 {
		projects = raw
	}
	writeJSON(w, 200, map[string]any{"projects": projects, "tag": env.Tag})
}

// ---------- GET /api/sync/4zrecon/selection ----------

// parseSyncProjects 解析持久化的同步范围。空串→nil（未设置）；坏 JSON→错误。
func parseSyncProjects(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// reconSelectedProjects 读取增量同步的项目范围（空 = 未设置/不同步）。
func (s *Server) reconSelectedProjects() ([]string, error) {
	if s.m == nil || s.m.pg == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	raw, _, err := s.m.pg.GetSetting(settingSyncProjects)
	if err != nil {
		return nil, err
	}
	return parseSyncProjects(raw)
}

func (s *Server) syncReconGetSelection(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	ids, err := s.reconSelectedProjects()
	if err != nil {
		writeErr(w, 500, "同步范围读取失败: "+err.Error())
		return
	}
	if ids == nil {
		ids = []string{}
	}
	writeJSON(w, 200, map[string]any{"projects": ids})
}

// syncReconSetSelection 保存同步范围。范围发生变化时清空全部类型水位——新勾选
// 项目的历史资产落在旧水位之前，不清水位它们永远不会被增量带进来；下一轮 ticker
// 会以新范围做一次首刷全量（幂等 upsert 吸收重复）。数据源未配置时只存范围不清水位。
func (s *Server) syncReconSetSelection(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var body struct {
		Projects []string `json:"projects"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	projects, changed := normalizeSyncProjects(body.Projects), false
	prev, err := s.reconSelectedProjects()
	if err == nil && !sameStringSet(prev, projects) {
		changed = true
	}
	raw, merr := json.Marshal(projects)
	if merr != nil {
		writeErr(w, 500, merr.Error())
		return
	}
	if err := pg.SetSetting(settingSyncProjects, string(raw)); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	resetWatermarks := 0
	if changed {
		if m, merr := s.findMCPByName(reconMCPName); merr == nil && m != nil {
			for _, ssType := range reconTypeMap {
				if err := pg.ResetSyncWatermark(r.Context(), m.ID, ssType); err == nil {
					resetWatermarks++
				}
			}
		}
	}
	writeJSON(w, 200, map[string]any{"projects": projects, "watermarks_reset": resetWatermarks})
}

// normalizeSyncProjects 去空、去重（保持首次出现顺序）。
func normalizeSyncProjects(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if !set[v] {
			return false
		}
	}
	return true
}

// ---------- GET /api/sync/4zrecon/tasks ----------

func (s *Server) syncReconTasks(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	cl, err := s.reconClient(ctx)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	defer cl.Close()

	args := map[string]any{
		"pageIndex": queryInt(r, "page", 1),
		"pageSize":  queryInt(r, "size", 50),
	}
	if q := r.URL.Query().Get("search"); q != "" {
		args["search"] = q
	}
	text, err := cl.Call(ctx, "list_tasks", args)
	if err != nil {
		writeErr(w, 502, "list_tasks 失败: "+err.Error())
		return
	}
	var env struct {
		List json.RawMessage `json:"list"`
	}
	if err := json.Unmarshal([]byte(text), &env); err != nil {
		writeErr(w, 502, "解析任务列表失败: "+err.Error())
		return
	}
	tasks := env.List
	if len(tasks) == 0 {
		tasks = json.RawMessage("[]")
	}
	writeJSON(w, 200, map[string]any{"tasks": tasks})
}

// ---------- POST /api/sync/4zrecon/sync ----------

type reconSyncReq struct {
	Mode          string   `json:"mode"`        // "full" 目标全量 | "inc" 全局增量(同 ticker)；缺省按调用形态推断
	Dimension     string   `json:"dimension"`   // "project" | "task"（full 模式必填）
	Targets       []string `json:"targets"`     // project ObjectIDs, or task names（full 模式必填）
	AssetTypes    []string `json:"asset_types"` // subdomain | root_domain | app | service
	CreateCompany bool     `json:"create_company"`
	PageSize      int      `json:"page_size"`
}

func (s *Server) syncReconRun(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	as := s.assetStore()
	cs := s.companyStore()
	if as == nil || cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req reconSyncReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	// mode 归一：显式传值优先；缺省时按调用形态推断——带 targets 的旧客户端要的是
	// 目标全量（曾经唯一的语义），空 targets 的新调用走全局增量（施工单变更1：默认 inc）。
	mode := reconNormalizeMode(req.Mode, len(req.Targets))
	if mode == "" {
		writeErr(w, 400, "mode 必须是 full 或 inc")
		return
	}

	if mode == "inc" {
		if !s.syncMu.TryLock() {
			writeErr(w, 409, "同步进行中，请稍候再试")
			return
		}
		defer s.syncMu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		synced, warnings, errs := s.reconIncremental(ctx)
		writeJSON(w, 200, map[string]any{
			"mode":     "inc",
			"synced":   synced,
			"warnings": warnings,
			"errors":   errs,
		})
		return
	}

	if req.Dimension != "project" && req.Dimension != "task" {
		writeErr(w, 400, "dimension 必须是 project 或 task")
		return
	}
	if len(req.Targets) == 0 {
		writeErr(w, 400, "targets 不能为空")
		return
	}
	if len(req.AssetTypes) == 0 {
		req.AssetTypes = append([]string(nil), reconDefaultTypes...)
	}
	pageSize := req.PageSize
	if pageSize <= 0 || pageSize > 500 {
		pageSize = syncDefaultPage
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	cl, err := s.reconClient(ctx)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	defer cl.Close()

	synced := map[string]int{"subdomain": 0, "root_domain": 0, "app": 0, "service": 0, "ip": 0}
	var companies []string
	var warnings, errs []string
	madeCompany := false

	for _, target := range req.Targets {
		filter := map[string]any{}
		switch req.Dimension {
		case "project":
			filter["project"] = []string{target}
			if req.CreateCompany {
				name, roots, perr := s.reconProjectMeta(ctx, cl, target)
				if perr != nil {
					warnings = append(warnings, fmt.Sprintf("项目 %s 详情获取失败: %v", target, perr))
				} else if name != "" {
					cid, cerr := cs.UpsertByName(name)
					if cerr != nil {
						warnings = append(warnings, fmt.Sprintf("公司 %s 创建失败: %v", name, cerr))
					} else {
						companies = append(companies, name)
						madeCompany = true
						if len(roots) > 0 {
							cs.AddScope(cid, roots, "4zrecon:"+name)
						}
					}
				}
			}
		case "task":
			filter["task"] = []string{target}
		}

		for _, at := range req.AssetTypes {
			ssType, ok := reconTypeMap[at]
			if !ok {
				warnings = append(warnings, "未知资产类型，已跳过: "+at)
				continue
			}
			items, truncated, ferr := s.reconPageAll(ctx, cl, ssType, filter, pageSize)
			if ferr != nil {
				errs = append(errs, fmt.Sprintf("%s(%s) 拉取失败: %v", at, target, ferr))
				continue
			}
			if truncated {
				warnings = append(warnings, fmt.Sprintf("%s(%s) 达到 %d 条上限，已截断", at, target, syncMaxPerType))
			}
			for _, raw := range items {
				if e := s.reconIngest(as, at, raw, synced); e != "" {
					errs = append(errs, e)
				}
			}
		}
	}

	// Rebuild company attribution so freshly-synced assets attach to their company
	// (scope was written above; assets came after).
	if madeCompany {
		_ = cs.RecomputeAttribution()
	}
	// 项目侧认领:同步入库只做企业归属,项目范围命中的资产在这里归属项目。
	s.claimProjectAssets("目标全量")

	// 目标全量只留 last_run 痕迹，不动水位：目标范围的"已同步"推不出全局结论，
	// 水位只有全局轮次（ticker / mode=inc）才有资格推进。
	s.recordSyncRun(ctx, req.AssetTypes, synced, warnings, errs)

	writeJSON(w, 200, map[string]any{
		"mode":      "full",
		"synced":    synced,
		"companies": companies,
		"warnings":  warnings,
		"errors":    errs,
	})
}

// recordSyncRun 把一轮（目标全量）同步的结果写进 sync_state 的 last_run_at/
// last_result/truncated——watermark 原值回写（SaveSyncState 只前进，等于不动）。
func (s *Server) recordSyncRun(ctx context.Context, assetTypes []string, synced map[string]int, warnings, errs []string) {
	pg := s.m.pg
	if pg == nil {
		return
	}
	m, err := s.findMCPByName(reconMCPName)
	if err != nil || m == nil {
		return
	}
	truncated := false
	for _, w := range warnings {
		if strings.Contains(w, "已截断") {
			truncated = true
			break
		}
	}
	for _, at := range assetTypes {
		if _, ok := reconTypeMap[at]; !ok {
			continue
		}
		st, serr := pg.SyncStateFor(ctx, m.ID, at)
		if serr != nil {
			continue
		}
		st.LastResult = fmt.Sprintf("full +%d items, %d warnings, %d errors", synced[at], len(warnings), len(errs))
		st.Truncated = truncated
		if err := pg.SaveSyncState(ctx, st); err != nil {
			log.Printf("[sync] sync_state 留痕失败(%s): %v", at, err)
		}
	}
	if truncated {
		s.notifySyncTruncated(ctx, strings.Join(warnings, "; "))
	}
}

// ---------- 增量水位 + 定时同步（施工单变更1） ----------

// reconIncremental 跑一轮全局增量：逐类型读水位 → reconPageSince 无过滤拉新 → 入库 →
// 水位前进（回拨 60s）→ sync_state 留痕。首刷（水位为空）退化为全局全量 + 5000
// 上限并以此建立水位；truncated 落 last_result 并走通知渠道告警。
// 调用方必须已持有 s.syncMu。
func (s *Server) reconIncremental(ctx context.Context) (synced map[string]int, warnings, errs []string) {
	synced = map[string]int{"subdomain": 0, "root_domain": 0, "app": 0, "service": 0, "ip": 0}
	pg := s.m.pg
	as := s.assetStore()
	if pg == nil || as == nil {
		errs = append(errs, "database unavailable")
		return synced, warnings, errs
	}
	m, err := s.findMCPByName(reconMCPName)
	if err != nil || m == nil || !m.Enabled {
		errs = append(errs, "数据源未配置或未启用")
		return synced, warnings, errs
	}
	cl, err := s.reconClient(ctx)
	if err != nil {
		errs = append(errs, err.Error())
		return synced, warnings, errs
	}
	defer cl.Close()

	// 增量只拉用户勾选的项目。无范围时跳过本轮：上游多项目混杂，无过滤的全局
	// 增量会把未选择项目的资产灌进来（增量是显式 opt-in；手动目标全量不受影响）。
	sel, selErr := s.reconSelectedProjects()
	if selErr != nil {
		errs = append(errs, "同步范围读取失败: "+selErr.Error())
		return synced, warnings, errs
	}
	if len(sel) == 0 {
		msg := "未设置同步项目范围（数据同步页 → 增量范围），本轮跳过"
		log.Printf("[sync] %s", msg)
		warnings = append(warnings, msg)
		return synced, warnings, errs
	}
	filter := map[string]any{"project": sel}

	for _, at := range reconDefaultTypes {
		ssType := reconTypeMap[at]
		st, serr := pg.SyncStateFor(ctx, m.ID, at)
		if serr != nil {
			errs = append(errs, fmt.Sprintf("%s 水位读取失败: %v", at, serr))
			continue
		}
		bootstrap := st.Watermark == ""
		var (
			items     []json.RawMessage
			truncated bool
			maxTime   string
			ferr      error
		)
		if bootstrap {
			// 首刷：范围内全量 + 总量保护上限。
			items, truncated, ferr = s.reconPageAll(ctx, cl, ssType, filter, syncDefaultPage)
			for _, raw := range items {
				if t := reconItemTime(raw); t > maxTime {
					maxTime = t
				}
			}
		} else {
			items, maxTime, truncated, ferr = s.reconPageSince(ctx, cl, ssType, filter, syncDefaultPage, st.Watermark)
		}
		if ferr != nil {
			// 本轮失败不推进水位：已入库部分下轮重拉，幂等 upsert 吸收。
			errs = append(errs, fmt.Sprintf("%s 拉取失败: %v", at, ferr))
			continue
		}
		for _, raw := range items {
			if e := s.reconIngest(as, at, raw, synced); e != "" {
				errs = append(errs, e)
			}
		}
		if truncated {
			warnings = append(warnings, fmt.Sprintf("%s 达到 %d 条上限，已截断", at, syncMaxPerType))
		}
		st.IncTaken += len(items)
		newWM := st.Watermark
		if maxTime != "" {
			if rb := reconRollbackWatermark(maxTime); rb > newWM {
				newWM = rb
			}
		}
		st.Watermark = newWM
		st.Truncated = truncated
		if bootstrap {
			st.LastResult = fmt.Sprintf("full +%d items", len(items))
		} else {
			st.LastResult = fmt.Sprintf("inc +%d items", len(items))
		}
		if truncated {
			st.LastResult += " (truncated)"
		}
		if serr := pg.SaveSyncState(ctx, st); serr != nil {
			warnings = append(warnings, fmt.Sprintf("%s 水位落库失败: %v", at, serr))
		}
	}
		if len(warnings) > 0 {
			s.notifySyncTruncated(ctx, strings.Join(warnings, "; "))
		}
		incTotal := 0
		for _, n := range synced {
			incTotal += n
		}
		if incTotal > 0 {
			s.claimProjectAssets("增量")
		}
		return synced, warnings, errs
}

// claimProjectAssets 把项目范围命中的未归属资产认领进项目(同步入库只做
// 企业归属,项目侧在这里补;只升不降,详见 RecomputeProjectAttribution)。
// 认领是增益操作:失败只记日志,不让同步轮次报错。
func (s *Server) claimProjectAssets(reason string) {
	pg := s.m.pg
	if pg == nil {
		return
	}
	n, err := pg.Projects().RecomputeProjectAttribution()
	if err != nil {
		log.Printf("[sync] 项目资产认领失败(%s): %v", reason, err)
		return
	}
	if n > 0 {
		log.Printf("[sync] 项目资产认领(%s): %d 条资产按项目范围归属", reason, n)
	}
}

// syncTick 是 ticker 的一轮：数据源未配置/未启用即静默跳过（不报错——半配置状态
// 是正常暂态），否则跑一轮增量。
func (s *Server) syncTick(ctx context.Context) {
	m, err := s.findMCPByName(reconMCPName)
	if err != nil || m == nil || !m.Enabled {
		return
	}
	if !s.syncMu.TryLock() {
		log.Printf("[sync] 上一轮同步仍在进行，跳过本轮")
		return
	}
	defer s.syncMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	synced, warnings, errs := s.reconIncremental(ctx)
	total := 0
	for _, n := range synced {
		total += n
	}
	if total > 0 || len(warnings) > 0 || len(errs) > 0 {
		log.Printf("[sync] 增量同步完成: %v（warnings=%d errors=%d）", synced, len(warnings), len(errs))
	}
	// 每日对账兜底：增量跑完再对（count_assets 反映的是本轮之后的上游总量）。
	// 设了同步范围就对不上账——count_assets 只报全局总量，无项目过滤，与范围内
	// 入库的计数永远失配，天天重置水位触发（过滤后的）全量重刷。跳过对账即可，
	// 失明风险由范围变更时的主动清水位兜底。
	if s.syncReconcileDue() {
		if sel, err := s.reconSelectedProjects(); err == nil && len(sel) > 0 {
			log.Printf("[sync] 已设置同步范围（%d 个项目），跳过全局对账", len(sel))
			return
		}
		if rc, rerr := s.reconClient(ctx); rerr == nil {
			s.ssReconcile(ctx, m, rc)
			rc.Close()
		} else {
			log.Printf("[sync] 对账拨号失败: %v", rerr)
		}
	}
}

// syncReconcileDue 对账到期判定（纯函数）：从未对过账或距上次 ≥ 24h。
func syncReconcileDue(last string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, last)
	if err != nil {
		return true
	}
	return now.Sub(t) >= syncReconcileEvery
}

func (s *Server) syncReconcileDue() bool {
	last, _, err := s.m.pg.GetSetting(settingSSLastReconcile)
	if err != nil {
		return false // 设置面不可用：宁可不对账也不误判
	}
	return syncReconcileDue(last, time.Now())
}

// reconcileNeedsReset 对账判定（纯函数）：上游净增长明显而增量入库停滞 → 增量
// 失明（典型病因：上游排序实现变化）。prev<=0 是首对账，无从比较不判。
func reconcileNeedsReset(prev, total, taken, threshold int) bool {
	if prev <= 0 {
		return false
	}
	growth := total - prev
	if growth <= threshold {
		return false
	}
	return taken*2 < growth
}

// ssCountAssets 调上游 count_assets 取某类型的资产总量。
func (s *Server) ssCountAssets(ctx context.Context, cl *mcphttp.Client, ssType string) (int, error) {
	text, err := cl.Call(ctx, "count_assets", map[string]any{"asset_type": ssType})
	if err != nil {
		return 0, err
	}
	var env struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal([]byte(text), &env); err != nil {
		return 0, err
	}
	if env.Total < 0 {
		return 0, nil
	}
	return int(env.Total), nil
}

// ssReconcile 每日对账：逐类型拉上游总量快照，对比上轮快照与期间增量入库量；
// 判定失明即清该类型水位（下轮全量重刷）并告警。顺序刻意为 Save → Reset：
// SaveSyncState 的水位只前进语义会把刚清掉的水位写回去，必须后清。
func (s *Server) ssReconcile(ctx context.Context, m *db.MCPServer, cl *mcphttp.Client) {
	pg := s.m.pg
	if pg == nil {
		return
	}
	var alerts []string
	for _, at := range reconDefaultTypes {
		total, err := s.ssCountAssets(ctx, cl, reconTypeMap[at])
		if err != nil {
			log.Printf("[sync] 对账 %s count_assets 失败: %v", at, err)
			continue
		}
		st, serr := pg.SyncStateFor(ctx, m.ID, at)
		if serr != nil {
			continue
		}
		if reconcileNeedsReset(st.UpstreamTotal, total, st.IncTaken, syncReconcileGrowth) {
			if rerr := pg.ResetSyncWatermark(ctx, m.ID, at); rerr != nil {
				log.Printf("[sync] 对账 %s 水位重置失败: %v", at, rerr)
				continue
			}
			alerts = append(alerts, fmt.Sprintf("%s: 上游净增 %d 而增量入库仅 %d——疑似上游排序/时间语义变化，水位已重置（下轮全量重刷，幂等吸收）",
				at, total-st.UpstreamTotal, st.IncTaken))
		}
		if uerr := pg.UpdateSyncCounters(ctx, m.ID, at, total, 0); uerr != nil {
			log.Printf("[sync] 对账 %s 计数回写失败: %v", at, uerr)
		}
	}
	if len(alerts) > 0 {
		s.notifySync(ctx, "资产同步对账告警", "增量疑似失明，涉事类型水位已重置，将在下轮定时同步自动全量重刷", strings.Join(alerts, "; "))
	}
	_ = pg.SetSetting(settingSSLastReconcile, time.Now().Format(time.RFC3339))
}

// runSyncTicker 定时增量同步。周期读 config.json 的 sync.4zrecon_interval_minutes
// （默认 30min，负数关闭）。刻意不并入 scheduler.go 的 triggers——那是 agent 会话
// 触发器，与后台批同步语义不合（施工单变更1.3）。
func (s *Server) runSyncTicker(ctx context.Context) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	d, ok := config.Load().SyncInterval()
	if !ok {
		log.Printf("[sync] 定时同步已关闭（config sync.4zrecon_interval_minutes < 0）")
		return
	}
	log.Printf("[sync] 定时增量同步已启动，周期 %s", d)
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.syncTick(ctx)
		}
	}
}

// notifySyncTruncated 把截断告警直发给启用中的渠道（复用渠道测试的直发路径，不走
// finding 事件表——同步告警没有 finding 语义）。发送失败只记日志，不影响同步本身。
func (s *Server) notifySyncTruncated(ctx context.Context, detail string) {
	s.notifySync(ctx, "资产同步截断告警", "已达单轮保护上限，剩余数据下轮继续；长期截断请提高上限或缩短同步周期", detail)
}

// notifySync 同步侧告警直发启用中的通知渠道（复用渠道直发路径，不走 finding
// 事件表——同步告警没有 finding 语义）。发送失败只记日志，不影响同步本身。
func (s *Server) notifySync(ctx context.Context, name, note, detail string) {
	pg := s.m.pg
	if pg == nil {
		return
	}
	if !pg.GetBool(settingNotifyEnabled, true) {
		return
	}
	channels, err := pg.ListNotificationChannels(ctx)
	if err != nil {
		log.Printf("[sync] 告警读取渠道失败: %v", err)
		return
	}
	baseURL := s.notifierBaseURL(pg)
	msg := notify.Message{
		Items: []notify.Item{{
			Name:      name,
			VulnClass: "4zrecon 同步",
			Severity:  "low",
			Summary:   detail + "（" + note + "）",
			Assets:    []string{reconMCPName},
			DetailURL: baseURL,
		}},
		HomeURL: baseURL,
	}
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		channel, ok := notify.Get(ch.Kind)
		if !ok {
			continue
		}
		var cfg map[string]any
		if len(ch.Config) > 0 {
			_ = json.Unmarshal(ch.Config, &cfg)
		}
		if _, serr := channel.Send(ctx, cfg, msg); serr != nil {
			log.Printf("[sync] 截断告警发送失败(渠道 %s): %v", ch.Kind, serr)
		}
	}
}

// reconProjectMeta fetches a project's display name and its target root domains
// (get_project.target is a newline-separated list) for company + scope creation.
func (s *Server) reconProjectMeta(ctx context.Context, cl *mcphttp.Client, projectID string) (name string, roots []string, err error) {
	text, err := cl.Call(ctx, "get_project", map[string]any{"id": projectID})
	if err != nil {
		return "", nil, err
	}
	var p struct {
		Name   string `json:"name"`
		Target string `json:"target"`
	}
	if err := json.Unmarshal([]byte(text), &p); err != nil {
		return "", nil, err
	}
	for _, line := range strings.Split(p.Target, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			roots = append(roots, t)
		}
	}
	return p.Name, roots, nil
}

// reconPageAll pages through list_assets for one asset_type + filter until a short/empty
// page or the protection cap. The {list:[...]} envelope has no total, so we stop when
// a page returns fewer than pageSize items.
func (s *Server) reconPageAll(ctx context.Context, cl *mcphttp.Client, ssType string, filter map[string]any, pageSize int) (items []json.RawMessage, truncated bool, err error) {
	for page := 1; ; page++ {
		args := map[string]any{"asset_type": ssType, "pageIndex": page, "pageSize": pageSize}
		if len(filter) > 0 {
			args["filter"] = filter
		}
		text, cerr := cl.Call(ctx, "list_assets", args)
		if cerr != nil {
			return items, truncated, cerr
		}
		var env struct {
			List []json.RawMessage `json:"list"`
		}
		if uerr := json.Unmarshal([]byte(text), &env); uerr != nil {
			return items, truncated, uerr
		}
		if len(env.List) == 0 {
			break
		}
		items = append(items, env.List...)
		if len(items) >= syncMaxPerType {
			items = items[:syncMaxPerType]
			truncated = true
			break
		}
		if len(env.List) < pageSize {
			break
		}
	}
	return items, truncated, nil
}

// reconNormalizeMode 归一同步模式：显式传值（大小写不敏感）优先；缺省时带 targets 的
// 旧调用走目标全量（兼容曾经唯一的语义），空 targets 缺省走全局增量（默认 inc）。
// 显式但非法的值返回 ""，由 handler 400。
func reconNormalizeMode(mode string, targets int) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "full":
		return "full"
	case "inc":
		return "inc"
	case "":
		if targets > 0 {
			return "full"
		}
		return "inc"
	}
	return ""
}

// reconItemTime 从一条资产 JSON 里取上游的 time 字段（原生字符串，可能缺失/为空）。
func reconItemTime(raw json.RawMessage) string {
	var it struct {
		Time string `json:"time"`
	}
	_ = json.Unmarshal(raw, &it)
	return strings.TrimSpace(it.Time)
}

// reconRollbackWatermark 把水位回拨 syncWatermarkLag（防边界丢数：源与消费端同在
// 节点时区）。解析失败原样返回——宁可下轮多拉（幂等吸收），不推进一个坏水位。
func reconRollbackWatermark(wm string) string {
	t, err := time.ParseInLocation(syncTimeLayout, wm, time.Local)
	if err != nil {
		return wm
	}
	return t.Add(-syncWatermarkLag).Format(syncTimeLayout)
}

// reconPageSince 在 reconPageAll 的分页骨架上加水位客户端截断。上游列表服务端按 time
// 倒序返回（4zrecon repo 层 SetSort(time,-1)；已核实其 MCP 的 sort 参数对资产类型
// 无效，故不传），该排序是实现细节而非 API 承诺——遇 time <= watermark 即止页，
// 另以每日 count_assets 计数对账兜底。返回本轮见到的最大 time（调用方回拨后落库）。
// time 缺失的条目按新数据处理（fail-open）。
func (s *Server) reconPageSince(ctx context.Context, cl *mcphttp.Client, ssType string, filter map[string]any, pageSize int, watermark string) (items []json.RawMessage, maxTime string, truncated bool, err error) {
	fetch := func(page int) ([]json.RawMessage, error) {
		args := map[string]any{"asset_type": ssType, "pageIndex": page, "pageSize": pageSize}
		if len(filter) > 0 {
			args["filter"] = filter
		}
		text, cerr := cl.Call(ctx, "list_assets", args)
		if cerr != nil {
			return nil, cerr
		}
		var env struct {
			List []json.RawMessage `json:"list"`
		}
		if uerr := json.Unmarshal([]byte(text), &env); uerr != nil {
			return nil, uerr
		}
		return env.List, nil
	}
	return reconPageSincePages(fetch, pageSize, watermark)
}

// reconPageSincePages 是 reconPageSince 的纯分页核（单测钉住倒序截断行为）：fetch 返回
// 第 page 页（服务端 time 倒序），遇 time <= watermark 整页止；5000 单轮上限截断。
func reconPageSincePages(fetch func(page int) ([]json.RawMessage, error), pageSize int, watermark string) (items []json.RawMessage, maxTime string, truncated bool, err error) {
	for page := 1; ; page++ {
		list, ferr := fetch(page)
		if ferr != nil {
			return items, maxTime, truncated, ferr
		}
		if len(list) == 0 {
			break
		}
		reachedWM := false
		for _, raw := range list {
			t := reconItemTime(raw)
			if t > maxTime {
				maxTime = t
			}
			if watermark != "" && t != "" && t <= watermark {
				reachedWM = true // 倒序保证其后更旧，整页止
				continue
			}
			items = append(items, raw)
		}
		if reachedWM {
			break
		}
		if len(items) >= syncMaxPerType {
			items = items[:syncMaxPerType]
			truncated = true
			break
		}
		if len(list) < pageSize {
			break
		}
	}
	return items, maxTime, truncated, nil
}

// reconIngest maps one 4zrecon asset JSON to the ARTEX asset store and upserts it.
// Returns a non-empty error string on failure. synced is incremented per kind.
func (s *Server) reconIngest(as *db.AssetStore, assetType string, raw json.RawMessage, synced map[string]int) string {
	switch assetType {
	case "subdomain":
		var it struct {
			Host  string   `json:"host"`
			Type  string   `json:"type"`
			Value []string `json:"value"`
			IP    []string `json:"ip"`
		}
		if err := json.Unmarshal(raw, &it); err != nil {
			return "subdomain 解析失败: " + err.Error()
		}
		if it.Host == "" {
			return ""
		}
		if _, err := as.UpsertSubdomain(db.UpsertSubdomainReq{Domain: it.Host, RecordType: it.Type, RecordValue: it.Value}); err != nil {
			return "subdomain " + it.Host + ": " + err.Error()
		}
		synced["subdomain"]++
		for _, ip := range it.IP {
			if ip != "" {
				if _, err := as.UpsertIP(db.UpsertIPReq{IP: ip, BoundDomains: []string{it.Host}}); err == nil {
					synced["ip"]++
				}
			}
		}
	case "root_domain":
		// 4zrecon RootDomain：{domain, icp, company, time}——量小，默认纳入同步
		// 自然补全根域清单（施工单变更2）。
		var it struct {
			Domain string `json:"domain"`
			ICP    string `json:"icp"`
		}
		if err := json.Unmarshal(raw, &it); err != nil {
			return "root_domain 解析失败: " + err.Error()
		}
		if it.Domain == "" {
			return ""
		}
		if _, err := as.UpsertRootDomain(db.UpsertRootDomainReq{Domain: it.Domain, ICP: it.ICP}); err != nil {
			return "root_domain " + it.Domain + ": " + err.Error()
		}
		synced["root_domain"]++
	case "app":
		var it struct {
			Name        string `json:"name"`
			Category    string `json:"category"`
			Description string `json:"description"`
			ICP         string `json:"icp"`
		}
		if err := json.Unmarshal(raw, &it); err != nil {
			return "app 解析失败: " + err.Error()
		}
		if it.Name == "" {
			return ""
		}
		if _, err := as.UpsertApp(db.UpsertAppReq{Name: it.Name, Category: it.Category, Description: it.Description, ICP: it.ICP}); err != nil {
			return "app " + it.Name + ": " + err.Error()
		}
		synced["app"]++
	case "service":
		var it struct {
			Domain   string   `json:"domain"`
			IP       string   `json:"ip"`
			Port     string   `json:"port"`
			Service  string   `json:"service"`
			URL      string   `json:"url"`
			Title    string   `json:"title"`
			Status   *int     `json:"status"`
			Products []string `json:"products"`
			Icon     string   `json:"icon"`
		}
		if err := json.Unmarshal(raw, &it); err != nil {
			return "service 解析失败: " + err.Error()
		}
		if it.Service == "http" || it.URL != "" {
			if it.URL == "" {
				return ""
			}
			if _, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{
				URL: it.URL, Technologies: it.Products, StatusCode: it.Status,
				PageTitle: it.Title, FaviconMMH3: it.Icon, IP: it.IP,
			}); err != nil {
				return "service " + it.URL + ": " + err.Error()
			}
		} else {
			port, _ := strconv.Atoi(it.Port)
			if _, err := as.UpsertOtherService(db.UpsertOtherServiceReq{
				Domain: it.Domain, IP: it.IP, Port: port, ServiceName: it.Service,
			}); err != nil {
				return "service " + it.IP + ":" + it.Port + ": " + err.Error()
			}
		}
		synced["service"]++
	}
	return ""
}

// queryInt reads an int query param with a default fallback.
func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
