// spacemap_api.go 五引擎空间测绘:HTTP 设置面(key 掩码回显)+ agent 工具面
// (space_search / space_search_batch / info_collect_capabilities)+ 资产入库。
// 工具定义移植自 4zreco internal/app 的 info_collect_tools.go / space_batch_tools.go
// (参数 JSON Schema 与描述文本原样复用,RBAC 权限点丢弃——单管理员架构);
// 入库走本平台 AssetStore + 授权状态机:范围内自动 approved(范围认领),范围外
// pending 待人工审批,不静默丢弃。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/db"
	"github.com/c1ayooo/4zrec/spacemap"
	actool "github.com/c1ayooo/4zrec/tools"
)

// spacemapClient 惰性构造的引擎客户端(key resolver 每次 resolving,改 key 即生效)。
func (s *Server) spacemapClient() *spacemap.Client {
	c := spacemap.NewClient()
	c.KeyResolver = func(provider string) string {
		return spacemap.ResolveKey(s.m.pg, provider)
	}
	c.BaseURLResolver = func(provider string) string {
		return spacemap.ResolveBaseURL(s.m.pg, provider)
	}
	return c
}

// ---------- HTTP: /api/spacemap/engines ----------

func (s *Server) spacemapEnginesGet(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	type engineInfo struct {
		Provider     string `json:"provider"`
		Display      string `json:"display"`
		Configured   bool   `json:"configured"`
		KeyMasked    string `json:"key_masked"`
		FromEnv      bool   `json:"from_env"`
		BaseURL      string `json:"base_url"`
		DefaultQuery string `json:"default_query"`
	}
	out := make([]engineInfo, 0, len(spacemap.Providers))
	for _, p := range spacemap.Providers {
		key := spacemap.ResolveKey(pg, p)
		out = append(out, engineInfo{
			Provider:     p,
			Display:      spacemap.ProviderDisplayName(p),
			Configured:   key != "",
			KeyMasked:    spacemap.Mask(key),
			FromEnv:      spacemap.KeyFromEnv(p),
			BaseURL:      spacemap.ResolveBaseURL(pg, p),
			DefaultQuery: spacemap.DomainQueryTemplate(p),
		})
	}
	writeJSON(w, 200, map[string]any{"engines": out})
}

// spacemapEnginesSet 保存引擎配置。api_key 留空=保持不变;显式传 "clear"=清除;
// base_url 留空=用内置默认。
func (s *Server) spacemapEnginesSet(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in struct {
		Provider string `json:"provider"`
		APIKey   string `json:"api_key"`
		BaseURL  string `json:"base_url"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !spacemap.ValidProvider(in.Provider) {
		writeErr(w, 400, "provider 不支持")
		return
	}
	if strings.TrimSpace(in.APIKey) != "" {
		if strings.TrimSpace(in.APIKey) == "clear" {
			if err := pg.SetSetting(spacemap.SettingsKey(in.Provider), ""); err != nil {
				writeErr(w, 500, "db: "+err.Error())
				return
			}
		} else if err := pg.SetSetting(spacemap.SettingsKey(in.Provider), strings.TrimSpace(in.APIKey)); err != nil {
			writeErr(w, 500, "db: "+err.Error())
			return
		}
	}
	if err := pg.SetSetting(spacemap.BaseURLSettingsKey(in.Provider), strings.TrimSpace(in.BaseURL)); err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	s.spacemapEnginesGet(w, r)
}

// ---------- 资产入库(范围语义) ----------

// spacemapImport 把引擎结果导入资产库并落授权状态:
//   - 域名 → subdomain 资产;IP → ip 资产;host+port → service 资产(http 形态带 title);
//   - projectID>0 时逐资产 StampDiscoveredAsset:命中项目范围 → approved,
//     范围外 → pending 待人工审批(不静默丢,不抢授权);
//   - 幂等:全部走 AssetStore 的 upsert 通道。
func (s *Server) spacemapImport(ctx0 context.Context, projectID int64, taskID int64, results []*spacemap.Result) (domains, ips, services int) {
	as := s.m.Assets()
	for _, r := range results {
		var ids []int64
		if d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), ".")); d != "" && strings.Contains(d, ".") {
			if id, err := as.UpsertSubdomain(db.UpsertSubdomainReq{Domain: d, TaskID: taskID}); err == nil {
				ids = append(ids, id)
				domains++
			}
		}
		if r.IP != "" {
			if id, err := as.UpsertIP(db.UpsertIPReq{IP: r.IP, TaskID: taskID}); err == nil {
				ids = append(ids, id)
				ips++
			}
		}
		if h := r.Host; h != "" && r.Port > 0 {
			if r.Protocol == "http" || r.Protocol == "https" || (r.Protocol == "" && r.Title != "") {
				scheme := r.Protocol
				if scheme == "" {
					scheme = "http"
				}
				if id, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{
					URL: fmt.Sprintf("%s://%s:%d", scheme, h, r.Port), PageTitle: r.Title, TaskID: taskID,
				}); err == nil {
					ids = append(ids, id)
					services++
				}
			}
		}
		if projectID > 0 {
			for _, id := range ids {
				_, _ = as.StampDiscoveredAsset(id, projectID)
			}
		}
		// 来源标注:空间测绘结果页按引擎筛选的数据依据。
		if r.Source != "" {
			for _, id := range ids {
				s.m.pg.StampAssetSource(ctx0, id, r.Source)
			}
		}
	}
	if projectID > 0 {
		_, _ = s.m.pg.Projects().RecomputeProjectAttribution()
	}
	return
}

// ---------- agent 工具面 ----------

// spacemapTools 三个空间测绘工具。默认绑定 auto/worker(工具表可改绑)。
func (s *Server) spacemapTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolInfoCollectCapabilities(),
		s.toolSpaceSearch(),
		s.toolSpaceSearchBatch(),
	}
}

func (s *Server) toolInfoCollectCapabilities() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "info_collect_capabilities",
		Description: "查询当前信息收集能力面：哪些空间测绘引擎(fofa/zoomeye/quake/shodan/hunter)已配置 key 可用、自定义端点与域名查询语法。发起新的测绘查询前先调它确认能力，避免对着未配置的引擎空跑。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			c := s.spacemapClient()
			var b strings.Builder
			b.WriteString("空间测绘引擎:\n")
			anyConfigured := false
			for _, p := range spacemap.Providers {
				status := "未配置 key"
				if c.SourceConfigured(p) {
					status = "可用"
					anyConfigured = true
				}
				if spacemap.KeyFromEnv(p) {
					status += "(key 来自环境变量)"
				}
				fmt.Fprintf(&b, "- %s: %s | 域名查询: %s\n", spacemap.ProviderDisplayName(p), status, spacemap.DomainQueryTemplate(p))
			}
			if !anyConfigured {
				b.WriteString("\n所有引擎均未配置 key:请在 系统设置 → 空间测绘 页面配置,或设置环境变量(FOFA_API_KEY 等)。")
			}
			return actool.Text(b.String()), nil
		},
	})
}

func (s *Server) toolSpaceSearch() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "space_search",
		Description: "空间测绘引擎查询(fofa/zoomeye/quake/shodan/hunter):按引擎各自的查询语法检索互联网资产测绘数据," +
			"返回归一化资产候选(host/ip/port/domain/title/protocol)。auto_import=true 时把结果导入资产库" +
			"(命中项目授权范围的自动 approved,范围外进待审批队列)。查询语法先调 info_collect_capabilities 查看。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"engine":      map[string]any{"type": "string", "enum": spacemap.Providers, "description": "引擎(缺省 fofa)"},
				"query":       map[string]any{"type": "string", "description": "引擎原生查询语法,如 domain=\"example.com\""},
				"size":        map[string]any{"type": "integer", "description": "返回条数(默认 100)"},
				"page":        map[string]any{"type": "integer", "description": "页码(默认 1)"},
				"project_id":  map[string]any{"type": "integer", "description": "导入目标项目(auto_import 时)"},
				"auto_import": map[string]any{"type": "boolean", "description": "结果导入资产库(默认 false 仅返回)"},
			},
			"required": []string{"query"},
		},
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Engine     string `json:"engine"`
				Query      string `json:"query"`
				Size       int    `json:"size"`
				Page       int    `json:"page"`
				ProjectID  int64  `json:"project_id"`
				AutoImport bool   `json:"auto_import"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			results, raw, total, err := s.spacemapClient().SearchEngineAssets(ctx, in.Engine, in.Query, in.Size, in.Page)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "引擎 %s 查询成功:命中 %d 条,返回 %d 条候选\n",
				spacemap.ProviderDisplayName(in.Engine), total, len(results))
			if in.AutoImport {
				// 显式参数优先;缺省取会话/任务挂载的项目(信息收集自动归属)。
				projectID := s.roeProjectID(ctx, in.ProjectID)
				d, i, sv := s.spacemapImport(ctx, projectID, 0, results)
				fmt.Fprintf(&b, "已导入资产库: 域名 %d / IP %d / 服务 %d(范围内自动授权,范围外进待审批)\n", d, i, sv)
				if projectID > 0 {
					fmt.Fprintf(&b, "目标项目 %d\n", projectID)
				} else {
					b.WriteString("未挂项目:结果仅入库,建议在对话页挂载项目后采集以自动归属。\n")
				}
			}
			// 原始行样本(前 50 条,字段裁剪)供 agent 判断数据质量
			sample := raw
			if len(sample) > 50 {
				sample = sample[:50]
			}
			for _, row := range sample {
				fmt.Fprintf(&b, "- %s\n", spacemap.SummarizeRow(row))
			}
			return actool.Text(b.String()), nil
		},
	})
}

func (s *Server) toolSpaceSearchBatch() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "space_search_batch",
		Description: "批量空间测绘:给定目标域名列表,遍历所有已配置 key 的引擎,用各引擎的域名查询语法检索并跨引擎去重," +
			"统一导入资产库(project_id 必填,范围内自动 approved/范围外待审批)。适合开局资产清扫。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"targets":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "目标域名列表(通常是项目授权根域)"},
				"engines":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "限定引擎(缺省=全部已配置的)"},
				"project_id": map[string]any{"type": "integer", "description": "导入目标项目"},
				"size_per":   map[string]any{"type": "integer", "description": "每引擎每目标返回条数(默认 100)"},
			},
			"required": []string{"targets", "project_id"},
		},
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Targets   []string `json:"targets"`
				Engines   []string `json:"engines"`
				ProjectID int64    `json:"project_id"`
				SizePer   int      `json:"size_per"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if len(in.Targets) == 0 {
				return actool.Errorf("targets 必填"), nil
			}
			// project_id 缺省取会话/任务挂载的项目(信息收集自动归属)。
			in.ProjectID = s.roeProjectID(ctx, in.ProjectID)
			if in.ProjectID <= 0 {
				return actool.Errorf("project_id 必填(可在对话页挂载项目后省略)"), nil
			}
			c := s.spacemapClient()
			engines := in.Engines
			if len(engines) == 0 {
				engines = spacemap.Providers
			}
			var (
				b          strings.Builder
				seen       = map[string]bool{}
				totDomains int
			)
			for _, engine := range engines {
				if !spacemap.ValidProvider(engine) {
					fmt.Fprintf(&b, "- %s: 不支持的引擎,跳过\n", engine)
					continue
				}
				if !c.SourceConfigured(engine) {
					fmt.Fprintf(&b, "- %s: 未配置 key,跳过\n", spacemap.ProviderDisplayName(engine))
					continue
				}
				for _, target := range in.Targets {
					q := spacemap.DomainQuery(engine, target)
					results, _, total, err := c.SearchEngineAssets(ctx, engine, q, in.SizePer, 1)
					if err != nil {
						fmt.Fprintf(&b, "- %s %s: %v\n", spacemap.ProviderDisplayName(engine), target, err)
						continue
					}
					d, i, sv := s.spacemapImport(ctx, in.ProjectID, 0, results)
					totDomains += d
					fmt.Fprintf(&b, "- %s %s: 命中 %d,导入 域名%d/IP%d/服务%d\n",
						spacemap.ProviderDisplayName(engine), target, total, d, i, sv)
					for _, r := range results {
						key := r.Domain + "|" + r.IP
						if !seen[key] {
							seen[key] = true
						}
					}
				}
			}
			fmt.Fprintf(&b, "跨引擎去重后唯一目标 %d 个,共导入域名资产 %d 条", len(seen), totDomains)
			return actool.Text(b.String()), nil
		},
	})
}

// seedSpacemapTools 工具表播种(首插入生效,UI 可改绑/停用)。
func (s *Server) seedSpacemapTools() {
	agents, _ := json.Marshal([]string{"auto", "worker"})
	allCollectTools := slices.Concat(
		s.spacemapTools(), s.spacemapExpandTools(), s.reconTools(),
		s.atomicTools(), s.entTools(), s.credTools(),
		s.webreconTools(), s.coverageTools(), s.oobTools(), s.probeTools(),
	)
	for _, t := range allCollectTools {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, agents)
	}
}

// ---------- HTTP: /api/spacemap/intelkeys(被动源与情报凭据:VT/GitHub) ----------

type intelKeyDef struct {
	Setting string // settings 键
	Label   string
	Env     string // 环境变量名(优先)
}

var intelKeys = []intelKeyDef{
	{Setting: "virustotal.key", Label: "VirusTotal", Env: "VT_API_KEY"},
	{Setting: "githubsearch.token", Label: "GitHub", Env: "GITHUB_TOKEN"},
}

func (s *Server) intelKeysGet(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	type row struct {
		Key        string `json:"key"`
		Label      string `json:"label"`
		Env        string `json:"env"`
		FromEnv    bool   `json:"from_env"`
		Configured bool   `json:"configured"`
		Masked     string `json:"masked"`
	}
	out := make([]row, 0, len(intelKeys))
	for _, k := range intelKeys {
		val := ""
		if v := strings.TrimSpace(os.Getenv(k.Env)); v != "" {
			val = v
		} else if v, ok, err := pg.GetSetting(k.Setting); err == nil && ok {
			val = strings.TrimSpace(v)
		}
		out = append(out, row{
			Key: k.Setting, Label: k.Label, Env: k.Env,
			FromEnv:    val != "" && strings.TrimSpace(os.Getenv(k.Env)) != "",
			Configured: val != "", Masked: spacemap.Mask(val),
		})
	}
	writeJSON(w, 200, map[string]any{"keys": out})
}

// intelKeysSet 保存(留空不变,"clear"清除)。
func (s *Server) intelKeysSet(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	valid := false
	for _, k := range intelKeys {
		if k.Setting == in.Key {
			valid = true
		}
	}
	if !valid {
		writeErr(w, 400, "key 不支持")
		return
	}
	if v := strings.TrimSpace(in.Value); v != "" {
		if v == "clear" {
			v = ""
		}
		if err := pg.SetSetting(in.Key, v); err != nil {
			writeErr(w, 500, "db: "+err.Error())
			return
		}
	}
	s.intelKeysGet(w, r)
}

// ---------- HTTP: /api/spacemap/results(结果页数据) ----------

// spacemapResultsList 按引擎筛选的测绘结果分页。
func (s *Server) spacemapResultsList(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	engine := strings.TrimSpace(q.Get("engine"))
	typ := strings.TrimSpace(q.Get("type"))
	page := strconvAtoiDefault(q.Get("page"), 1)
	size := strconvAtoiDefault(q.Get("size"), 50)
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > 200 {
		size = 50
	}
	pid, _ := strconv.ParseInt(q.Get("project_id"), 10, 64)
	rows, total, err := pg.SpacemapResultsPage(r.Context(), engine, typ, pid, size, (page-1)*size)
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	// 引擎清单(归一化名→展示名,前端筛选 chips 用)。
	engines := make([]map[string]any, 0, len(spacemap.Providers))
	for _, p := range spacemap.Providers {
		engines = append(engines, map[string]any{"provider": p, "display": spacemap.ProviderDisplayName(p)})
	}
	writeJSON(w, 200, map[string]any{"results": rows, "total": total, "page": page, "size": size, "engines": engines})
}

func strconvAtoiDefault(s string, def int) int {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 {
		return def
	}
	return n
}

// ---------- HTTP: POST /api/spacemap/search(手工搜索台) ----------

// spacemapSearch 手动执行一次引擎查询并返回归一化结果(不落资产库);
// auto_import=true 时连同入库(项目缺省取会话挂载)。前端搜索台与 agent 的
// space_search 同一后端通道。
func (s *Server) spacemapSearch(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in struct {
		Engine     string `json:"engine"`
		Query      string `json:"query"`
		Size       int    `json:"size"`
		ProjectID  int64  `json:"project_id"`
		AutoImport bool   `json:"auto_import"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	results, _, total, err := s.spacemapClient().SearchEngineAssets(r.Context(), in.Engine, in.Query, in.Size, 1)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	type searchRow struct {
		Host     string `json:"host"`
		Domain   string `json:"domain"`
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Title    string `json:"title"`
		Protocol string `json:"protocol"`
		Server   string `json:"server"`
		Country  string `json:"country"`
		City     string `json:"city"`
	}
	out := make([]searchRow, 0, len(results))
	for _, r2 := range results {
		out = append(out, searchRow{
			Host: r2.Host, Domain: r2.Domain, IP: r2.IP, Port: r2.Port,
			Title: r2.Title, Protocol: r2.Protocol, Server: r2.Server,
			Country: r2.Country, City: r2.City,
		})
	}
	resp := map[string]any{
		"engine": spacemap.ProviderDisplayName(in.Engine),
		"query":  in.Query,
		"total":  total,
		"count":  len(out),
		"rows":   out,
	}
	if in.AutoImport {
		projectID := s.roeProjectID(r.Context(), in.ProjectID)
		d, i, sv := s.spacemapImport(r.Context(), projectID, 0, results)
		resp["imported"] = map[string]any{"domains": d, "ips": i, "services": sv, "project_id": projectID}
	}
	writeJSON(w, 200, resp)
}
