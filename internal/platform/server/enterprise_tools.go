// enterprise_tools.go 企业关系采集:enterprise(BFS 编排+四 HTTP 适配器)与
// datasource(AES 加密会话 vault)两包直接搬自 4zreco(浏览器型小蓝本按规格剔除)。
// 会话凭据只进 vault(前端永不回显 Cookie 明文);未配置会话时仅 ICP 反查路径
// 可用(经既有 icp_expand)。工具四个:search/collect/job_status/assets_import。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"

	"github.com/c1ayooo/4zrec/internal/capability/recon/datasource"
	"github.com/c1ayooo/4zrec/internal/platform/enterprise"
)

// enterpriseStack 惰性构造:vault(key 落 dataDir/datasource.key,0600) +
// enterprise store + collector。
type entStack struct {
	vault     *datasource.Store
	store     *enterprise.Store
	collector *enterprise.Collector
}

var (
	entOnce  sync.Once
	entStk   *entStack
	entErr   error
	entProxy func() string // 可注入代理地址(测试);nil=空
)

func (s *Server) entStores() (*entStack, error) {
	if s.m == nil || s.m.pg == nil {
		return nil, fmt.Errorf("服务未初始化(无数据库上下文)")
	}
	entOnce.Do(func() {
		keyPath := filepath.Join(s.m.Dir(), "datasource.key")
		key, err := datasource.LoadOrCreateKey(keyPath, true)
		if err != nil {
			entErr = fmt.Errorf("会话密钥初始化失败: %w", err)
			return
		}
		vault, err := datasource.NewStore(s.m.pg.DB, key)
		if err != nil {
			entErr = fmt.Errorf("会话库初始化失败: %w", err)
			return
		}
		store := enterprise.NewStore(s.m.pg.DB)
		entStk = &entStack{vault: vault, store: store, collector: enterprise.NewCollector(store, log.Default())}
	})
	return entStk, entErr
}

// entSessionCfg 取某 provider 的平台级会话配置(无 → nil)。
func (s *Server) entSessionCfg(provider string) (map[string]string, string) {
	stk, err := s.entStores()
	if err != nil {
		return nil, ""
	}
	metas, err := stk.vault.List("", "", true)
	if err != nil {
		return nil, ""
	}
	for _, mt := range metas {
		if strings.EqualFold(mt.Provider, provider) && mt.Configured {
			if sess, err := stk.vault.Get(mt.ID); err == nil {
				return sess.Config, mt.ID
			}
		}
	}
	return nil, ""
}

// entProvider 构造 provider;未配置会话返回 IsSessionMissing 语义错误。
func (s *Server) entProvider(provider string) (enterprise.Provider, error) {
	cfg, _ := s.entSessionCfg(provider)
	proxyURL := ""
	if entProxy != nil {
		proxyURL = entProxy()
	}
	if cfg == nil {
		// 未配置会话:明确提示 ICP 路径替代,不让调用方误以为坏掉。
		return nil, enterprise.SessionMissing(fmt.Sprintf(
			"%s 会话未配置(系统设置 → 企业数据源);无会话时请用 icp_expand 的 ICP 反查路径(零会话成本)", provider))
	}
	return enterprise.NewProvider(provider, cfg, proxyURL)
}

// ---------- HTTP: 会话配置面(凭据只进 vault,回显仅元数据) ----------

func (s *Server) entProvidersGet(w http.ResponseWriter, r *http.Request) {
	if _, err := s.entStores(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	type row struct {
		Name       string `json:"name"`
		Label      string `json:"label"`
		Auth       string `json:"auth"`
		Available  bool   `json:"available"`
		Hint       string `json:"hint"`
		Configured bool   `json:"configured"`
	}
	out := make([]row, 0, len(enterprise.Registry))
	for _, p := range enterprise.Registry {
		_, sid := s.entSessionCfg(p.Name)
		out = append(out, row{p.Name, p.Label, p.Auth, p.Available, p.Hint, sid != ""})
	}
	writeJSON(w, 200, map[string]any{"providers": out})
}

func (s *Server) entSessionsList(w http.ResponseWriter, r *http.Request) {
	stk, err := s.entStores()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	metas, err := stk.vault.List("", "", true)
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"sessions": metas})
}

// entSessionsSet 保存(或清除)某 provider 的平台级会话。config 各字段留空=清除。
func (s *Server) entSessionsSet(w http.ResponseWriter, r *http.Request) {
	stk, err := s.entStores()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var in struct {
		Provider string            `json:"provider"`
		Config   map[string]string `json:"config"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !datasource.IsSupportedProvider(in.Provider) {
		writeErr(w, 400, "provider 不支持")
		return
	}
	// 同 provider 只保留一条平台级会话:先清旧。
	old, _ := stk.vault.List("", "", true)
	for _, mt := range old {
		if strings.EqualFold(mt.Provider, in.Provider) {
			_ = stk.vault.Delete(mt.ID, "", true)
		}
	}
	if len(in.Config) == 0 {
		writeJSON(w, 200, map[string]any{"ok": true, "cleared": true})
		return
	}
	if _, err := stk.vault.Upsert(datasource.UpsertRequest{
		Owner: "platform", Provider: in.Provider, Config: in.Config,
	}); err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------- agent 工具面(四工具) ----------

// toolEntSearch 关键词搜企业,返回 ext_id 列表(collect 的入参)。
func (s *Server) toolEntSearch() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "enterprise_company_search",
		Description: "企业关键词搜索(需企业数据源会话:爱企查/天眼查/快查/风鸟):返回企业列表与稳定 ext_id," +
			"ext_id 用于 enterprise_collect 发起关联采集。未配置会话时用 icp_expand 的 ICP 反查路径替代(零会话成本)。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider": map[string]any{"type": "string", "description": "数据源(aqc/tyc/kuaicha/fengniao)"},
				"keyword":  map[string]any{"type": "string", "description": "企业名关键词"},
				"limit":    map[string]any{"type": "integer", "description": "返回上限(默认 10)"},
			},
			"required": []string{"provider", "keyword"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Provider string `json:"provider"`
				Keyword  string `json:"keyword"`
				Limit    int    `json:"limit"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			p, err := s.entProvider(in.Provider)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if in.Limit <= 0 {
				in.Limit = 10
			}
			refs, err := p.Search(ctx, strings.TrimSpace(in.Keyword), in.Limit)
			if err != nil {
				return actool.Errorf("搜索失败: " + err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "命中 %d 家:\n", len(refs))
			for _, r := range refs {
				fmt.Fprintf(&b, "- %s (ext_id=%s)\n", r.Name, r.ExtID)
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolEntCollect BFS 关联采集(异步):分支机构+对外投资逐层展开,域名入候选池。
func (s *Server) toolEntCollect() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "enterprise_collect",
		Description: "企业关联采集(异步 BFS):从根企业逐层展开分支机构与对外投资(深度≤3、节点上限),采集关联域名/备案入候选池。" +
			"立即返回 job id,用 enterprise_job_status 查进度;候选域名经 enterprise_assets_import 导入或 icp_expand 授权。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider":   map[string]any{"type": "string", "description": "数据源"},
				"ext_id":     map[string]any{"type": "string", "description": "根企业 ext_id(enterprise_company_search 的返回)"},
				"depth":      map[string]any{"type": "integer", "description": "展开深度(默认 2,上限 3)"},
				"max_nodes":  map[string]any{"type": "integer", "description": "节点上限(默认 20)"},
				"project_id": map[string]any{"type": "integer", "description": "归属项目"},
			},
			"required": []string{"provider", "ext_id"},
		},
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Provider  string `json:"provider"`
				ExtID     string `json:"ext_id"`
				Depth     int    `json:"depth"`
				MaxNodes  int    `json:"max_nodes"`
				ProjectID int64  `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			p, err := s.entProvider(in.Provider)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			stk, err := s.entStores()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			job, err := stk.collector.Start(ctx, p, enterprise.Job{
				ProjectID: fmt.Sprintf("%d", in.ProjectID), Provider: in.Provider,
				Depth: in.Depth, MaxNodes: in.MaxNodes,
			}, enterprise.CompanyRef{ExtID: in.ExtID})
			if err != nil {
				return actool.Errorf("任务创建失败: " + err.Error()), nil
			}
			return actool.Text(fmt.Sprintf(
				"采集任务已起跑:job %s(深度≤%d/节点≤%d)。用 enterprise_job_status(job_id=%q) 查进度——异步执行,不要等待。",
				job.ID, job.Depth, job.MaxNodes, job.ID)), nil
		},
	})
}

// toolEntJobStatus 任务/候选查询。
func (s *Server) toolEntJobStatus() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "enterprise_job_status",
		Description: "查询企业采集任务与候选资产:job_id 查单任务进度(节点/实体/域名计数);不带 job_id 列最近任务;" +
			"candidates=true 列候选域名清单(待授权/已导入)。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"job_id":     map[string]any{"type": "string", "description": "任务 id(缺省=列表)"},
				"candidates": map[string]any{"type": "boolean", "description": "列候选域名(默认 false)"},
				"project_id": map[string]any{"type": "integer", "description": "项目过滤"},
			},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				JobID      string `json:"job_id"`
				Candidates bool   `json:"candidates"`
				ProjectID  int64  `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			stk, err := s.entStores()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			if in.JobID != "" {
				job, err := stk.store.GetJob(ctx, in.JobID)
				if err != nil {
					return actool.Errorf("任务不存在: " + in.JobID), nil
				}
				fmt.Fprintf(&b, "任务 %s [%s] 深度%d/节点%d(%d)/实体%d/域名%d/导入%d",
					job.ID, job.Status, job.Depth, job.MaxNodes, job.Nodes, job.Entities, job.Domains, job.Imported)
				if job.Error != "" {
					fmt.Fprintf(&b, " 错误: %s", job.Error)
				}
				b.WriteString("\n")
			} else {
				jobs, _ := stk.store.ListJobs(ctx, fmt.Sprintf("%d", in.ProjectID), "")
				fmt.Fprintf(&b, "最近 %d 个任务:\n", len(jobs))
				for _, j := range jobs {
					fmt.Fprintf(&b, "- %s [%s] 节点%d/实体%d/域名%d/导入%d\n", j.ID, j.Status, j.Nodes, j.Entities, j.Domains, j.Imported)
				}
			}
			if in.Candidates {
				rows, total, _ := stk.store.ListCandidateAssets(ctx, fmt.Sprintf("%d", in.ProjectID), "", "", 1, 50)
				fmt.Fprintf(&b, "候选域名(总数 %d,前 %d):\n", total, len(rows))
				for _, c := range rows {
					fmt.Fprintf(&b, "- %s [%s] %s\n", c.Value, c.Status, c.EntityName)
				}
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolEntImport 候选域名导入资产库(范围语义同其他收集工具)。
func (s *Server) toolEntImport() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "enterprise_assets_import",
		Description: "企业采集候选域名导入资产库:不带 domains 导入该项目全部待授权候选;带 domains 导入指定清单。" +
			"入库走范围语义(项目范围内自动 approved,范围外待审批);授权范围的正式扩充仍走 icp_expand。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"project_id": map[string]any{"type": "integer", "description": "目标项目(必填)"},
				"domains":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "指定域名(缺省=全部候选)"},
			},
			"required": []string{"project_id"},
		},
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				ProjectID int64    `json:"project_id"`
				Domains   []string `json:"domains"`
			}
			if err := json.Unmarshal(input, &in); err != nil || in.ProjectID <= 0 {
				return actool.Errorf("project_id 必填"), nil
			}
			stk, err := s.entStores()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			domains := in.Domains
			if len(domains) == 0 {
				rows, _, err := stk.store.ListCandidateAssets(ctx, fmt.Sprintf("%d", in.ProjectID), "candidate", "", 1, 200)
				if err != nil {
					return actool.Errorf("候选查询失败: " + err.Error()), nil
				}
				for _, c := range rows {
					domains = append(domains, c.Value)
				}
			}
			if len(domains) == 0 {
				return actool.Text("没有可导入的候选域名"), nil
			}
			imported := s.importSubdomains(ctx, in.ProjectID, domains)
			return actool.Text(fmt.Sprintf("已导入 %d/%d 个候选域名(范围内自动授权,范围外待审批)", imported, len(domains))), nil
		},
	})
}

// entTools 企业采集工具族。
func (s *Server) entTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolEntSearch(),
		s.toolEntCollect(),
		s.toolEntJobStatus(),
		s.toolEntImport(),
	}
}

// ---------- HTTP: 企业采集数据页(任务/候选/导入) ----------

func (s *Server) entJobsList(w http.ResponseWriter, r *http.Request) {
	stk, err := s.entStores()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// project_id 查参(项目为主轴的筛选);缺省=最近全部。
	pid := strings.TrimSpace(r.URL.Query().Get("project_id"))
	var jobs []enterprise.Job
	if pid != "" {
		jobs, err = stk.store.ListJobs(r.Context(), pid, "")
	} else {
		jobs, err = stk.store.ListRecentJobs(r.Context(), 20)
	}
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"jobs": jobs})
}

func (s *Server) entCandidatesList(w http.ResponseWriter, r *http.Request) {
	stk, err := s.entStores()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	status := r.URL.Query().Get("status")
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	rows, total, err := stk.store.ListCandidateAssets(r.Context(), projectID, status, "", page, 50)
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"candidates": rows, "total": total, "page": page})
}

// entImport 候选域名导入资产库(指定 domains 或全部 candidate),并标已导入。
func (s *Server) entImport(w http.ResponseWriter, r *http.Request) {
	stk, err := s.entStores()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var in struct {
		ProjectID int64    `json:"project_id"`
		Domains   []string `json:"domains"`
	}
	if err := decode(r, &in); err != nil || in.ProjectID <= 0 {
		writeErr(w, 400, "project_id 必填")
		return
	}
	domains := in.Domains
	if len(domains) == 0 {
		rows, _, err := stk.store.ListCandidateAssets(r.Context(), fmt.Sprintf("%d", in.ProjectID), "candidate", "", 1, 500)
		if err != nil {
			writeErr(w, 500, "db: "+err.Error())
			return
		}
		for _, c := range rows {
			domains = append(domains, c.Value)
		}
	}
	if len(domains) == 0 {
		writeJSON(w, 200, map[string]any{"imported": 0, "note": "没有可导入的候选"})
		return
	}
	imported := s.importSubdomains(r.Context(), in.ProjectID, domains)
	if n, err := stk.store.MarkCandidatesImportedByValue(r.Context(), domains); err != nil {
		log.Printf("[enterprise] 候选标记已导入失败(导入已完成): %v", err)
	} else {
		_ = n
	}
	writeJSON(w, 200, map[string]any{"imported": imported, "total": len(domains)})
}
