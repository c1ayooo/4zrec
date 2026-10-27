// recon_schedule.go 周期采集任务:worker 复用直接搬来的 collect.RunScheduleWorker
// (30s tick + inflight 去重 + 有界并发),执行体分 engine(五引擎按域采集,增量=
// 新入库子域数)与 pipeline(主动测绘流水线)两形态。鉴权失败经引擎层
// SourceRecorder 感知,指数退避熔断(db.MarkScheduleRan 维护);新资产>0 入
// notification_events(既有通知渠道渲染投递)。HTTP 管理面与系统设置页同风格。
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/recon/collect"
	"github.com/c1ayooo/4zrec/internal/capability/recon/pipeline"
	"github.com/c1ayooo/4zrec/internal/capability/recon/spacemap"
	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/platform/notify"
)

// runReconScheduleWorker 阻塞运行到 ctx 取消(启动时 go 起)。
func (s *Server) runReconScheduleWorker(ctx context.Context) {
	collect.RunScheduleWorker(ctx, collect.WorkerOptions{
		Name: "recon-schedules", Tick: 30 * time.Second, MaxConcurrent: 1,
		ListDue: func() ([]collect.ScheduleTask, error) {
			due, err := s.m.pg.ListDueSchedules(context.Background())
			if err != nil {
				return nil, err
			}
			out := make([]collect.ScheduleTask, 0, len(due))
			for _, d := range due {
				out = append(out, collect.ScheduleTask{ID: strconv.FormatInt(d.ID, 10)})
			}
			return out, nil
		},
		Execute: func(_ context.Context, id string) {
			sid, _ := strconv.ParseInt(id, 10, 64)
			if sid <= 0 {
				return
			}
			s.executeReconSchedule(sid)
		},
	})
}

// executeReconSchedule 执行一条到期任务(panic 兜底,失败写 last_result)。
func (s *Server) executeReconSchedule(id int64) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recon-sched] 任务 #%d panic: %v", id, r)
			_ = s.m.pg.MarkScheduleRan(context.Background(), id, 1800, false, fmt.Sprintf("panic: %v", r), 0)
		}
	}()
	sched, err := s.m.pg.GetReconSchedule(context.Background(), id)
	if err != nil || sched == nil {
		return
	}
	var (
		result    string
		newAssets int
		authFail  bool
	)
	switch sched.Kind {
	case "engine":
		result, newAssets, authFail = s.executeEngineSchedule(sched)
	case "pipeline":
		result, newAssets, authFail = s.executePipelineSchedule(sched)
	case "zreark":
		result, newAssets, authFail = s.executeZrearkSchedule(sched)
	default:
		result = "未知任务形态: " + sched.Kind
	}
	_ = s.m.pg.MarkScheduleRan(context.Background(), id, sched.IntervalSec, authFail, result, newAssets)
	// 增量通知:仅新资产 > 0 且未熔断时入事件(渠道渲染投递由既有 notifier 完成)。
	if newAssets > 0 && !authFail {
		_, _ = s.m.pg.AddNotificationEvent(context.Background(), notify.EventReconNewAssets, 0, notify.Snapshot{
			Kind:      notify.EventReconNewAssets,
			Title:     fmt.Sprintf("周期采集「%s」新增 %d 个资产", sched.Name, newAssets),
			Category:  "侦察",
			Severity:  "info",
			Summary:   result,
			ProjectID: derefInt64(sched.ProjectID),
			ActionURL: "/function/assets",
		})
	}
}

// executeZrearkSchedule 定时从 4zreark 拉取站点资产入库（复用 asset_sync 核心）。
// config: {"source_project_id":1,"target_project_id":2,"catalog":"all","limit":1000}；
// 未配置连接或鉴权失败均视为 authFail 走指数退避熔断。
func (s *Server) executeZrearkSchedule(sched *db.ReconSchedule) (string, int, bool) {
	var cfg struct {
		SourceProjectID int64  `json:"source_project_id"`
		TargetProjectID int64  `json:"target_project_id"`
		Catalog         string `json:"catalog"`
		Limit           int    `json:"limit"`
	}
	_ = json.Unmarshal(sched.Config, &cfg)

	caller, err := s.zrearkCallerFromRequest("", "")
	if err != nil {
		authFail := errors.Is(err, errZrearkNoConfig)
		return "4zreark 连接未就绪: " + err.Error(), 0, authFail
	}
	result, err := s.runZrearkAssetSync(context.Background(), caller, zrearkSyncParams{
		SourceProjectID: cfg.SourceProjectID,
		TargetProjectID: cfg.TargetProjectID,
		Catalog:         cfg.Catalog,
		Limit:           cfg.Limit,
	})
	if err != nil {
		authFail := errors.Is(err, errZrearkAuth)
		return truncateSyncText(err.Error(), 300), 0, authFail
	}
	summary := fmt.Sprintf("4zreark 同步: 读取 %d / 写入 %d / 跳过 %d", result.Fetched, result.Imported, result.Skipped)
	if len(result.Errors) > 0 {
		summary += "; 首个错误: " + result.Errors[0]
	}
	return summary, result.Imported, false
}

// executeEngineSchedule 五引擎按域采集:每引擎×每域查询,新入库子域计数。
func (s *Server) executeEngineSchedule(sched *db.ReconSchedule) (string, int, bool) {
	var cfg struct {
		Domains []string `json:"domains"`
		Engines []string `json:"engines"`
	}
	_ = json.Unmarshal(sched.Config, &cfg)
	if len(cfg.Domains) == 0 {
		return "config.domains 为空,跳过", 0, false
	}
	engines := cfg.Engines
	if len(engines) == 0 {
		engines = spacemap.Providers
	}
	projectID := derefInt64(sched.ProjectID)

	c := s.spacemapClient()
	authFailed := false
	c.SourceRecorder = func(provider, status, errMsg string) {
		if status == "auth_failed" {
			authFailed = true
			log.Printf("[recon-sched] 引擎 %s 鉴权失败: %s", provider, errMsg)
		}
	}
	var (
		totalHits int
		newCount  int
		notes     []string
	)
	for _, engine := range engines {
		if !spacemap.ValidProvider(engine) || !c.SourceConfigured(engine) {
			continue
		}
		for _, domain := range cfg.Domains {
			q := spacemap.DomainQuery(engine, strings.TrimSpace(domain))
			results, _, total, err := c.SearchEngineAssets(context.Background(), engine, q, 100, 1)
			if err != nil {
				notes = append(notes, fmt.Sprintf("%s %s: %v", spacemap.ProviderDisplayName(engine), domain, err))
				continue
			}
			totalHits += total
			for _, r := range results {
				if r.Domain == "" {
					continue
				}
				var existed int
				_ = s.m.pg.QueryRow(`SELECT 1 FROM assets WHERE domain=$1 LIMIT 1`, r.Domain).Scan(&existed)
				if existed == 0 {
					newCount++
				}
				// 复用统一入库路径(域名+IP+服务,范围认领)。
				s.spacemapImport(context.Background(), projectID, 0, []*spacemap.Result{r}, q)
			}
		}
	}
	result := fmt.Sprintf("命中 %d,新资产 %d(引擎遍历 %d 域 %d)", totalHits, newCount, len(engines), len(cfg.Domains))
	if len(notes) > 0 {
		result += ";错误 " + strconv.Itoa(len(notes)) + " 条"
	}
	if authFailed {
		result += ";存在引擎鉴权失败,进入退避"
	}
	return result, newCount, authFailed
}

// executePipelineSchedule 主动测绘流水线(周期版默认只跑被动+解析,主动探测
// 需在 config 显式开启)。
func (s *Server) executePipelineSchedule(sched *db.ReconSchedule) (string, int, bool) {
	opts := pipeline.Options{EnableSubdomain: true, EnableDNS: true}
	// config 用小写键(前端/工具入参形态);pipeline.Options 无 json tag,先解到
	// 影子结构再映射,避免大小写不匹配落回默认值(全阶段误开)。
	var cfgShadow struct {
		Domains   []string `json:"domains"`
		Subdomain *bool    `json:"subdomain"`
		Permute   *bool    `json:"permute"`
		Brute     *bool    `json:"brute"`
		DNS       *bool    `json:"dns"`
		Portscan  *bool    `json:"portscan"`
		HTTP      *bool    `json:"http"`
		Ports     string   `json:"ports"`
	}
	if err := json.Unmarshal(sched.Config, &cfgShadow); err != nil {
		return "config 解析失败: " + err.Error(), 0, false
	}
	opts.Domains = cfgShadow.Domains
	opts.PortsSet = cfgShadow.Ports
	for _, kv := range []struct {
		p *bool
		d *bool
	}{{cfgShadow.Subdomain, &opts.EnableSubdomain}, {cfgShadow.Permute, &opts.EnablePermute},
		{cfgShadow.Brute, &opts.EnableBrute}, {cfgShadow.DNS, &opts.EnableDNS},
		{cfgShadow.Portscan, &opts.EnablePortscan}, {cfgShadow.HTTP, &opts.EnableHTTP}} {
		if kv.p != nil {
			*kv.d = *kv.p
		}
	}
	if len(opts.Domains) == 0 {
		return "config.domains 为空,跳过", 0, false
	}
	projectID := derefInt64(sched.ProjectID)
	opts.ProjectID = projectID
	// RoE:周期任务无人值守,范围外主域直接跳过整单并记录。
	if projectID > 0 {
		rules, err := s.m.pg.ProjectScopeRules(projectID)
		if err == nil {
			var denied []string
			for _, d := range opts.Domains {
				if _, ok := db.MatchProjectScope(rules, strings.TrimSpace(d), ""); !ok {
					denied = append(denied, d)
				}
			}
			if len(denied) > 0 {
				return fmt.Sprintf("RoE:主域 %s 不在项目 %d 授权范围,整单跳过", strings.Join(denied, ","), projectID), 0, false
			}
		}
	}
	// 每轮落一行运行记录(schedule_id 关联,前端展开运行历史)。
	cfgRaw, _ := json.Marshal(map[string]any{"subdomain": opts.EnableSubdomain, "dns": opts.EnableDNS,
		"portscan": opts.EnablePortscan, "http": opts.EnableHTTP})
	runID, rerr := s.m.pg.CreateReconRunForSchedule(context.Background(), projectID, sched.ID, opts.Domains, cfgRaw)
	if rerr != nil {
		log.Printf("[recon-sched] 任务 #%d 运行记录创建失败(继续执行): %v", sched.ID, rerr)
	}
	stats, runErr := pipeline.Run(context.Background(), opts, s.m.pg, func(stage string, st pipeline.Stats) {
		if runID > 0 {
			_ = s.m.pg.UpdateReconRunProgress(context.Background(), runID, stage, pipeline.MarshalStats(st))
		}
	})
	if runID > 0 {
		var finalStats json.RawMessage
		if stats != nil {
			finalStats = pipeline.MarshalStats(*stats)
		}
		stage := "dns"
		if runErr != nil {
			stage = "interrupted"
		}
		_ = s.m.pg.FinishReconRun(context.Background(), runID, stage, finalStats, errStr(runErr))
	}
	if runErr != nil {
		return fmt.Sprintf("流水线中断: %v", runErr), 0, false
	}
	return fmt.Sprintf("候选 %d/活 %d/新 %d/端口 %d/http %d(run #%d)", stats.Candidates, stats.Live, stats.NewAssets, stats.OpenPorts, stats.HTTPAlive, runID),
		stats.NewAssets, false
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// ---------- HTTP 管理面 ----------

func (s *Server) reconSchedList(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	list, err := pg.ListReconSchedules(r.Context())
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"schedules": list})
}

func (s *Server) reconSchedCreate(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in struct {
		Name        string          `json:"name"`
		Kind        string          `json:"kind"`
		Config      json.RawMessage `json:"config"`
		IntervalSec int             `json:"interval_sec"`
		ProjectID   int64           `json:"project_id"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(in.Name) == "" || (in.Kind != "engine" && in.Kind != "pipeline" && in.Kind != "zreark") {
		writeErr(w, 400, "name 与 kind(engine|pipeline|zreark) 必填")
		return
	}
	if in.IntervalSec < 60 {
		in.IntervalSec = 1800
	}
	var pid *int64
	if in.ProjectID > 0 {
		pid = &in.ProjectID
	}
	id, err := pg.CreateReconSchedule(r.Context(), &db.ReconSchedule{
		Name: strings.TrimSpace(in.Name), Kind: in.Kind, Config: in.Config,
		IntervalSec: in.IntervalSec, ProjectID: pid,
	})
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id})
}

func (s *Server) reconSchedUpdate(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	var in struct {
		Name        string          `json:"name"`
		Config      json.RawMessage `json:"config"`
		IntervalSec int             `json:"interval_sec"`
		Enabled     *bool           `json:"enabled"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	if in.IntervalSec < 60 {
		in.IntervalSec = 1800
	}
	if err := pg.UpdateReconSchedule(r.Context(), id, strings.TrimSpace(in.Name), in.IntervalSec, in.Config, enabled); err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) reconSchedDelete(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	if err := pg.DeleteReconSchedule(r.Context(), id); err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

func (s *Server) reconSchedToggle(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &in); err != nil || id <= 0 {
		writeErr(w, 400, "invalid request")
		return
	}
	if err := pg.SetReconScheduleEnabled(r.Context(), id, in.Enabled); err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// reconRunsList 运行历史(schedule_id 过滤,倒序)。
func (s *Server) reconRunsList(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sid, _ := strconv.ParseInt(r.URL.Query().Get("schedule_id"), 10, 64)
	if sid <= 0 {
		writeErr(w, 400, "schedule_id 必填")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := pg.ListReconRunsForSchedule(r.Context(), sid, limit)
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"runs": runs})
}

func (s *Server) reconSchedRunNow(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	if err := pg.RunReconScheduleNow(r.Context(), id); err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "note": "已标记到期,worker 30s 内拾取"})
}
