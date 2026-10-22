// fingerprint_api.go 指纹规则库管理面:规则分页(搜索)+ 数据源同步状态 + 统计。
// 规则本身由 24h 上游自动同步维护(fingerprint.Updater),本页只读展示。
package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/recon/fingerprint"
	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/platform/notify"
)

func (s *Server) fingerprintRulesList(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	pg := s.pg(w)
	if pg == nil {
		return
	}
	store, err := fingerprint.NewStore(pg.DB)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	query := strings.TrimSpace(q.Get("query"))
	source := strings.TrimSpace(q.Get("source"))
	rows, total, err := store.ListRulesPage(r.Context(), query, source, 50, (page-1)*50)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureFingerprint, Action: "search", Source: "web", Status: "error",
			Query: query, Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	sources, _ := store.ListSources(r.Context())
	var enabled int
	_ = pg.QueryRow(`SELECT count(*) FROM fingerprint_rules WHERE enabled`).Scan(&enabled)
	if query != "" || source != "" {
		action := "list"
		summary := fmt.Sprintf("指纹规则列出 %d 条", total)
		if query != "" {
			action = "search"
			summary = fmt.Sprintf("指纹规则搜索「%s」命中 %d 条", query, total)
		}
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureFingerprint, Action: action, Source: "web",
			Query: query, Summary: summary,
			Result: featureJSON(map[string]any{
				"total": total, "enabled": enabled, "source": source,
			}),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
	}
	writeJSON(w, 200, map[string]any{
		"rules": rows, "total": total, "page": page, "enabled": enabled,
		"sources": sources,
	})
}

// fingerprintSyncState 是异步指纹库同步任务的快照。
type fingerprintSyncState struct {
	Running    bool                        `json:"running"`
	Phase      string                      `json:"phase,omitempty"`
	Percent    int                         `json:"percent"`
	Message    string                      `json:"message,omitempty"`
	StartedAt  string                      `json:"started_at,omitempty"`
	FinishedAt string                      `json:"finished_at,omitempty"`
	Error      string                      `json:"error,omitempty"`
	Outcomes   []fingerprint.SourceOutcome `json:"outcomes,omitempty"`
}

// GET /api/fingerprint/status
func (s *Server) fingerprintStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	store, err := fingerprint.NewStore(pg.DB)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	sources, _ := store.ListSources(r.Context())
	var total, enabled int
	_ = pg.QueryRow(`SELECT count(*) FROM fingerprint_rules`).Scan(&total)
	_ = pg.QueryRow(`SELECT count(*) FROM fingerprint_rules WHERE enabled`).Scan(&enabled)
	writeJSON(w, 200, map[string]any{
		"sources": sources,
		"total":   total,
		"enabled": enabled,
		"syncing": s.m.FingerprintSyncing(),
		"proxy":   s.m.FingerprintProxy(),
	})
}

// POST /api/fingerprint/sync — 异步手动更新指纹规则库。
func (s *Server) startFingerprintSync(w http.ResponseWriter, r *http.Request) {
	syncStart := time.Now()
	if s.m.FingerprintSyncing() {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureFingerprint, Action: "sync", Source: "web", Status: "denied",
			Summary:    "指纹库自动同步进行中",
			DurationMS: int(time.Since(syncStart).Milliseconds()),
		})
		writeErr(w, 409, "指纹库自动同步进行中，请稍后再试")
		return
	}
	s.fingerprintSyncMu.Lock()
	if s.fingerprintSync != nil && s.fingerprintSync.Running {
		snap := *s.fingerprintSync
		s.fingerprintSyncMu.Unlock()
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureFingerprint, Action: "sync", Source: "web", Status: "denied",
			Summary:    "已有指纹库同步任务进行中",
			DurationMS: int(time.Since(syncStart).Milliseconds()),
		})
		writeJSON(w, 409, snap)
		return
	}
	job := &fingerprintSyncState{Running: true, Phase: "准备中", StartedAt: time.Now().Format(time.RFC3339)}
	started := job.StartedAt
	s.fingerprintSync = job
	s.fingerprintSyncMu.Unlock()

	go func() {
		outcomes := s.m.SyncFingerprint(s.ctx, func(p fingerprint.Progress) {
			s.fingerprintSyncMu.Lock()
			job.Phase = p.Phase
			job.Percent = p.Percent
			job.Message = p.Message
			s.fingerprintSyncMu.Unlock()
		})
		s.fingerprintSyncMu.Lock()
		job.Running = false
		job.FinishedAt = time.Now().Format(time.RFC3339)
		job.Outcomes = outcomes
		if len(outcomes) == 0 {
			job.Error = "同步未执行（可能已有同步在进行）"
			job.Phase = "失败"
		} else {
			failed := 0
			for _, o := range outcomes {
				if o.Error != "" {
					failed++
				}
			}
			if failed == len(outcomes) {
				job.Error = "所有来源同步失败"
				job.Phase = "失败"
			} else {
				job.Phase = "完成"
				job.Percent = 100
			}
		}
		jobError := job.Error
		s.fingerprintSyncMu.Unlock()

		imported, failed := 0, 0
		for _, o := range outcomes {
			imported += o.Imported
			if o.Error != "" {
				failed++
			}
		}
		kind, title, severity := notify.EventFingerprintSyncDone, "指纹库更新完成", "info"
		if len(outcomes) == 0 || failed == len(outcomes) {
			kind, title, severity = notify.EventFingerprintSyncFailed, "指纹库更新失败", "high"
		}
		_, _ = s.m.pg.AddNotificationEvent(s.ctx, kind, 0, notify.Snapshot{
			Kind: kind, Title: title, Category: "规则库", Severity: severity,
			Summary:   fmt.Sprintf("导入 %d 条；失败来源 %d/%d", imported, failed, len(outcomes)),
			ActionURL: "/system/fingerprint",
		})

		call := db.FeatureCall{
			Feature: FeatureFingerprint, Action: "sync", Source: "web",
			Summary: fmt.Sprintf("指纹库同步完成：导入 %d 条，失败来源 %d/%d", imported, failed, len(outcomes)),
			Result: featureJSON(map[string]any{
				"imported": imported, "failed": failed, "sources": len(outcomes),
			}),
			DurationMS: int(time.Since(syncStart).Milliseconds()),
		}
		if len(outcomes) == 0 || failed == len(outcomes) {
			call.Status = "error"
			call.Error = jobError
		}
		s.recordFeatureCall(context.Background(), call)
	}()

	writeJSON(w, 202, map[string]any{"running": true, "phase": "准备中", "percent": 0, "started_at": started})
}

// GET /api/fingerprint/sync/status
func (s *Server) fingerprintSyncStatus(w http.ResponseWriter, r *http.Request) {
	s.fingerprintSyncMu.Lock()
	var out any = map[string]any{"running": false}
	if s.fingerprintSync != nil {
		snap := *s.fingerprintSync
		out = snap
	}
	s.fingerprintSyncMu.Unlock()
	writeJSON(w, 200, out)
}

// DELETE /api/fingerprint/rules/{id} —— 删除一条自定义规则(上游来源的规则由
// 同步任务维护,不允许手工删)。漏洞情报确认入库的指纹就是 custom 来源,撤下
// 它们走这里;删除后立即失效匹配缓存,下一次 fingerprint_scan 不再命中。
func (s *Server) fingerprintRuleDelete(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, 400, "missing id")
		return
	}
	store, err := fingerprint.NewStore(pg.DB)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := store.DeleteCustomRule(r.Context(), id); err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureFingerprint, Action: "delete", Source: "web", Status: "error",
			RefType: "fingerprint_rule", RefID: id, Summary: "删除自定义指纹规则", Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 400, err.Error())
		return
	}
	fingerprint.CacheInvalidate()
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureFingerprint, Action: "delete", Source: "web",
		RefType: "fingerprint_rule", RefID: id, Summary: "删除自定义指纹规则",
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, map[string]any{"ok": true})
}
