package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/nuclei"
	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/platform/notify"
)

// nucleiUpdateState 是异步更新任务的快照。
type nucleiUpdateState struct {
	Running    bool                 `json:"running"`
	Phase      string               `json:"phase,omitempty"`
	Percent    int                  `json:"percent"`
	Message    string               `json:"message,omitempty"`
	StartedAt  string               `json:"started_at,omitempty"`
	FinishedAt string               `json:"finished_at,omitempty"`
	Error      string               `json:"error,omitempty"`
	Result     *nuclei.UpdateResult `json:"result,omitempty"`
}

// GET /api/nuclei/templates?q=&severity=&tags=&type=&source=&page=&size=
func (s *Server) getNucleiTemplates(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := r.URL.Query()
	page := nucleiQueryInt(q.Get("page"), 1)
	size := nucleiQueryInt(q.Get("size"), 20)
	search := strings.TrimSpace(q.Get("q"))
	severity := queryCSV(q, "severity")
	tags := queryCSV(q, "tags")
	tmplType := strings.TrimSpace(q.Get("type"))
	source := strings.TrimSpace(q.Get("source"))
	items, total, err := s.nucleiManager().Index().List(nuclei.ListOptions{
		Query: search,
		Filters: nuclei.Filters{
			Severity: severity,
			Tags:     tags,
			Type:     tmplType,
			Source:   source,
		},
		Page: page,
		Size: size,
	})
	resp := map[string]any{"items": items, "total": total, "page": page, "size": size}
	if err != nil {
		// 全新安装尚未下载模板：返回空列表 + 提示，而不是 500。
		resp["items"] = []nuclei.TemplateMeta{}
		resp["total"] = 0
		resp["warning"] = err.Error()
	}
	if search != "" || len(severity) > 0 || len(tags) > 0 || tmplType != "" || err != nil {
		status := "ok"
		summary := fmt.Sprintf("模板检索命中 %d 条", total)
		if search != "" {
			summary = fmt.Sprintf("检索模板「%s」命中 %d 条", search, total)
		}
		errText := ""
		if err != nil {
			status = "error"
			errText = err.Error()
			summary = "模板检索失败：" + err.Error()
		}
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureNuclei, Action: "search", Source: "web", Status: status,
			Query: search, Summary: summary, Error: errText,
			Result: featureJSON(map[string]any{
				"total": total, "severity": severity, "tags": tags,
				"type": tmplType, "source": source,
			}),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
	}
	writeJSON(w, 200, resp)
}

// GET /api/nuclei/templates/{id}
func (s *Server) getNucleiTemplate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := strings.TrimSpace(r.PathValue("id"))
	meta, content, err := s.nucleiManager().Index().Read(id)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureNuclei, Action: "view", Source: "web", Status: "error",
			RefType: "nuclei_template", RefID: id, Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 404, err.Error())
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureNuclei, Action: "view", Source: "web",
		RefType: "nuclei_template", RefID: id,
		Summary:    fmt.Sprintf("查看模板「%s」", meta.Name),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, map[string]any{
		"meta": meta, "content": content, "editable": meta.Source == nuclei.SourceCustom,
	})
}

// POST /api/nuclei/templates/validate {yaml}
func (s *Server) validateNucleiTemplate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	meta, err := s.nucleiManager().ValidateCustomTemplate(body.YAML)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureNuclei, Action: "validate", Source: "web", Status: "error",
			Error: err.Error(), Summary: "模板校验失败：" + err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureNuclei, Action: "validate", Source: "web",
		RefType: "nuclei_template", RefID: meta.ID,
		Summary:    fmt.Sprintf("模板校验通过「%s」", meta.ID),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, map[string]any{"ok": true, "meta": meta})
}

// POST /api/nuclei/templates {yaml}
func (s *Server) createNucleiTemplate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	meta, err := s.nucleiManager().SaveCustomTemplate(body.YAML, false)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureNuclei, Action: "create", Source: "web", Status: "error",
			Error: err.Error(), Summary: "新建自定义模板失败：" + err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 400, err.Error())
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureNuclei, Action: "create", Source: "web",
		RefType: "nuclei_template", RefID: meta.ID,
		Summary:    fmt.Sprintf("新建自定义模板「%s」", meta.ID),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 201, meta)
}

// PUT /api/nuclei/templates/{id} {yaml}
func (s *Server) updateNucleiTemplate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := strings.TrimSpace(r.PathValue("id"))
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	meta, err := s.nucleiManager().UpdateCustomTemplate(id, body.YAML)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureNuclei, Action: "update", Source: "web", Status: "error",
			RefType: "nuclei_template", RefID: id, Error: err.Error(),
			Summary:    "更新自定义模板失败：" + err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 400, err.Error())
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureNuclei, Action: "update", Source: "web",
		RefType: "nuclei_template", RefID: id,
		Summary:    fmt.Sprintf("更新自定义模板「%s」", id),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, meta)
}

// DELETE /api/nuclei/templates/{id}
func (s *Server) deleteNucleiTemplate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := strings.TrimSpace(r.PathValue("id"))
	if err := s.nucleiManager().DeleteCustomTemplate(id); err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureNuclei, Action: "delete", Source: "web", Status: "error",
			RefType: "nuclei_template", RefID: id, Error: err.Error(),
			Summary:    "删除自定义模板失败：" + err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 400, err.Error())
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureNuclei, Action: "delete", Source: "web",
		RefType: "nuclei_template", RefID: id,
		Summary:    fmt.Sprintf("删除自定义模板「%s」", id),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/nuclei/update — 异步更新二进制与官方模板。
func (s *Server) startNucleiUpdate(w http.ResponseWriter, r *http.Request) {
	updateStart := time.Now()
	s.nucleiUpdateMu.Lock()
	if s.nucleiUpdate != nil && s.nucleiUpdate.Running {
		snap := *s.nucleiUpdate
		s.nucleiUpdateMu.Unlock()
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureNuclei, Action: "update", Source: "web", Status: "denied",
			Summary:    "已有 nuclei 更新任务进行中",
			DurationMS: int(time.Since(updateStart).Milliseconds()),
		})
		writeJSON(w, 409, snap)
		return
	}
	job := &nucleiUpdateState{Running: true, Phase: "准备中", StartedAt: time.Now().Format(time.RFC3339)}
	started := job.StartedAt
	s.nucleiUpdate = job
	s.nucleiUpdateMu.Unlock()

	go func() {
		res, err := s.nucleiManager().UpdateWithProgress(s.ctx, true, false, false, func(p nuclei.Progress) {
			s.nucleiUpdateMu.Lock()
			job.Phase = p.Phase
			job.Percent = p.Percent
			job.Message = p.Message
			s.nucleiUpdateMu.Unlock()
		})
		s.nucleiUpdateMu.Lock()
		job.Running = false
		job.FinishedAt = time.Now().Format(time.RFC3339)
		if err != nil {
			job.Error = err.Error()
			job.Phase = "失败"
			job.Message = err.Error()
		} else {
			job.Result = res
			job.Phase = "完成"
			job.Percent = 100
			if len(res.Warnings) > 0 {
				job.Message = strings.Join(res.Warnings, "；")
			} else {
				job.Message = ""
			}
		}
		s.nucleiUpdateMu.Unlock()

		kind, title, severity := notify.EventNucleiUpdateDone, "nuclei 更新完成", "info"
		summary := ""
		if err != nil {
			kind, title, severity = notify.EventNucleiUpdateFailed, "nuclei 更新失败", "high"
			summary = err.Error()
		} else if res != nil {
			summary = fmt.Sprintf("官方模板 %d 个；自定义 %d 个", res.TemplateCount, res.CustomTemplateCount)
			if len(res.Warnings) > 0 {
				summary += "；" + strings.Join(res.Warnings, "；")
			}
		}
		_, _ = s.m.pg.AddNotificationEvent(s.ctx, kind, 0, notify.Snapshot{
			Kind: kind, Title: title, Category: "规则库", Severity: severity,
			Summary: summary, ActionURL: "/function/nuclei-templates",
		})

		call := db.FeatureCall{
			Feature: FeatureNuclei, Action: "update", Source: "web",
			Summary:    summary,
			DurationMS: int(time.Since(updateStart).Milliseconds()),
		}
		if err != nil {
			call.Status = "error"
			call.Error = err.Error()
		} else if res != nil {
			call.Result = featureJSON(map[string]any{
				"template_count":        res.TemplateCount,
				"custom_template_count": res.CustomTemplateCount,
				"warnings":              res.Warnings,
			})
			if call.Summary == "" {
				call.Summary = fmt.Sprintf("官方模板更新完成，共 %d 个模板", res.TemplateCount)
			}
		}
		s.recordFeatureCall(context.Background(), call)
	}()

	writeJSON(w, 202, map[string]any{"running": true, "phase": "准备中", "percent": 0, "started_at": started})
}

// GET /api/nuclei/update/status
func (s *Server) nucleiUpdateStatus(w http.ResponseWriter, r *http.Request) {
	s.nucleiUpdateMu.Lock()
	var out any = map[string]any{"running": false}
	if s.nucleiUpdate != nil {
		snap := *s.nucleiUpdate
		out = snap
	}
	s.nucleiUpdateMu.Unlock()
	writeJSON(w, 200, out)
}

func nucleiQueryInt(raw string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func queryCSV(q map[string][]string, key string) []string {
	var out []string
	for _, raw := range q[key] {
		for _, part := range strings.Split(raw, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}
