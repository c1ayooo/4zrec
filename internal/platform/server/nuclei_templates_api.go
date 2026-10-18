package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/nuclei"
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
	q := r.URL.Query()
	page := nucleiQueryInt(q.Get("page"), 1)
	size := nucleiQueryInt(q.Get("size"), 20)
	items, total, err := s.nucleiManager().Index().List(nuclei.ListOptions{
		Query: q.Get("q"),
		Filters: nuclei.Filters{
			Severity: queryCSV(q, "severity"),
			Tags:     queryCSV(q, "tags"),
			Type:     strings.TrimSpace(q.Get("type")),
			Source:   strings.TrimSpace(q.Get("source")),
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
	writeJSON(w, 200, resp)
}

// GET /api/nuclei/templates/{id}
func (s *Server) getNucleiTemplate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	meta, content, err := s.nucleiManager().Index().Read(id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"meta": meta, "content": content, "editable": meta.Source == nuclei.SourceCustom,
	})
}

// POST /api/nuclei/templates/validate {yaml}
func (s *Server) validateNucleiTemplate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	meta, err := s.nucleiManager().ValidateCustomTemplate(body.YAML)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "meta": meta})
}

// POST /api/nuclei/templates {yaml}
func (s *Server) createNucleiTemplate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	meta, err := s.nucleiManager().SaveCustomTemplate(body.YAML, false)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, meta)
}

// PUT /api/nuclei/templates/{id} {yaml}
func (s *Server) updateNucleiTemplate(w http.ResponseWriter, r *http.Request) {
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
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, meta)
}

// DELETE /api/nuclei/templates/{id}
func (s *Server) deleteNucleiTemplate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if err := s.nucleiManager().DeleteCustomTemplate(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/nuclei/update — 异步更新二进制与官方模板。
func (s *Server) startNucleiUpdate(w http.ResponseWriter, r *http.Request) {
	s.nucleiUpdateMu.Lock()
	if s.nucleiUpdate != nil && s.nucleiUpdate.Running {
		snap := *s.nucleiUpdate
		s.nucleiUpdateMu.Unlock()
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
