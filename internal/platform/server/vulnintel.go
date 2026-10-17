package server

import (
	"net/http"
	"strconv"
	"time"
)

// pgListVulnIntel 分页列出情报流。severity 精确,q 模糊匹配标题/CVE/来源。
func (s *Server) pgListVulnIntel(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 0)
	size := atoiDefault(q.Get("size"), 50)
	entries, total, err := s.m.PG().ListVulnIntel(q.Get("q"), q.Get("severity"), page, size)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"entries": entries, "total": total})
}

// pgGetVulnIntel 返回单条完整情报（统一漏洞库详情用）。
func (s *Server) pgGetVulnIntel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	entry, err := s.m.PG().GetVulnIntel(id)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, map[string]any{"entry": entry})
}

// pgVulnIntelRefresh 触发一次立即轮询(非阻塞,后台执行)。
func (s *Server) pgVulnIntelRefresh(w http.ResponseWriter, _ *http.Request) {
	s.m.vulnIntel.Refresh()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// pgVulnIntelStatus 轮询状态(是否在跑、上次结果、源数量)。
func (s *Server) pgVulnIntelStatus(w http.ResponseWriter, _ *http.Request) {
	polling, last, res, sources := s.m.vulnIntel.Status()
	writeJSON(w, 200, map[string]any{
		"polling": polling,
		"last":    last.Format(time.RFC3339),
		"result":  res,
		"sources": sources,
	})
}
