package server

import (
	"net/http"
	"strconv"
)

// pgListVulnKB 分页检索漏洞知识库。q 匹配标题/产品/CVE/指纹,type 取值
// 来自 /api/vulnkb/stats。列表不带 body。
func (s *Server) pgListVulnKB(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 0)
	size := atoiDefault(q.Get("size"), 50)
	entries, total, err := s.m.PG().ListVulnKB(q.Get("q"), q.Get("type"), page, size)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"entries": entries, "total": total})
}

// pgGetVulnKB 返回单条完整记录(含原始 markdown)。
func (s *Server) pgGetVulnKB(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	entry, err := s.m.PG().GetVulnKB(id)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, map[string]any{"entry": entry})
}

// pgVulnKBStats 返回库概览(总量/产品数/字段覆盖率/类型分布)。
func (s *Server) pgVulnKBStats(w http.ResponseWriter, _ *http.Request) {
	stats, err := s.m.PG().VulnKBStats()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"stats": stats})
}
