package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// pgListVulnKB 分页检索漏洞知识库。q 匹配标题/产品/CVE/指纹,type 取值
// 来自 /api/vulnkb/stats。列表不带 body。
func (s *Server) pgListVulnKB(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 0)
	size := atoiDefault(q.Get("size"), 50)
	entries, total, err := s.m.PG().ListVulnKB(q.Get("q"), q.Get("type"), page, size)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: "search", Source: "web", Status: "error",
			Query: q.Get("q"), Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 500, err.Error())
		return
	}
	if q.Get("q") != "" || q.Get("type") != "" {
		action := "list"
		summary := fmt.Sprintf("1day 库列出 %d 条", total)
		if q.Get("q") != "" {
			action = "search"
			summary = fmt.Sprintf("1day 库搜索「%s」命中 %d 条", q.Get("q"), total)
		}
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: action, Source: "web",
			Query: q.Get("q"), Summary: summary,
			Result:     featureJSON(map[string]any{"total": total, "type": q.Get("type")}),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
	}
	writeJSON(w, 200, map[string]any{"entries": entries, "total": total})
}

// pgGetVulnKB 返回单条完整记录(含原始 markdown)。
func (s *Server) pgGetVulnKB(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	entry, err := s.m.PG().GetVulnKB(id)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: "view", Source: "web", Status: "error",
			RefType: "vuln_kb", RefID: strconv.FormatInt(id, 10), Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 404, "not found")
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureVulnKB, Action: "view", Source: "web",
		RefType: "vuln_kb", RefID: strconv.FormatInt(id, 10),
		Summary:    fmt.Sprintf("查看 1day 漏洞「%s」", entry.Title),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
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
