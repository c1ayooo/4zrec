package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// pgListVulnLibrary 统一漏洞库列表：1day 打击库 + 自动抓取情报流。
// source 为空=全部；1day / intel 精确筛选。q 匹配标题/产品/CVE/指纹/情报来源。
func (s *Server) pgListVulnLibrary(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 0)
	size := atoiDefault(q.Get("size"), 50)
	source := q.Get("source")
	if source != "" && source != "1day" && source != "intel" {
		writeErr(w, 400, "invalid source")
		return
	}
	entries, total, err := s.m.PG().ListVulnLibrary(q.Get("q"), source, page, size)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: "search", Source: "web", Status: "error",
			Query: q.Get("q"), Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 500, err.Error())
		return
	}
	if q.Get("q") != "" || source != "" {
		action := "list"
		summary := fmt.Sprintf("漏洞库列出 %d 条", total)
		if q.Get("q") != "" {
			action = "search"
			summary = fmt.Sprintf("漏洞库搜索「%s」命中 %d 条", q.Get("q"), total)
		}
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: action, Source: "web",
			Query: q.Get("q"), Summary: summary,
			Result:     featureJSON(map[string]any{"total": total, "source": source}),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
	}
	writeJSON(w, 200, map[string]any{"entries": entries, "total": total})
}
