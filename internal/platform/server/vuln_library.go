package server

import "net/http"

// pgListVulnLibrary 统一漏洞库列表：1day 打击库 + 自动抓取情报流。
// source 为空=全部；1day / intel 精确筛选。q 匹配标题/产品/CVE/指纹/情报来源。
func (s *Server) pgListVulnLibrary(w http.ResponseWriter, r *http.Request) {
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
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"entries": entries, "total": total})
}
