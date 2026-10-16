// fingerprint_api.go 指纹规则库管理面:规则分页(搜索)+ 数据源同步状态 + 统计。
// 规则本身由 24h 上游自动同步维护(fingerprint.Updater),本页只读展示。
package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/fingerprint"
)

func (s *Server) fingerprintRulesList(w http.ResponseWriter, r *http.Request) {
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
	rows, total, err := store.ListRulesPage(r.Context(),
		strings.TrimSpace(q.Get("query")), strings.TrimSpace(q.Get("source")), 50, (page-1)*50)
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	sources, _ := store.ListSources(r.Context())
	var enabled int
	_ = pg.QueryRow(`SELECT count(*) FROM fingerprint_rules WHERE enabled`).Scan(&enabled)
	writeJSON(w, 200, map[string]any{
		"rules": rows, "total": total, "page": page, "enabled": enabled,
		"sources": sources,
	})
}
