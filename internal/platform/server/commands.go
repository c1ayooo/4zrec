package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// pgListCommands returns tool executions (any tool) from the activity table.
func (s *Server) pgListCommands(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 0)
	size := atoiDefault(q.Get("size"), 50)
	keyword := q.Get("q")

	records, total, err := s.m.PG().ListCommands(commandTaskFilter(q.Get("task")), keyword, page, size)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"commands": records, "total": total})
}

// pgToolStats returns per-tool call counts for the tool-execution history, under
// the same task/keyword filters the list takes — the summary describes the whole
// filtered set, not the page on screen.
func (s *Server) pgToolStats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pg := s.m.PG()
	if pg == nil {
		writeJSON(w, 200, map[string]any{"stats": []db.ToolStat{}})
		return
	}
	stats, err := pg.ToolStats(commandTaskFilter(q.Get("task")), q.Get("q"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"stats": stats})
}

// commandTaskFilter parses the ?task= exploration id. Absent or unparsable → nil
// (no filter), matching the list endpoint's long-standing lenient behaviour.
func commandTaskFilter(v string) *int64 {
	if v == "" {
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

// pgListLLMRecords returns paginated LLM call records.
func (s *Server) pgListLLMRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 0)
	size := atoiDefault(q.Get("size"), 50)
	model := q.Get("model")
	session := q.Get("session")
	task := q.Get("task")

	records, total, err := s.m.PG().ListLLMRecords(model, session, task, page, size)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"records": records, "total": total})
}

// pgTokenByModel returns a task's LLM token usage grouped by model, from the
// always-on llm_usage metering ledger. Accurate even with per-agent model bindings,
// pool rotation/failover, and interrupted runs (every call is metered on success or
// error). No recording toggle required.
func (s *Server) pgTokenByModel(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("task"))
	if id == "" {
		writeErr(w, 400, "missing task")
		return
	}
	pg := s.m.PG()
	if pg == nil {
		writeJSON(w, 200, map[string]any{"models": []db.ModelTokenStat{}})
		return
	}
	models, err := pg.TokenByModel(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"models": models})
}

// pgUsageStats returns global llm_usage aggregates for the dashboard's "new" token
// view: per-profile totals (all-time) + per-(profile, day) buckets for the daily
// chart. Sourced from the always-on metering ledger, so it is accurate across
// per-agent bindings, pool rotation, and interrupted runs.
func (s *Server) pgUsageStats(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeJSON(w, 200, map[string]any{"by_profile": []db.ProfileUsage{}, "daily": []db.ProfileDayUsage{}, "tasks": 0})
		return
	}
	days := atoiDefault(r.URL.Query().Get("days"), 365)
	byProfile, err := pg.UsageByProfile()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	daily, err := pg.UsageDaily(days)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 全局去重任务数：「全部」Tab 不能把各 profile 的 tasks 相加——同一任务
	// 可能用过多个 profile，相加会重复计数。
	tasks, err := pg.UsageTaskCount()
	if err != nil {
		tasks = 0 // 展示用,失败不影响 token 主数据
	}
	// 费用：按 llm_pricing 的模型单价，对 live 账本逐 (model, profile) 计价。
	// 归档聚合没有 model 维度，不计价（其 token 仍计入总量）。
	rules, _ := pg.ListLLMPricing()
	modelUsage, _ := pg.UsageByModel()
	costByProfile := map[string]float64{}
	unpriced := map[string]bool{}
	currency := "CNY"
	if len(rules) > 0 && strings.TrimSpace(rules[0].Currency) != "" {
		currency = rules[0].Currency
	}
	var totalCost float64
	for _, m := range modelUsage {
		rule, ok := db.MatchLLMPricing(rules, m.Model)
		if !ok {
			if m.InputTokens+m.OutputTokens+m.CacheRead+m.CacheWrite > 0 {
				unpriced[m.Model] = true
			}
			continue
		}
		c := float64(m.InputTokens)*rule.InputPerMTok/1e6 +
			float64(m.OutputTokens)*rule.OutputPerMTok/1e6 +
			float64(m.CacheRead)*rule.CacheReadPerMTok/1e6 +
			float64(m.CacheWrite)*rule.CacheWritePerMTok/1e6
		costByProfile[m.ProfileName] += c
		totalCost += c
	}
	for i := range byProfile {
		byProfile[i].Cost = costByProfile[byProfile[i].ProfileName]
	}
	// 每日费用：同一套单价，按 (profile, day) 归桶。
	dailyByModel, _ := pg.UsageDailyByModel(days)
	costByDay := map[string]float64{}
	for _, m := range dailyByModel {
		rule, ok := db.MatchLLMPricing(rules, m.Model)
		if !ok {
			continue
		}
		costByDay[m.ProfileName+"\x00"+m.Date] += float64(m.InputTokens)*rule.InputPerMTok/1e6 +
			float64(m.OutputTokens)*rule.OutputPerMTok/1e6 +
			float64(m.CacheRead)*rule.CacheReadPerMTok/1e6 +
			float64(m.CacheWrite)*rule.CacheWritePerMTok/1e6
	}
	for i := range daily {
		daily[i].Cost = costByDay[daily[i].ProfileName+"\x00"+daily[i].Date]
	}
	unpricedModels := make([]string, 0, len(unpriced))
	for m := range unpriced {
		unpricedModels = append(unpricedModels, m)
	}
	sort.Strings(unpricedModels)
	writeJSON(w, 200, map[string]any{
		"by_profile": byProfile, "daily": daily, "tasks": tasks,
		"cost": totalCost, "currency": currency, "unpriced_models": unpricedModels,
	})
}

// llmPricingGet returns the price book plus the models currently seen in the
// ledger, so the UI can prefill rows for models that have no rule yet.
func (s *Server) llmPricingGet(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeJSON(w, 200, map[string]any{"rules": []db.LLMPricing{}, "models": []db.ModelUsage{}})
		return
	}
	rules, err := pg.ListLLMPricing()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	models, err := pg.UsageByModel()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"rules": rules, "models": models})
}

// llmPricingPut replaces the whole price book (the UI edits the complete list).
func (s *Server) llmPricingPut(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	var req struct {
		Rules []db.LLMPricing `json:"rules"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(req.Rules) > 200 {
		writeErr(w, 400, "计价规则最多 200 条")
		return
	}
	for i := range req.Rules {
		req.Rules[i].ModelPattern = strings.TrimSpace(req.Rules[i].ModelPattern)
		if req.Rules[i].ModelPattern == "" {
			writeErr(w, 400, "model_pattern 不能为空")
			return
		}
		if req.Rules[i].InputPerMTok < 0 || req.Rules[i].OutputPerMTok < 0 ||
			req.Rules[i].CacheReadPerMTok < 0 || req.Rules[i].CacheWritePerMTok < 0 {
			writeErr(w, 400, "单价不能为负数")
			return
		}
		if strings.TrimSpace(req.Rules[i].Currency) == "" {
			req.Rules[i].Currency = "CNY"
		}
	}
	if err := pg.ReplaceLLMPricing(req.Rules); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "rules": len(req.Rules)})
}

// pgLLMTasks returns distinct recorded tasks with counts, for the page's task
// picker (pick a task → filter the list, then delete its conversations).
func (s *Server) pgLLMTasks(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.m.PG().LLMTasks()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"tasks": tasks})
}

// pgDeleteLLMRecords removes all LLM records for one exact task_id (the same
// match the task picker uses). Empty task → 400. Returns rows deleted.
func (s *Server) pgDeleteLLMRecords(w http.ResponseWriter, r *http.Request) {
	task := strings.TrimSpace(r.URL.Query().Get("task"))
	if task == "" {
		writeErr(w, 400, "missing task")
		return
	}
	n, err := s.m.PG().DeleteLLMRecords(task)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": n})
}

// pgGetLLMRecord returns a single LLM record with full request/response bodies.
func (s *Server) pgGetLLMRecord(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	rec, err := s.m.PG().GetLLMRecord(id)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, rec)
}
