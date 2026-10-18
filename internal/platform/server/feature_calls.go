package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/orchestration/agent"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

const (
	FeatureVulnKB      = "vulnkb"
	FeatureNuclei      = "nuclei"
	FeatureFingerprint = "fingerprint"

	featureCallRetentionDays = 90
	featureCallMaxText       = 16384
)

// featureCallRecorder 由 *db.DB 实现；meteredTool 用它写 Agent 工具的调用历史。
type featureCallRecorder interface {
	InsertFeatureCall(*db.FeatureCall) error
}

// recordFeatureCall 是 Web handler 和异步任务共用的写入入口：补齐 RunInfo
// 归属、默认值和截断，写失败只记日志，不影响主流程。
func (s *Server) recordFeatureCall(ctx context.Context, c db.FeatureCall) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	ri := agent.RunInfoFrom(ctx)
	if c.TaskID == 0 {
		c.TaskID = ri.TaskID
	}
	if c.ExplorationID == 0 {
		c.ExplorationID = ri.ExplorationID
	}
	if c.IntentID == 0 {
		c.IntentID = ri.IntentID
	}
	if c.SessionID == "" {
		c.SessionID = ri.SessionID
	}
	if c.Source == "" {
		c.Source = "web"
	}
	if c.Status == "" {
		c.Status = "ok"
	}
	if c.Action == "" {
		c.Action = "unknown"
	}
	c.Actor = truncateRunes(c.Actor, 256)
	c.Query = truncateRunes(c.Query, 1024)
	c.Summary = truncateRunes(c.Summary, 1024)
	c.Error = truncateRunes(c.Error, 4096)
	c.RefType = truncateRunes(c.RefType, 64)
	c.RefID = truncateRunes(c.RefID, 256)
	c.Request = truncateFeatureJSON(c.Request, featureCallMaxText)
	c.Result = truncateFeatureJSON(c.Result, featureCallMaxText)
	if err := s.m.pg.InsertFeatureCall(&c); err != nil {
		log.Printf("[featurecall] insert %s/%s: %v", c.Feature, c.Action, err)
	}
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

func truncateFeatureJSON(raw json.RawMessage, max int) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	if len(raw) <= max {
		if !json.Valid(raw) {
			return json.RawMessage(`{}`)
		}
		return raw
	}
	b, _ := json.Marshal(map[string]any{"truncated": true, "bytes": len(raw)})
	return b
}

func featureJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func validFeature(feature string) bool {
	switch feature {
	case FeatureVulnKB, FeatureNuclei, FeatureFingerprint:
		return true
	}
	return false
}

func parseFeatureCallTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, true
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// GET /api/feature-calls?feature=&action=&source=&status=&q=&from=&to=&page=&size=
func (s *Server) getFeatureCalls(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	feature := strings.TrimSpace(q.Get("feature"))
	if feature != "" && !validFeature(feature) {
		writeErr(w, 400, "invalid feature")
		return
	}
	from, ok := parseFeatureCallTime(q.Get("from"))
	if !ok {
		writeErr(w, 400, "invalid from")
		return
	}
	to, ok := parseFeatureCallTime(q.Get("to"))
	if !ok {
		writeErr(w, 400, "invalid to")
		return
	}
	page := atoiDefault(q.Get("page"), 1)
	if page < 1 {
		page = 1
	}
	size := atoiDefault(q.Get("size"), 50)
	if size < 1 {
		size = 50
	}
	items, total, err := pg.ListFeatureCalls(db.FeatureCallFilter{
		Feature: feature,
		Action:  strings.TrimSpace(q.Get("action")),
		Source:  strings.TrimSpace(q.Get("source")),
		Status:  strings.TrimSpace(q.Get("status")),
		Query:   strings.TrimSpace(q.Get("q")),
		From:    from,
		To:      to,
		Page:    page - 1,
		Size:    size,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"items": items, "total": total, "page": page, "size": size,
	})
}

// GET /api/feature-calls/stats?feature=&from=&to=
func (s *Server) getFeatureCallStats(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	feature := strings.TrimSpace(q.Get("feature"))
	if feature != "" && !validFeature(feature) {
		writeErr(w, 400, "invalid feature")
		return
	}
	from, ok := parseFeatureCallTime(q.Get("from"))
	if !ok {
		writeErr(w, 400, "invalid from")
		return
	}
	to, ok := parseFeatureCallTime(q.Get("to"))
	if !ok {
		writeErr(w, 400, "invalid to")
		return
	}
	stats, err := pg.FeatureCallStats(feature, from, to)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"stats": stats})
}

// GET /api/feature-calls/{id}
func (s *Server) getFeatureCall(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	call, err := pg.GetFeatureCall(id)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, map[string]any{"call": call})
}

// startFeatureCallPruner 每天清理一次超过保留期的历史。写历史是 best-effort，
// 清理失败同样只记日志。
func (s *Server) startFeatureCallPruner() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		prune := func() {
			cutoff := time.Now().AddDate(0, 0, -featureCallRetentionDays)
			n, err := s.m.pg.PruneFeatureCalls(cutoff)
			if err != nil {
				log.Printf("[featurecall] prune: %v", err)
				return
			}
			if n > 0 {
				log.Printf("[featurecall] pruned %d rows older than %d days", n, featureCallRetentionDays)
			}
		}
		prune()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				prune()
			}
		}
	}()
}

// featureToolSpec 描述一个 Agent 工具如何落到调用历史。
type featureToolSpec struct {
	Feature   string
	Action    string
	Summarize func(input json.RawMessage, res actool.Result) (query, summary string)
}

var (
	reHitCount        = regexp.MustCompile(`命中 (\d+) 条`)
	reNucleiScan      = regexp.MustCompile(`nuclei 扫描完成：(\d+) 命中 / (\d+) 目标 / ([^，\n]+)，耗时 ([^\n]+)`)
	reFingerprintScan = regexp.MustCompile(`扫描 (\d+) 目标,规则命中 (\d+) 条`)
)

func featureToolSpecFor(toolKey string) *featureToolSpec {
	switch toolKey {
	case "search_vuln_kb":
		return &featureToolSpec{Feature: FeatureVulnKB, Action: "lookup", Summarize: summarizeVulnKBSearch}
	case "nuclei_scan":
		return &featureToolSpec{Feature: FeatureNuclei, Action: "scan", Summarize: summarizeNucleiScan}
	case "nuclei_template_search":
		return &featureToolSpec{Feature: FeatureNuclei, Action: "template_search", Summarize: summarizeNucleiTemplateSearch}
	case "nuclei_update":
		return &featureToolSpec{Feature: FeatureNuclei, Action: "update", Summarize: summarizeNucleiUpdate}
	case "fingerprint_scan":
		return &featureToolSpec{Feature: FeatureFingerprint, Action: "scan", Summarize: summarizeFingerprintScan}
	}
	return nil
}

func summarizeVulnKBSearch(input json.RawMessage, res actool.Result) (string, string) {
	q := jsonStringField(input, "q")
	text := res.Flatten()
	if n := firstIntMatch(reHitCount, text); n != "" {
		if q == "" {
			return "", fmt.Sprintf("漏洞库查询命中 %s 条", n)
		}
		return q, fmt.Sprintf("查询「%s」命中 %s 条", q, n)
	}
	return q, featureFirstLine(text)
}

func summarizeNucleiScan(input json.RawMessage, res actool.Result) (string, string) {
	targets := jsonStringSliceField(input, "targets")
	query := strings.Join(targets, ", ")
	query = truncateRunes(query, 512)
	text := res.Flatten()
	if m := reNucleiScan.FindStringSubmatch(text); len(m) > 1 {
		return query, fmt.Sprintf("扫描 %s 个目标，命中 %s 条（%s，耗时 %s）", m[2], m[1], m[3], m[4])
	}
	return query, featureFirstLine(text)
}

func summarizeNucleiTemplateSearch(input json.RawMessage, res actool.Result) (string, string) {
	q := jsonStringField(input, "q")
	text := res.Flatten()
	if n := firstIntMatch(reHitCount, text); n != "" {
		if q == "" {
			return "", fmt.Sprintf("模板检索命中 %s 条", n)
		}
		return q, fmt.Sprintf("检索「%s」命中 %s 条", q, n)
	}
	return q, featureFirstLine(text)
}

func summarizeNucleiUpdate(_ json.RawMessage, res actool.Result) (string, string) {
	return "", featureFirstLine(res.Flatten())
}

func summarizeFingerprintScan(input json.RawMessage, res actool.Result) (string, string) {
	targets := jsonStringSliceField(input, "targets")
	query := truncateRunes(strings.Join(targets, ", "), 512)
	text := res.Flatten()
	if m := reFingerprintScan.FindStringSubmatch(text); len(m) > 1 {
		return query, fmt.Sprintf("扫描 %s 个目标，规则命中 %s 条", m[1], m[2])
	}
	return query, featureFirstLine(text)
}

func firstIntMatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func featureFirstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "完成"
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return truncateRunes(s, 300)
}

func jsonMap(raw json.RawMessage) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	return m
}

func jsonStringField(raw json.RawMessage, key string) string {
	v, _ := jsonMap(raw)[key].(string)
	return strings.TrimSpace(v)
}

func jsonStringSliceField(raw json.RawMessage, key string) []string {
	rawV, ok := jsonMap(raw)[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(rawV))
	for _, v := range rawV {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func jsonIntField(raw json.RawMessage, key string) int64 {
	switch v := jsonMap(raw)[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
}

// recordMeteredFeatureCall 由 meteredTool 在 Agent 工具调用结束后调用。
func recordMeteredFeatureCall(rec featureCallRecorder, spec *featureToolSpec, agentKey string, ri agent.RunInfo, input json.RawMessage, res actool.Result, callErr error, dur time.Duration) {
	if rec == nil || spec == nil {
		return
	}
	query, summary := spec.Summarize(input, res)
	status := "ok"
	errText := ""
	if callErr != nil {
		status = "error"
		errText = callErr.Error()
	}
	if res.IsError {
		status = "error"
		if errText == "" {
			errText = res.Flatten()
		}
	}
	if summary == "" {
		summary = spec.Action
	}
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	output, _ := json.Marshal(map[string]any{
		"output": truncateRunes(res.Flatten(), 8000),
	})
	c := db.FeatureCall{
		Feature:       spec.Feature,
		Action:        spec.Action,
		Source:        "agent",
		Status:        status,
		Actor:         agentKey,
		TaskID:        ri.TaskID,
		ExplorationID: ri.ExplorationID,
		IntentID:      ri.IntentID,
		SessionID:     ri.SessionID,
		Query:         query,
		Summary:       summary,
		Request:       input,
		Result:        output,
		Error:         errText,
		DurationMS:    int(dur.Milliseconds()),
	}
	if pid := jsonIntField(input, "project_id"); pid > 0 {
		c.ProjectID = pid
	}
	c.Actor = truncateRunes(c.Actor, 256)
	c.Query = truncateRunes(c.Query, 1024)
	c.Summary = truncateRunes(c.Summary, 1024)
	c.Error = truncateRunes(c.Error, 4096)
	c.Request = truncateFeatureJSON(c.Request, featureCallMaxText)
	c.Result = truncateFeatureJSON(c.Result, featureCallMaxText)
	if err := rec.InsertFeatureCall(&c); err != nil {
		log.Printf("[featurecall] insert %s/%s: %v", c.Feature, c.Action, err)
	}
}
