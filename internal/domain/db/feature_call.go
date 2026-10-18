package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// FeatureCall 是漏洞库 / nuclei 模板 / 指纹规则库的一次语义化调用记录。
// 与 tool_usage 分离：tool_usage 只做工具目录的累计计数，这里保留查询条件、
// 结果摘要和耗时，供三个功能页的“调用历史”tab 展示。
type FeatureCall struct {
	ID            int64           `json:"id"`
	TS            time.Time       `json:"ts"`
	Feature       string          `json:"feature"` // vulnkb | nuclei | fingerprint
	Action        string          `json:"action"`  // search | view | scan | sync | refresh | create | update | delete | validate
	Source        string          `json:"source"`  // web | agent | schedule | system
	Status        string          `json:"status"`  // ok | error | denied
	Actor         string          `json:"actor,omitempty"`
	TaskID        int64           `json:"task_id,omitempty"`
	ExplorationID int64           `json:"exploration_id,omitempty"`
	IntentID      int64           `json:"intent_id,omitempty"`
	SessionID     string          `json:"session_id,omitempty"`
	ProjectID     int64           `json:"project_id,omitempty"`
	RefType       string          `json:"ref_type,omitempty"`
	RefID         string          `json:"ref_id,omitempty"`
	Query         string          `json:"query,omitempty"`
	Summary       string          `json:"summary"`
	Request       json.RawMessage `json:"request,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
	Error         string          `json:"error,omitempty"`
	DurationMS    int             `json:"duration_ms"`
}

// FeatureCallFilter 是历史列表的检索条件。零值字段不过滤。
type FeatureCallFilter struct {
	Feature string
	Action  string
	Source  string
	Status  string
	Query   string
	From    time.Time
	To      time.Time
	Page    int
	Size    int
}

// FeatureCallStats 是一个功能在时间窗口内的概览。
type FeatureCallStats struct {
	Total         int        `json:"total"`
	OK            int        `json:"ok"`
	Error         int        `json:"error"`
	Denied        int        `json:"denied"`
	AvgDurationMS int        `json:"avg_duration_ms"`
	LastAt        *time.Time `json:"last_at,omitempty"`
}

func normalizeFeatureJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 || !json.Valid(raw) {
		return []byte("{}")
	}
	return raw
}

// InsertFeatureCall 追加一条调用历史。调用方按 best-effort 处理错误，历史写入
// 失败不应中断实际功能。
func (d *DB) InsertFeatureCall(c *FeatureCall) error {
	ts := c.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	feature := c.Feature
	if feature == "" {
		return fmt.Errorf("feature 不能为空")
	}
	action := c.Action
	if action == "" {
		action = "unknown"
	}
	source := c.Source
	if source == "" {
		source = "web"
	}
	status := c.Status
	if status == "" {
		status = "ok"
	}
	_, err := d.Exec(`
INSERT INTO feature_call_log(
    ts, feature, action, source, status, actor, task_id, exploration_id, intent_id,
    session_id, project_id, ref_type, ref_id, query, summary, request, result, error, duration_ms
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		ts, feature, action, source, status,
		nullIfEmpty(c.Actor), nullIfZero(c.TaskID), nullIfZero(c.ExplorationID),
		nullIfZero(c.IntentID), nullIfEmpty(c.SessionID), nullIfZero(c.ProjectID),
		nullIfEmpty(c.RefType), nullIfEmpty(c.RefID), c.Query, c.Summary,
		normalizeFeatureJSON(c.Request), normalizeFeatureJSON(c.Result), c.Error, c.DurationMS,
	)
	return err
}

// featureCallWhere 组装列表/统计共用的过滤条件。
func featureCallWhere(f FeatureCallFilter) (string, []any) {
	where := " WHERE 1=1"
	var args []any
	add := func(v any, clause string) {
		args = append(args, v)
		where += fmt.Sprintf(clause, len(args))
	}
	if f.Feature != "" {
		add(f.Feature, " AND feature = $%d")
	}
	if f.Action != "" {
		add(f.Action, " AND action = $%d")
	}
	if f.Source != "" {
		add(f.Source, " AND source = $%d")
	}
	if f.Status != "" {
		add(f.Status, " AND status = $%d")
	}
	if f.Query != "" {
		args = append(args, "%"+f.Query+"%")
		n := len(args)
		where += fmt.Sprintf(` AND (query ILIKE $%d OR summary ILIKE $%d OR ref_id ILIKE $%d OR actor ILIKE $%d OR error ILIKE $%d)`,
			n, n, n, n, n)
	}
	if !f.From.IsZero() {
		add(f.From, " AND ts >= $%d")
	}
	if !f.To.IsZero() {
		add(f.To, " AND ts < $%d")
	}
	return where, args
}

// ListFeatureCalls 分页检索调用历史。列表不返回 request/result 大字段，
// 详情走 GetFeatureCall。
func (d *DB) ListFeatureCalls(f FeatureCallFilter) ([]FeatureCall, int, error) {
	if f.Size <= 0 {
		f.Size = 50
	}
	if f.Size > 200 {
		f.Size = 200
	}
	if f.Page < 0 {
		f.Page = 0
	}
	where, args := featureCallWhere(f)

	var total int
	if err := d.QueryRow("SELECT COUNT(*) FROM feature_call_log"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := `
SELECT id, ts, feature, action, source, status,
       COALESCE(actor,''), COALESCE(task_id,0), COALESCE(exploration_id,0),
       COALESCE(intent_id,0), COALESCE(session_id,''), COALESCE(project_id,0),
       COALESCE(ref_type,''), COALESCE(ref_id,''), COALESCE(query,''),
       COALESCE(summary,''), COALESCE(error,''), COALESCE(duration_ms,0)
FROM feature_call_log` + where + fmt.Sprintf(`
ORDER BY ts DESC, id DESC
LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)

	args = append(args, f.Size, f.Page*f.Size)
	rows, err := d.Query(dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []FeatureCall{}
	for rows.Next() {
		var c FeatureCall
		if err := rows.Scan(&c.ID, &c.TS, &c.Feature, &c.Action, &c.Source, &c.Status,
			&c.Actor, &c.TaskID, &c.ExplorationID, &c.IntentID, &c.SessionID,
			&c.ProjectID, &c.RefType, &c.RefID, &c.Query, &c.Summary,
			&c.Error, &c.DurationMS); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// GetFeatureCall 返回单条完整记录（含 request/result）。
func (d *DB) GetFeatureCall(id int64) (*FeatureCall, error) {
	var c FeatureCall
	var req, res []byte
	err := d.QueryRow(`
SELECT id, ts, feature, action, source, status,
       COALESCE(actor,''), COALESCE(task_id,0), COALESCE(exploration_id,0),
       COALESCE(intent_id,0), COALESCE(session_id,''), COALESCE(project_id,0),
       COALESCE(ref_type,''), COALESCE(ref_id,''), COALESCE(query,''),
       COALESCE(summary,''), COALESCE(request,'{}'::jsonb), COALESCE(result,'{}'::jsonb),
       COALESCE(error,''), COALESCE(duration_ms,0)
FROM feature_call_log WHERE id = $1`, id,
	).Scan(&c.ID, &c.TS, &c.Feature, &c.Action, &c.Source, &c.Status,
		&c.Actor, &c.TaskID, &c.ExplorationID, &c.IntentID, &c.SessionID,
		&c.ProjectID, &c.RefType, &c.RefID, &c.Query, &c.Summary,
		&req, &res, &c.Error, &c.DurationMS)
	if err != nil {
		return nil, err
	}
	c.Request = json.RawMessage(req)
	c.Result = json.RawMessage(res)
	return &c, nil
}

// FeatureCallStats 返回一个功能在 [from, to) 内的概览。
func (d *DB) FeatureCallStats(feature string, from, to time.Time) (*FeatureCallStats, error) {
	where, args := featureCallWhere(FeatureCallFilter{Feature: feature, From: from, To: to})
	s := &FeatureCallStats{}
	var last sql.NullTime
	err := d.QueryRow(`
SELECT COUNT(*),
       COUNT(*) FILTER (WHERE status = 'ok'),
       COUNT(*) FILTER (WHERE status = 'error'),
       COUNT(*) FILTER (WHERE status = 'denied'),
       COALESCE(AVG(duration_ms), 0)::int,
       MAX(ts)
FROM feature_call_log`+where, args...,
	).Scan(&s.Total, &s.OK, &s.Error, &s.Denied, &s.AvgDurationMS, &last)
	if err != nil {
		return nil, err
	}
	if last.Valid {
		s.LastAt = &last.Time
	}
	return s, nil
}

// PruneFeatureCalls 删除 before 之前的调用历史，返回删除行数。
func (d *DB) PruneFeatureCalls(before time.Time) (int64, error) {
	res, err := d.Exec(`DELETE FROM feature_call_log WHERE ts < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
