// recon_schedules.go 周期采集任务的 CRUD 与到期查询。worker(collect.RunScheduleWorker)
// 每 30s 调 ListDue 拿到期任务;执行后 MarkRan 推进 next_run_at 并按结果维护熔断列。
package db

import (
	"context"
	"encoding/json"
	"time"
)

// ReconSchedule 一条周期采集任务。
type ReconSchedule struct {
	ID           int64           `json:"id"`
	Name         string          `json:"name"`
	Kind         string          `json:"kind"` // engine|pipeline
	Config       json.RawMessage `json:"config"`
	IntervalSec  int             `json:"interval_sec"`
	ProjectID    *int64          `json:"project_id,omitempty"`
	Enabled      bool            `json:"enabled"`
	LastRunAt    *time.Time      `json:"last_run_at,omitempty"`
	NextRunAt    time.Time       `json:"next_run_at"`
	AuthFailures int             `json:"auth_failures"`
	BackoffUntil *time.Time      `json:"backoff_until,omitempty"`
	LastResult   string          `json:"last_result"`
	LastNew      int             `json:"last_new"`
	CreatedAt    time.Time       `json:"created_at"`
}

const reconSchedCols = `id, name, kind, config, interval_sec, project_id, enabled, last_run_at, next_run_at, auth_failures, backoff_until, last_result, last_new, created_at`

func scanReconSchedule(sc interface{ Scan(...any) error }) (*ReconSchedule, error) {
	r := &ReconSchedule{}
	if err := sc.Scan(&r.ID, &r.Name, &r.Kind, &r.Config, &r.IntervalSec, &r.ProjectID, &r.Enabled,
		&r.LastRunAt, &r.NextRunAt, &r.AuthFailures, &r.BackoffUntil, &r.LastResult, &r.LastNew, &r.CreatedAt); err != nil {
		return nil, err
	}
	return r, nil
}

// CreateReconSchedule 建任务。
func (d *DB) CreateReconSchedule(ctx context.Context, s *ReconSchedule) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO recon_schedules(name, kind, config, interval_sec, project_id, next_run_at)
VALUES ($1, $2, COALESCE($3,'{}'::jsonb), $4, NULLIF($5,0), now()) RETURNING id`,
		s.Name, s.Kind, s.Config, s.IntervalSec, deref(s.ProjectID)).Scan(&id)
	return id, err
}

// UpdateReconSchedule 更新可编辑字段(enabled/interval/config/name)。
func (d *DB) UpdateReconSchedule(ctx context.Context, id int64, name string, intervalSec int, config json.RawMessage, enabled bool) error {
	_, err := d.ExecContext(ctx, `
UPDATE recon_schedules SET name=$2, interval_sec=$3, config=COALESCE($4,config), enabled=$5 WHERE id=$1`,
		id, name, intervalSec, config, enabled)
	return err
}

// DeleteReconSchedule 删除。
func (d *DB) DeleteReconSchedule(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM recon_schedules WHERE id=$1`, id)
	return err
}

// SetReconScheduleEnabled 启停。
func (d *DB) SetReconScheduleEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := d.ExecContext(ctx, `
UPDATE recon_schedules SET enabled=$2, next_run_at=CASE WHEN $2 THEN now() ELSE next_run_at END WHERE id=$1`, id, enabled)
	return err
}

// ListDueSchedules 到期任务(enabled + next_run_at<=now + 熔断已过)。
func (d *DB) ListDueSchedules(ctx context.Context) ([]*ReconSchedule, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+reconSchedCols+` FROM recon_schedules
		WHERE enabled AND next_run_at <= now() AND (backoff_until IS NULL OR backoff_until <= now())`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ReconSchedule
	for rows.Next() {
		r, err := scanReconSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListReconSchedules 全量(管理页)。
func (d *DB) ListReconSchedules(ctx context.Context) ([]*ReconSchedule, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+reconSchedCols+` FROM recon_schedules ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ReconSchedule
	for rows.Next() {
		r, err := scanReconSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetReconSchedule 单条。
func (d *DB) GetReconSchedule(ctx context.Context, id int64) (*ReconSchedule, error) {
	r, err := scanReconSchedule(d.QueryRowContext(ctx, `SELECT `+reconSchedCols+` FROM recon_schedules WHERE id=$1`, id))
	if err != nil {
		return nil, err
	}
	return r, nil
}

// MarkScheduleRan 执行收尾:推进 next_run_at;authFailed=true 时熔断指数退避
// (15min→1h→6h→24h 封顶,成功清零——恢复后立即回归正常节奏)。
func (d *DB) MarkScheduleRan(ctx context.Context, id int64, intervalSec int, authFailed bool, result string, newAssets int) error {
	if authFailed {
		var fails int
		if err := d.QueryRowContext(ctx, `SELECT auth_failures FROM recon_schedules WHERE id=$1`, id).Scan(&fails); err != nil {
			return err
		}
		fails++
		backoff := 15 * time.Minute
		switch {
		case fails >= 4:
			backoff = 24 * time.Hour
		case fails == 3:
			backoff = 6 * time.Hour
		case fails == 2:
			backoff = time.Hour
		}
		_, err := d.ExecContext(ctx, `
UPDATE recon_schedules SET last_run_at=now(), next_run_at=now()+make_interval(secs=>$2::int),
	auth_failures=$3, backoff_until=now()+make_interval(secs=>$4::int), last_result=$5, last_new=$6 WHERE id=$1`,
			id, intervalSec, fails, int(backoff.Seconds()), result, newAssets)
		return err
	}
	_, err := d.ExecContext(ctx, `
UPDATE recon_schedules SET last_run_at=now(), next_run_at=now()+make_interval(secs=>$2::int),
	auth_failures=0, backoff_until=NULL, last_result=$3, last_new=$4 WHERE id=$1`,
		id, intervalSec, result, newAssets)
	return err
}

// RunReconScheduleNow 手动触发:立即到期。
func (d *DB) RunReconScheduleNow(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `UPDATE recon_schedules SET next_run_at=now() WHERE id=$1`, id)
	return err
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
