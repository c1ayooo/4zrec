// recon_runs.go 主动测绘流水线的运行记录 CRUD。异步 goroutine 的事实源:
// 每阶段结束回写进度,终态回写 done/failed;recon_results 工具与前端都读这里。
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// splitDomains 拆逗号拼接的主域列(TEXT 存储)。
func splitDomains(joined string) []string {
	var out []string
	for _, d := range strings.Split(joined, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// ReconRun 一行运行记录。
type ReconRun struct {
	ID         int64           `json:"id"`
	ProjectID  *int64          `json:"project_id,omitempty"`
	ScheduleID *int64          `json:"schedule_id,omitempty"`
	Domains    []string        `json:"domains"`
	Config     json.RawMessage `json:"config"`
	Status     string          `json:"status"` // running|done|failed
	Stage      string          `json:"stage"`
	Stats      json.RawMessage `json:"stats"`
	Error      string          `json:"error,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

const reconRunCols = `id, project_id, schedule_id, domains, config, status, stage, stats, error, created_at, finished_at`

// CreateReconRun 建一行 running 记录并返回 id。
func (d *DB) CreateReconRun(ctx context.Context, projectID int64, domains []string, config json.RawMessage) (int64, error) {
	return d.CreateReconRunForSchedule(ctx, projectID, 0, domains, config)
}

// CreateReconRunForSchedule 周期任务发起的运行(schedule_id>0 时关联)。
func (d *DB) CreateReconRunForSchedule(ctx context.Context, projectID, scheduleID int64, domains []string, config json.RawMessage) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO recon_runs(project_id, schedule_id, domains, config)
VALUES (NULLIF($1,0), NULLIF($2,0), $3, COALESCE($4,'{}'::jsonb))
RETURNING id`, projectID, scheduleID, strings.Join(domains, ","), config).Scan(&id)
	return id, err
}

// ListReconRunsForSchedule 某周期任务的运行历史(倒序)。
func (d *DB) ListReconRunsForSchedule(ctx context.Context, scheduleID int64, limit int) ([]*ReconRun, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := d.QueryContext(ctx, `SELECT `+reconRunCols+` FROM recon_runs
		WHERE schedule_id=$1 ORDER BY id DESC LIMIT $2`, scheduleID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ReconRun
	for rows.Next() {
		r := &ReconRun{}
		var domains string
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.ScheduleID, &domains, &r.Config, &r.Status, &r.Stage, &r.Stats, &r.Error, &r.CreatedAt, &r.FinishedAt); err != nil {
			return nil, err
		}
		r.Domains = splitDomains(domains)
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateReconRunProgress 回写进度(阶段名 + 统计;status 保持 running)。
func (d *DB) UpdateReconRunProgress(ctx context.Context, id int64, stage string, stats json.RawMessage) error {
	_, err := d.ExecContext(ctx, `UPDATE recon_runs SET stage=$2, stats=COALESCE($3,stats) WHERE id=$1`,
		id, stage, stats)
	return err
}

// FinishReconRun 置终态。errMsg 非空 → failed。
func (d *DB) FinishReconRun(ctx context.Context, id int64, stage string, stats json.RawMessage, errMsg string) error {
	status := "done"
	if errMsg != "" {
		status = "failed"
	}
	_, err := d.ExecContext(ctx, `
UPDATE recon_runs SET status=$2, stage=$3, stats=COALESCE($4,stats), error=$5, finished_at=now() WHERE id=$1`,
		id, status, stage, stats, errMsg)
	return err
}

// GetReconRun 单行。
func (d *DB) GetReconRun(ctx context.Context, id int64) (*ReconRun, error) {
	r := &ReconRun{}
	var domains string
	err := d.QueryRowContext(ctx, `SELECT `+reconRunCols+` FROM recon_runs WHERE id=$1`, id).
		Scan(&r.ID, &r.ProjectID, &r.ScheduleID, &domains, &r.Config, &r.Status, &r.Stage, &r.Stats, &r.Error, &r.CreatedAt, &r.FinishedAt)
	if err != nil {
		return nil, err
	}
	r.Domains = splitDomains(domains)
	return r, nil
}

// ListReconRuns 倒序分页;projectID>0 时按项目过滤。
func (d *DB) ListReconRuns(ctx context.Context, projectID int64, limit, offset int) ([]*ReconRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	q := `SELECT ` + reconRunCols + ` FROM recon_runs`
	args := []any{}
	if projectID > 0 {
		args = append(args, projectID)
		q += ` WHERE project_id=$1`
	}
	args = append(args, limit, offset)
	q += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ReconRun
	for rows.Next() {
		r := &ReconRun{}
		var domains string
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.ScheduleID, &domains, &r.Config, &r.Status, &r.Stage, &r.Stats, &r.Error, &r.CreatedAt, &r.FinishedAt); err != nil {
			return nil, err
		}
		r.Domains = splitDomains(domains)
		out = append(out, r)
	}
	return out, rows.Err()
}
