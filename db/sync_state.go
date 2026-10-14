package db

import (
	"context"
	"database/sql"
	"time"
)

// SyncState 是一个 (datasource, asset_type) 的增量同步水位。Watermark 存上游
// 原生字符串时间（"2006-01-02 15:04:05"，节点时区），与响应体同源比较；last_result
// 是最近一轮的人类可读摘要，truncated 必须留痕（上游 5000/型上限截断）。
type SyncState struct {
	DatasourceID int64
	AssetType    string
	Watermark    string
	LastRunAt    *time.Time
	LastResult   string
	Truncated    bool
	UpdatedAt    time.Time
	// 每日对账字段（施工单变更1兜底）：upstream_total 是最近一次对账的上游
	// count_assets 快照；inc_taken 是自上次对账以来增量拉取的条数累计。
	UpstreamTotal int
	IncTaken      int
}

// SyncStateFor 返回指定 (datasource, type) 的水位；不存在时返回零值（首刷）。
func (d *DB) SyncStateFor(ctx context.Context, datasourceID int64, assetType string) (*SyncState, error) {
	row := d.QueryRowContext(ctx, `SELECT watermark, last_run_at, COALESCE(last_result,''), truncated, updated_at,
		COALESCE(upstream_total,0), COALESCE(inc_taken,0)
		FROM sync_state WHERE datasource_id=$1 AND asset_type=$2`, datasourceID, assetType)
	st := &SyncState{DatasourceID: datasourceID, AssetType: assetType}
	if err := row.Scan(&st.Watermark, &st.LastRunAt, &st.LastResult, &st.Truncated, &st.UpdatedAt, &st.UpstreamTotal, &st.IncTaken); err != nil {
		if err == sql.ErrNoRows {
			return st, nil
		}
		return nil, err
	}
	return st, nil
}

// LatestSyncRun 返回全表最近一次成功同步的时间（AssetSummary 的新鲜度标注用）。
func (d *DB) LatestSyncRun(ctx context.Context) (*time.Time, error) {
	var t *time.Time
	if err := d.QueryRowContext(ctx, `SELECT max(last_run_at) FROM sync_state`).Scan(&t); err != nil {
		return nil, err
	}
	return t, nil
}

// ListSyncState 返回一个数据源的全部水位行（状态接口展示增量健康度用）。
func (d *DB) ListSyncState(ctx context.Context, datasourceID int64) ([]*SyncState, error) {
	rows, err := d.QueryContext(ctx, `SELECT datasource_id, asset_type, watermark, last_run_at,
		COALESCE(last_result,''), truncated, updated_at, COALESCE(upstream_total,0), COALESCE(inc_taken,0)
		FROM sync_state WHERE datasource_id=$1 ORDER BY asset_type`, datasourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SyncState
	for rows.Next() {
		st := &SyncState{}
		if err := rows.Scan(&st.DatasourceID, &st.AssetType, &st.Watermark, &st.LastRunAt, &st.LastResult, &st.Truncated, &st.UpdatedAt, &st.UpstreamTotal, &st.IncTaken); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// SaveSyncState upsert 一行水位。watermark 只前进不后退：传入值若早于现存值
// （字符串同源比较），保留现存值——防止一轮空结果把水位打回石器时代。
func (d *DB) SaveSyncState(ctx context.Context, st *SyncState) error {
	_, err := d.ExecContext(ctx, `INSERT INTO sync_state(datasource_id,asset_type,watermark,last_run_at,last_result,truncated,updated_at,upstream_total,inc_taken)
		VALUES ($1,$2,$3,now(),$4,$5,now(),$6,$7)
		ON CONFLICT (datasource_id,asset_type) DO UPDATE SET
			watermark      = CASE WHEN EXCLUDED.watermark > sync_state.watermark THEN EXCLUDED.watermark ELSE sync_state.watermark END,
			last_run_at    = now(),
			last_result    = EXCLUDED.last_result,
			truncated      = EXCLUDED.truncated,
			updated_at     = now(),
			upstream_total = EXCLUDED.upstream_total,
			inc_taken      = EXCLUDED.inc_taken`,
		st.DatasourceID, st.AssetType, st.Watermark, st.LastResult, st.Truncated, st.UpstreamTotal, st.IncTaken)
	return err
}

// UpdateSyncCounters 对账回写：只动 upstream_total / inc_taken，不碰水位与
// last_run_at（对账不是一轮同步，不该伪造新鲜度）。
func (d *DB) UpdateSyncCounters(ctx context.Context, datasourceID int64, assetType string, upstreamTotal, incTaken int) error {
	_, err := d.ExecContext(ctx, `UPDATE sync_state SET upstream_total=$3, inc_taken=$4, updated_at=now()
		WHERE datasource_id=$1 AND asset_type=$2`, datasourceID, assetType, upstreamTotal, incTaken)
	return err
}

// ResetSyncWatermark 清空水位（对账判定增量失明后的自愈：下一轮自动退化首刷
// 全量重拉，幂等 upsert 吸收重复）。刻意绕开 SaveSyncState 的"只前进"语义——
// 重置就是要后退。
func (d *DB) ResetSyncWatermark(ctx context.Context, datasourceID int64, assetType string) error {
	_, err := d.ExecContext(ctx, `UPDATE sync_state SET watermark='', updated_at=now()
		WHERE datasource_id=$1 AND asset_type=$2`, datasourceID, assetType)
	return err
}
