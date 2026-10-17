// spacemap_results.go 空间测绘结果页查询:按引擎(source 标注)筛选的资产分页。
// source 由导入通道写入(引擎展示名),null=本地发现不在本页范围。
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SpacemapResultRow 结果页一行。
type SpacemapResultRow struct {
	ID           int64     `json:"id"`
	Type         string    `json:"type"`
	Label        string    `json:"label"`
	Port         int       `json:"port,omitempty"`
	Title        string    `json:"title"`
	Source       string    `json:"source"`
	Authz        *string   `json:"authz,omitempty"`
	Technologies []string  `json:"technologies"`
	ProjectID    *int64    `json:"project_id,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
}

const spacemapResultCols = `a.id, a.type,
	COALESCE(a.url, a.domain, a.ip, a.app_name, a.root_domain, '') AS label,
	COALESCE(a.port, 0), COALESCE(a.page_title, ''), COALESCE(a.source, ''), a.authz,
	COALESCE(array_to_json(a.technologies)::text, '[]'), a.project_id, a.last_seen`

// SpacemapResultsPage 按引擎筛选(source 精确=引擎展示名)的分页结果。
// engine 空=全部测绘来源;typ 资产类型可选。
func (d *DB) SpacemapResultsPage(ctx context.Context, engine, typ string, projectID int64, limit, offset int) ([]SpacemapResultRow, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where := `a.source IS NOT NULL`
	args := []any{}
	if engine != "" {
		args = append(args, engine)
		where += ` AND a.source=$` + fmt.Sprintf("%d", len(args))
	}
	if typ != "" {
		args = append(args, typ)
		where += ` AND a.type=$` + fmt.Sprintf("%d", len(args))
	}
	if projectID > 0 {
		args = append(args, projectID)
		where += ` AND a.project_id=$` + fmt.Sprintf("%d", len(args))
	}
	var total int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM assets a WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	q := `SELECT ` + spacemapResultCols + ` FROM assets a WHERE ` + where +
		` ORDER BY a.last_seen DESC LIMIT $` + fmt.Sprintf("%d", len(args)-1) + ` OFFSET $` + fmt.Sprintf("%d", len(args))
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]SpacemapResultRow, 0, limit)
	for rows.Next() {
		var r SpacemapResultRow
		var techRaw string
		if err := rows.Scan(&r.ID, &r.Type, &r.Label, &r.Port, &r.Title, &r.Source, &r.Authz, &techRaw, &r.ProjectID, &r.LastSeen); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal([]byte(techRaw), &r.Technologies)
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// StampAssetSource 给资产行打来源标注(已有时不覆盖)。
func (d *DB) StampAssetSource(ctx context.Context, id int64, source string) {
	if source == "" || id <= 0 {
		return
	}
	_, _ = d.ExecContext(ctx, `UPDATE assets SET source=$2 WHERE id=$1 AND (source IS NULL OR source='')`, id, source)
}

// StampAssetSourceQuery 记录资产来自哪条测绘查询(如 Quake 的 cert:"huya.com")。
// 存在 extra.source_query 里,已有值不覆盖(更早的具体查询优先)。审批页据此
// 展示出处,人工才能判断该资产是否落在授权范围。
func (d *DB) StampAssetSourceQuery(ctx context.Context, id int64, query string) {
	query = strings.TrimSpace(query)
	if query == "" || id <= 0 {
		return
	}
	_, _ = d.ExecContext(ctx, `
UPDATE assets
SET extra = COALESCE(extra, '{}'::jsonb) || jsonb_build_object('source_query', $2::text)
WHERE id=$1 AND NOT (COALESCE(extra, '{}'::jsonb) ? 'source_query')`, id, query)
}
