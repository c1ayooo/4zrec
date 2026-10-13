package db

import (
	"strconv"
	"time"
)

// VulnIntel 是一条自动抓取的漏洞情报(标题/等级/CVE/披露时间/参考链接)。
// 与 VulnKBEntry(1day 打击库)分表:情报回答「新披露了什么」,1day 回答
// 「指纹命中后怎么打」。
type VulnIntel struct {
	ID          int64     `json:"id"`
	UniqueKey   string    `json:"-"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Severity    string    `json:"severity"`
	CVE         string    `json:"cve"`
	Disclosure  string    `json:"disclosure"`
	Solutions   string    `json:"solutions,omitempty"`
	Source      string    `json:"source"`
	SourceURL   string    `json:"source_url"`
	Tags        string    `json:"tags"` // JSON 数组文本
	Refs        string    `json:"refs"` // JSON 数组文本
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UpsertVulnIntel 按唯一键(源:源内ID)入库,返回是否为新记录(xmax=0 表示
// 本次 INSERT 而非 DO UPDATE 命中)。
func (d *DB) UpsertVulnIntel(v VulnIntel) (bool, error) {
	var id int64
	var inserted bool
	err := d.QueryRow(`
INSERT INTO vuln_intel(unique_key, title, description, severity, cve, disclosure,
                       solutions, source, source_url, tags, refs)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (unique_key) DO UPDATE SET
  title=EXCLUDED.title, description=EXCLUDED.description, severity=EXCLUDED.severity,
  cve=EXCLUDED.cve, disclosure=EXCLUDED.disclosure, solutions=EXCLUDED.solutions,
  tags=EXCLUDED.tags, refs=EXCLUDED.refs, updated_at=now()
RETURNING id, (xmax = 0)`,
		v.UniqueKey, v.Title, v.Description, v.Severity, v.CVE, v.Disclosure,
		v.Solutions, v.Source, v.SourceURL, v.Tags, v.Refs,
	).Scan(&id, &inserted)
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// ListVulnIntel 分页列出情报,按入库时间倒序。severity 精确过滤,q 模糊
// 匹配标题/CVE/来源。
func (d *DB) ListVulnIntel(q, severity string, page, size int) ([]VulnIntel, int, error) {
	if size <= 0 {
		size = 50
	}
	if page < 0 {
		page = 0
	}
	where := " WHERE 1=1"
	var args []any
	if q != "" {
		args = append(args, "%"+q+"%")
		where += ` AND (title ILIKE $1 OR cve ILIKE $1 OR source ILIKE $1)`
	}
	if severity != "" {
		args = append(args, severity)
		where += ` AND severity = $` + strconv.Itoa(len(args))
	}
	var total int
	if err := d.QueryRow("SELECT COUNT(*) FROM vuln_intel"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	dataQ := `
SELECT id, title, COALESCE(description,''), COALESCE(severity,''), COALESCE(cve,''),
       COALESCE(disclosure,''), COALESCE(solutions,''), COALESCE(source,''),
       COALESCE(source_url,''), tags, refs, created_at, updated_at
FROM vuln_intel` + where + `
ORDER BY created_at DESC, id DESC
LIMIT ` + strconv.Itoa(size) + " OFFSET " + strconv.Itoa(page*size)
	rows, err := d.Query(dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []VulnIntel{}
	for rows.Next() {
		var v VulnIntel
		if err := rows.Scan(&v.ID, &v.Title, &v.Description, &v.Severity, &v.CVE,
			&v.Disclosure, &v.Solutions, &v.Source, &v.SourceURL, &v.Tags, &v.Refs,
			&v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

