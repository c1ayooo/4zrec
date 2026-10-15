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

// ListVulnIntel 分页列出情报(含富化字段),按入库时间倒序。severity 精确
// 过滤,q 模糊匹配标题/CVE/来源。
func (d *DB) ListVulnIntel(q, severity string, page, size int) ([]EnrichedVulnIntel, int, error) {
	if size <= 0 {
		size = 50
	}
	if page < 0 {
		page = 0
	}
	where := " WHERE 1=1" // 列名不带前缀;dataQ 处统一替换表名
	var args []any
	if q != "" {
		args = append(args, "%"+q+"%")
		where += ` AND (v.title ILIKE $1 OR v.cve ILIKE $1 OR v.source ILIKE $1)`
	}
	if severity != "" {
		args = append(args, severity)
		where += ` AND v.severity = $` + strconv.Itoa(len(args))
	}
	var total int
	if err := d.QueryRow("SELECT COUNT(*) FROM vuln_intel v"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	dataQ := `
SELECT v.id, v.title, COALESCE(v.description,''), COALESCE(v.severity,''), COALESCE(v.cve,''),
       COALESCE(v.disclosure,''), COALESCE(v.solutions,''), COALESCE(v.source,''),
       COALESCE(v.source_url,''), v.tags, v.refs, v.created_at, v.updated_at,
       v.github_poc, v.cvss_score, COALESCE(v.cvss_vector,''), v.cwes, v.affected,
       v.lab_only, v.enriched_at
FROM vuln_intel v` + where + `
ORDER BY v.created_at DESC, v.id DESC
LIMIT ` + strconv.Itoa(size) + " OFFSET " + strconv.Itoa(page*size)
	rows, err := d.Query(dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []EnrichedVulnIntel{}
	for rows.Next() {
		v := EnrichedVulnIntel{}
		if err := rows.Scan(&v.ID, &v.Title, &v.Description, &v.Severity, &v.CVE,
			&v.Disclosure, &v.Solutions, &v.Source, &v.SourceURL, &v.Tags, &v.Refs,
			&v.CreatedAt, &v.UpdatedAt,
			&v.GithubPoc, &v.CvssScore, &v.CvssVector, &v.Cwes, &v.Affected,
			&v.LabOnly, &v.EnrichedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}
