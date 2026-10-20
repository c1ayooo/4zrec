package db

import (
	"fmt"
	"time"
)

// VulnLibraryEntry 是「漏洞库」统一列表的一行：1day 打击库与自动抓取情报流
// 共用一个视图，source 区分来源；两张底表保持独立，详情字段各自保留。
type VulnLibraryEntry struct {
	Source      string    `json:"source"` // 1day | intel
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	Product     string    `json:"product,omitempty"`
	VulnType    string    `json:"vuln_type,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	CVE         string    `json:"cve,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Disclosure  string    `json:"disclosure,omitempty"`
	SourceName  string    `json:"source_name,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

const vulnLibraryCTE = `
WITH lib AS (
  SELECT '1day'::text AS source, id, title, product, vuln_type, ''::text AS severity,
         COALESCE(cve,'') AS cve, COALESCE(fingerprint,'') AS fingerprint,
         ''::text AS disclosure, ''::text AS source_name, created_at
  FROM vuln_kb
  UNION ALL
  SELECT 'intel'::text, id, COALESCE(NULLIF(title_zh,''), title), ''::text, ''::text, COALESCE(severity,''),
         COALESCE(cve,''), ''::text, COALESCE(disclosure,''), COALESCE(source,''), created_at
  FROM vuln_intel
)`

const vulnLibraryWhere = `
WHERE ($1 = '' OR source = $1)
  AND ($2 = '' OR title ILIKE $2 OR product ILIKE $2 OR cve ILIKE $2
       OR fingerprint ILIKE $2 OR source_name ILIKE $2)`

// ListVulnLibrary 分页检索统一漏洞库。source 为空表示全部，否则 1day / intel；
// q 模糊匹配标题/产品/CVE/指纹/情报来源。按入库时间倒序。
func (d *DB) ListVulnLibrary(q, source string, page, size int) ([]VulnLibraryEntry, int, error) {
	if size <= 0 {
		size = 50
	}
	if page < 0 {
		page = 0
	}
	pattern := ""
	if q != "" {
		pattern = "%" + q + "%"
	}

	var total int
	if err := d.QueryRow(vulnLibraryCTE+` SELECT COUNT(*) FROM lib`+vulnLibraryWhere,
		source, pattern).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := vulnLibraryCTE + `
SELECT source, id, title, product, vuln_type, severity, cve, fingerprint,
       disclosure, source_name, created_at
FROM lib` + vulnLibraryWhere + fmt.Sprintf(`
ORDER BY created_at DESC NULLS LAST, source, id DESC
LIMIT $3 OFFSET $4`)

	rows, err := d.Query(dataQ, source, pattern, size, page*size)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []VulnLibraryEntry{}
	for rows.Next() {
		var e VulnLibraryEntry
		if err := rows.Scan(&e.Source, &e.ID, &e.Title, &e.Product, &e.VulnType,
			&e.Severity, &e.CVE, &e.Fingerprint, &e.Disclosure, &e.SourceName,
			&e.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}
