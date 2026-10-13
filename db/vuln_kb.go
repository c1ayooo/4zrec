package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// VulnKBEntry 是漏洞知识库的一条结构化记录,来源为仓库 vulnkb/ 目录下的
// 1day 漏洞 markdown(老 4zreco 项目资产)。导入按 content_hash 幂等。
type VulnKBEntry struct {
	ID          int64     `json:"id"`
	ContentHash string    `json:"-"`
	Title       string    `json:"title"`
	Product     string    `json:"product"`
	VulnType    string    `json:"vuln_type"`
	CVE         string    `json:"cve"`
	Fingerprint string    `json:"fingerprint"`
	RequestLine string    `json:"request_line"`
	Headers     string    `json:"headers"`
	Payload     string    `json:"payload"`
	ResponseSig string    `json:"response_sig"`
	Expected    string    `json:"expected"`
	Body        string    `json:"body,omitempty"`
	SourcePath  string    `json:"source_path"`
	CreatedAt   time.Time `json:"created_at"`
}

// VulnKBTypeCount 是统计接口里「按漏洞类型的条数」。
type VulnKBTypeCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// VulnKBStats 是漏洞库的概览统计。
type VulnKBStats struct {
	Total          int               `json:"total"`
	Products       int               `json:"products"`
	WithCVE        int               `json:"with_cve"`
	WithPayload    int               `json:"with_payload"`
	WithFingerprint int              `json:"with_fingerprint"`
	Types          []VulnKBTypeCount `json:"types"`
}

// UpsertVulnKB 按 content_hash 幂等插入,返回是否为新记录。
func (d *DB) UpsertVulnKB(e VulnKBEntry) (bool, error) {
	var id int64
	err := d.QueryRow(`
INSERT INTO vuln_kb(content_hash, title, product, vuln_type, cve, fingerprint,
                    request_line, headers, payload, response_sig, expected, body, source_path)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (content_hash) DO NOTHING
RETURNING id`,
		e.ContentHash, e.Title, e.Product, e.VulnType, e.CVE, e.Fingerprint,
		e.RequestLine, e.Headers, e.Payload, e.ResponseSig, e.Expected, e.Body, e.SourcePath,
	).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// vulnKBFilter 组装检索条件。q 匹配 title/product/cve/fingerprint 的 ILIKE;
// vulnType 精确(取值来自统计接口,不猜)。
func vulnKBFilter(q, vulnType string) (string, []any, int) {
	where := " WHERE 1=1"
	var args []any
	if q != "" {
		args = append(args, "%"+q+"%")
		where += fmt.Sprintf(" AND (title ILIKE $%d OR product ILIKE $%d OR cve ILIKE $%d OR fingerprint ILIKE $%d)",
			len(args), len(args), len(args), len(args))
	}
	if vulnType != "" {
		args = append(args, vulnType)
		where += fmt.Sprintf(" AND vuln_type = $%d", len(args))
	}
	return where, args, len(args)
}

// ListVulnKB 分页检索,列表不带 body(大字段,详情接口才给)。
func (d *DB) ListVulnKB(q, vulnType string, page, size int) ([]VulnKBEntry, int, error) {
	if size <= 0 {
		size = 50
	}
	if page < 0 {
		page = 0
	}
	where, args, argN := vulnKBFilter(q, vulnType)

	var total int
	if err := d.QueryRow("SELECT COUNT(*) FROM vuln_kb"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := `
SELECT id, title, product, vuln_type, COALESCE(cve,''), COALESCE(fingerprint,''),
       COALESCE(request_line,''), COALESCE(headers,''), COALESCE(payload,''),
       COALESCE(response_sig,''), COALESCE(expected,''), source_path, created_at
FROM vuln_kb` + where + fmt.Sprintf(`
ORDER BY id DESC
LIMIT $%d OFFSET $%d`, argN+1, argN+2)

	args = append(args, size, page*size)
	rows, err := d.Query(dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []VulnKBEntry{}
	for rows.Next() {
		var e VulnKBEntry
		if err := rows.Scan(&e.ID, &e.Title, &e.Product, &e.VulnType, &e.CVE, &e.Fingerprint,
			&e.RequestLine, &e.Headers, &e.Payload, &e.ResponseSig, &e.Expected, &e.SourcePath, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// GetVulnKB 返回单条完整记录(含 body)。
func (d *DB) GetVulnKB(id int64) (*VulnKBEntry, error) {
	var e VulnKBEntry
	err := d.QueryRow(`
SELECT id, title, product, vuln_type, COALESCE(cve,''), COALESCE(fingerprint,''),
       COALESCE(request_line,''), COALESCE(headers,''), COALESCE(payload,''),
       COALESCE(response_sig,''), COALESCE(expected,''), body, source_path, created_at
FROM vuln_kb WHERE id = $1`, id,
	).Scan(&e.ID, &e.Title, &e.Product, &e.VulnType, &e.CVE, &e.Fingerprint,
		&e.RequestLine, &e.Headers, &e.Payload, &e.ResponseSig, &e.Expected, &e.Body, &e.SourcePath, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// VulnKBStats 返回库概览。types 取条数最多的前 30 类(前端下拉用)。
func (d *DB) VulnKBStats() (*VulnKBStats, error) {
	s := &VulnKBStats{Types: []VulnKBTypeCount{}}
	if err := d.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT product),
	COUNT(*) FILTER (WHERE cve <> ''), COUNT(*) FILTER (WHERE payload <> ''),
	COUNT(*) FILTER (WHERE fingerprint <> '') FROM vuln_kb`,
	).Scan(&s.Total, &s.Products, &s.WithCVE, &s.WithPayload, &s.WithFingerprint); err != nil {
		return nil, err
	}
	rows, err := d.Query(`SELECT vuln_type, COUNT(*) FROM vuln_kb
	WHERE vuln_type <> '' GROUP BY vuln_type ORDER BY COUNT(*) DESC, vuln_type LIMIT 30`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t VulnKBTypeCount
		if err := rows.Scan(&t.Name, &t.Count); err != nil {
			return nil, err
		}
		s.Types = append(s.Types, t)
	}
	return s, rows.Err()
}
