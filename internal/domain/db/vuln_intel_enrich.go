package db

import (
	"time"
)

// VulnIntelEnrich 一次富化的写回载荷。零值字段不覆盖(只补缺语义)。
type VulnIntelEnrich struct {
	ID              int64
	GithubPoc       string  // JSON 数组文本
	CvssScore       float64 // >0 才写
	CvssVector      string
	Cwes            string // JSON 数组文本
	Affected        string // JSON 数组文本
	LabOnly         bool
	HasLabOnly      bool // lab_only 显式置位才写
	SupplementTitle string
	HasTitle        bool
	Enriched        bool // true = 写 enriched_at(本次富化完成)
}

// PendingVulnIntel 挑待富化条目:带 CVE 且(未富化或超 7 天)。
func (d *DB) PendingVulnIntel(limit int) ([]VulnIntel, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := d.Query(`
SELECT id, unique_key, title, COALESCE(description,''), COALESCE(severity,''), COALESCE(cve,''),
       COALESCE(disclosure,''), COALESCE(solutions,''), COALESCE(source,''),
       COALESCE(source_url,''), tags, refs, created_at, updated_at
FROM vuln_intel
WHERE cve <> '' AND (enriched_at IS NULL OR enriched_at < now() - interval '7 days')
ORDER BY enriched_at NULLS FIRST, created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VulnIntel{}
	for rows.Next() {
		var v VulnIntel
		if err := rows.Scan(&v.ID, &v.UniqueKey, &v.Title, &v.Description, &v.Severity, &v.CVE,
			&v.Disclosure, &v.Solutions, &v.Source, &v.SourceURL, &v.Tags, &v.Refs,
			&v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// EnrichVulnIntel 富化写回。全部字段只补缺:已有非空值不被空值覆盖。
func (d *DB) EnrichVulnIntel(e VulnIntelEnrich) error {
	_, err := d.Exec(`
UPDATE vuln_intel SET
  github_poc   = CASE WHEN $2 <> '[]' THEN $2 ELSE github_poc END,
  cvss_score   = COALESCE($3, cvss_score),
  cvss_vector  = CASE WHEN $4 <> '' THEN $4 ELSE cvss_vector END,
  cwes         = CASE WHEN $5 <> '[]' THEN $5 ELSE cwes END,
  affected     = CASE WHEN $6 <> '[]' THEN $6 ELSE affected END,
  lab_only     = CASE WHEN $7 THEN TRUE ELSE lab_only END,
  title        = CASE WHEN $8 <> '' AND (title = '' OR title = cve OR length(title) < 8) THEN $8 ELSE title END,
  enriched_at  = CASE WHEN $9 THEN now() ELSE enriched_at END
WHERE id = $1`,
		e.ID, e.GithubPoc, nullableFloat(e.CvssScore), e.CvssVector, e.Cwes, e.Affected,
		e.HasLabOnly && e.LabOnly, e.SupplementTitle, e.Enriched)
	return err
}

func nullableFloat(v float64) any {
	if v <= 0 {
		return nil
	}
	return v
}

// VulnIntelPOC 是 github_poc JSON 数组里的一项(前端直接消费)。
type VulnIntelPOC struct {
	FullName    string   `json:"full_name"`
	URL         string   `json:"url"`
	Description string   `json:"description,omitempty"`
	Stars       int      `json:"stars"`
	PushedAt    string   `json:"pushed_at,omitempty"`
	Verdict     string   `json:"verdict,omitempty"`
	TriageScore int      `json:"triage_score,omitempty"`
	Reasons     []string `json:"triage_reasons,omitempty"`
}

// EnrichedVulnIntel 是带富化字段的完整情报记录(列表/详情接口)。
type EnrichedVulnIntel struct {
	VulnIntel
	GithubPoc  string     `json:"github_poc"`
	CvssScore  *float64   `json:"cvss_score"`
	CvssVector string     `json:"cvss_vector"`
	Cwes       string     `json:"cwes"`
	Affected   string     `json:"affected"`
	LabOnly    bool       `json:"lab_only"`
	EnrichedAt *time.Time `json:"enriched_at"`
}
