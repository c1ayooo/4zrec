package db

import (
	"strings"
	"time"
)

// 情报流水线阶段标记的写回载荷。零值字段不覆盖(只补缺/只置位语义),与
// VulnIntelEnrich 同一约定;阶段位(analyzed/localized/templated)是显式布尔,
// 只有真正跑完那一步才置 1。
type VulnIntelAnalysisStage struct {
	VulnIntelID int64

	// 长文本产物,写 vuln_intel_analysis 旁表。空串不覆盖已有内容。
	Principle      string
	AttackScope    string
	DescriptionZh  string
	PocCode        string
	PocLang        string
	PocOrigin      string // ai | upstream | none
	NucleiTemplate string
	Model          string

	// 阶段位:true 才写对应时间戳。
	Analyzed  bool
	Localized bool
	Templated bool

	TitleZh string // 短标题进 vuln_intel 主表
}

// IntelAnalysis 是 vuln_intel_analysis 旁表的完整读模型(详情接口用)。
type IntelAnalysis struct {
	VulnIntelID  int64     `json:"vuln_intel_id"`
	Principle    string    `json:"principle"`
	AttackScope  string    `json:"attack_scope"`
	DescriptionZh string   `json:"description_zh"`
	PocCode      string    `json:"poc_code"`
	PocLang      string    `json:"poc_lang"`
	PocOrigin    string    `json:"poc_origin"`
	NucleiTemplate string  `json:"nuclei_template"`
	Model        string    `json:"model"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// SaveIntelAnalysisStage 把一次分析/中文化/模板化的产物落库。主表写阶段位
// 与短标题,旁表写长文本。两个写在同一事务里,避免出现「标记已分析但没有
// 产物」的中间态。
func (d *DB) SaveIntelAnalysisStage(s VulnIntelAnalysisStage) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`
INSERT INTO vuln_intel_analysis(vuln_intel_id, principle, attack_scope, description_zh,
                               poc_code, poc_lang, poc_origin, nuclei_tpl, model, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now())
ON CONFLICT (vuln_intel_id) DO UPDATE SET
  principle      = CASE WHEN $2 <> '' THEN $2 ELSE vuln_intel_analysis.principle END,
  attack_scope   = CASE WHEN $3 <> '' THEN $3 ELSE vuln_intel_analysis.attack_scope END,
  description_zh = CASE WHEN $4 <> '' THEN $4 ELSE vuln_intel_analysis.description_zh END,
  poc_code       = CASE WHEN $5 <> '' THEN $5 ELSE vuln_intel_analysis.poc_code END,
  poc_lang       = CASE WHEN $6 <> '' THEN $6 ELSE vuln_intel_analysis.poc_lang END,
  poc_origin     = CASE WHEN $7 <> '' THEN $7 ELSE vuln_intel_analysis.poc_origin END,
  nuclei_tpl     = CASE WHEN $8 <> '' THEN $8 ELSE vuln_intel_analysis.nuclei_tpl END,
  model          = CASE WHEN $9 <> '' THEN $9 ELSE vuln_intel_analysis.model END,
  updated_at     = now()`,
		s.VulnIntelID, s.Principle, s.AttackScope, s.DescriptionZh,
		s.PocCode, s.PocLang, s.PocOrigin, s.NucleiTemplate, s.Model,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(`
UPDATE vuln_intel SET
  title_zh       = CASE WHEN $2 <> '' THEN $2 ELSE title_zh END,
  localized_at   = CASE WHEN $3 THEN now() ELSE localized_at END,
  analyzed_at    = CASE WHEN $4 THEN now() ELSE analyzed_at END,
  nuclei_tpl_at  = CASE WHEN $5 THEN now() ELSE nuclei_tpl_at END,
  analysis_error = ''
WHERE id = $1`,
		s.VulnIntelID, s.TitleZh, s.Localized, s.Analyzed, s.Templated,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// SetIntelAnalysisError 记录一次失败的原因,供详情页展示与人工重试。
// 不写 analyzed_at —— 下一轮还会把它挑出来重试。
func (d *DB) SetIntelAnalysisError(id int64, msg string) error {
	msg = strings.TrimSpace(msg)
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_, err := d.Exec(`UPDATE vuln_intel SET analysis_error = $2 WHERE id = $1`, id, msg)
	return err
}

// GetIntelAnalysis 读单条情报的分析产物。
func (d *DB) GetIntelAnalysis(id int64) (*IntelAnalysis, error) {
	a := &IntelAnalysis{}
	err := d.QueryRow(`
SELECT vuln_intel_id, principle, attack_scope, description_zh, poc_code, poc_lang,
       poc_origin, nuclei_tpl, model, updated_at
FROM vuln_intel_analysis WHERE vuln_intel_id = $1`, id,
	).Scan(&a.VulnIntelID, &a.Principle, &a.AttackScope, &a.DescriptionZh,
		&a.PocCode, &a.PocLang, &a.PocOrigin, &a.NucleiTemplate, &a.Model, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// PendingIntelAnalysis 挑待分析条目:未分析或超 7 天,且标题+描述有实质内容。
// 返回带富化字段的读模型 —— 分析要参考 github_poc 判断是否已有上游 PoC。
// 与 PendingVulnIntel(GitHub PoC 富化)并列,两条链互不干扰。
func (d *DB) PendingIntelAnalysis(limit int) ([]EnrichedVulnIntel, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := d.Query(`
SELECT v.id, v.title, COALESCE(v.description,''), COALESCE(v.severity,''), COALESCE(v.cve,''),
       COALESCE(v.disclosure,''), COALESCE(v.solutions,''), COALESCE(v.source,''),
       COALESCE(v.source_url,''), v.tags, v.refs, v.created_at, v.updated_at,
       v.github_poc, v.cvss_score, COALESCE(v.cvss_vector,''), v.cwes, v.affected,
       v.lab_only, v.enriched_at,
       COALESCE(v.title_zh,''), v.analyzed_at, v.localized_at,
       COALESCE(v.nuclei_tpl_id,''), v.nuclei_tpl_at, COALESCE(v.analysis_error,'')
FROM vuln_intel v
WHERE (v.analyzed_at IS NULL OR v.analyzed_at < now() - interval '7 days')
  AND length(COALESCE(v.description,'') || COALESCE(v.title,'')) >= 8
ORDER BY v.analyzed_at NULLS FIRST, v.created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnrichedVulnIntel{}
	for rows.Next() {
		v := EnrichedVulnIntel{}
		if err := rows.Scan(&v.ID, &v.Title, &v.Description, &v.Severity, &v.CVE,
			&v.Disclosure, &v.Solutions, &v.Source, &v.SourceURL, &v.Tags, &v.Refs,
			&v.CreatedAt, &v.UpdatedAt,
			&v.GithubPoc, &v.CvssScore, &v.CvssVector, &v.Cwes, &v.Affected,
			&v.LabOnly, &v.EnrichedAt,
			&v.TitleZh, &v.AnalyzedAt, &v.LocalizedAt,
			&v.NucleiTplID, &v.NucleiTplAt, &v.AnalysisError); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// IntelAnalysisPendingCount 统计待分析条目数(状态接口用)。
func (d *DB) IntelAnalysisPendingCount() (int, error) {
	var n int
	err := d.QueryRow(`
SELECT COUNT(*) FROM vuln_intel
WHERE (analyzed_at IS NULL OR analyzed_at < now() - interval '7 days')
  AND length(COALESCE(description,'') || COALESCE(title,'')) >= 8`).Scan(&n)
	return n, err
}

// IntelAnalyzedCount 统计已产出分析产物的条目数(状态接口用)。
func (d *DB) IntelAnalyzedCount() (int, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(*) FROM vuln_intel WHERE analyzed_at IS NOT NULL`).Scan(&n)
	return n, err
}
