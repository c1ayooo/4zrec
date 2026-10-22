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
	PocNote        string // 未生成/不可直接使用的原因
	NucleiTemplate string
	// Fingerprint 是待确认的指纹草稿(code:yaml 两行:分类与匹配表达式)。
	Fingerprint string
	Model       string

	// 阶段位:true 才写对应时间戳。
	Analyzed  bool
	Localized bool
	Templated bool

	TitleZh string // 短标题进 vuln_intel 主表

	// NucleiTplID 是模板落盘后得到的模板 id,同时记进主表(nuclei_tpl_id)供
	// 前端判断「已生成并入库」。Templated=true 但 id 为空 = 只生成了草稿,
	// 还没经人工确认入库。
	NucleiTplID string

	// FingerprintID 同理,对应指纹规则库(fingerprint_rules.id)。
	FingerprintID string
}

// IntelAnalysis 是 vuln_intel_analysis 旁表的完整读模型(详情接口用)。
type IntelAnalysis struct {
	VulnIntelID    int64     `json:"vuln_intel_id"`
	Principle      string    `json:"principle"`
	AttackScope    string    `json:"attack_scope"`
	DescriptionZh  string    `json:"description_zh"`
	PocCode        string    `json:"poc_code"`
	PocLang        string    `json:"poc_lang"`
	PocOrigin      string    `json:"poc_origin"`
	PocNote        string    `json:"poc_note"`
	NucleiTemplate string    `json:"nuclei_template"`
	Fingerprint    string    `json:"fingerprint"`
	FingerprintID  string    `json:"fingerprint_id"`
	Model          string    `json:"model"`
	UpdatedAt      time.Time `json:"updated_at"`
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
                               poc_code, poc_lang, poc_origin, poc_note, nuclei_tpl, fingerprint,
                               fingerprint_id, model, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now())
ON CONFLICT (vuln_intel_id) DO UPDATE SET
  principle      = CASE WHEN $2 <> '' THEN $2 ELSE vuln_intel_analysis.principle END,
  attack_scope   = CASE WHEN $3 <> '' THEN $3 ELSE vuln_intel_analysis.attack_scope END,
  description_zh = CASE WHEN $4 <> '' THEN $4 ELSE vuln_intel_analysis.description_zh END,
  poc_code       = CASE WHEN $5 <> '' THEN $5 ELSE vuln_intel_analysis.poc_code END,
  poc_lang       = CASE WHEN $6 <> '' THEN $6 ELSE vuln_intel_analysis.poc_lang END,
  poc_origin     = CASE WHEN $7 <> '' THEN $7 ELSE vuln_intel_analysis.poc_origin END,
  poc_note       = CASE WHEN $8 <> '' THEN $8 ELSE vuln_intel_analysis.poc_note END,
  nuclei_tpl     = CASE WHEN $9 <> '' THEN $9 ELSE vuln_intel_analysis.nuclei_tpl END,
  fingerprint    = CASE WHEN $10 <> '' THEN $10 ELSE vuln_intel_analysis.fingerprint END,
  fingerprint_id = CASE WHEN $11 <> '' THEN $11 ELSE vuln_intel_analysis.fingerprint_id END,
  model          = CASE WHEN $12 <> '' THEN $12 ELSE vuln_intel_analysis.model END,
  updated_at     = now()`,
		s.VulnIntelID, s.Principle, s.AttackScope, s.DescriptionZh,
		s.PocCode, s.PocLang, s.PocOrigin, s.PocNote, s.NucleiTemplate, s.Fingerprint,
		s.FingerprintID, s.Model,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(`
UPDATE vuln_intel SET
  title_zh       = CASE WHEN $2 <> '' THEN $2 ELSE title_zh END,
  localized_at   = CASE WHEN $3 THEN now() ELSE localized_at END,
  analyzed_at    = CASE WHEN $4 THEN now() ELSE analyzed_at END,
  nuclei_tpl_at  = CASE WHEN $5 THEN now() ELSE nuclei_tpl_at END,
  nuclei_tpl_id  = CASE WHEN $6 <> '' THEN $6 ELSE nuclei_tpl_id END,
  fingerprint_at = CASE WHEN $7 <> '' THEN now() ELSE fingerprint_at END,
  fingerprint_id = CASE WHEN $7 <> '' THEN $7 ELSE fingerprint_id END,
  analysis_error = ''
WHERE id = $1`,
		s.VulnIntelID, s.TitleZh, s.Localized, s.Analyzed, s.Templated, s.NucleiTplID, s.FingerprintID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// IntelDraft 是一条「已生成但未人工确认」的流水线产物草稿。模板与指纹各自
// 独立确认,所以两条草稿可能同时存在、各自为空或已入库。
type IntelDraft struct {
	VulnIntelID int64  `json:"vuln_intel_id"`
	Title       string `json:"title"`
	TitleZh     string `json:"title_zh"`
	Severity    string `json:"severity"`
	CVE         string `json:"cve"`
	Source      string `json:"source"`

	NucleiYAML    string    `json:"nuclei_yaml"`
	NucleiTplID   string    `json:"nuclei_tpl_id"`
	Fingerprint   string    `json:"fingerprint"`
	FingerprintID string    `json:"fingerprint_id"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ListIntelDrafts 列出待人工确认的产物草稿(nuclei 模板或指纹规则尚未入库)。
// 自动生成只产草稿,是否写进模板库/指纹库由人决定 —— matcher 与表达式都是
// 模型补的,直接进扫描链路会污染结果。
func (d *DB) ListIntelDrafts(limit int) ([]IntelDraft, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.Query(`
SELECT v.id, v.title, COALESCE(v.title_zh,''), COALESCE(v.severity,''), COALESCE(v.cve,''),
       COALESCE(v.source,''), COALESCE(a.nuclei_tpl,''), COALESCE(v.nuclei_tpl_id,''),
       COALESCE(a.fingerprint,''), COALESCE(v.fingerprint_id,''), a.updated_at
FROM vuln_intel_analysis a
JOIN vuln_intel v ON v.id = a.vuln_intel_id
WHERE (a.nuclei_tpl <> '' AND COALESCE(v.nuclei_tpl_id,'') = '')
   OR (a.fingerprint <> '' AND COALESCE(v.fingerprint_id,'') = '')
ORDER BY a.updated_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IntelDraft{}
	for rows.Next() {
		var d0 IntelDraft
		if err := rows.Scan(&d0.VulnIntelID, &d0.Title, &d0.TitleZh, &d0.Severity, &d0.CVE,
			&d0.Source, &d0.NucleiYAML, &d0.NucleiTplID, &d0.Fingerprint, &d0.FingerprintID,
			&d0.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d0)
	}
	return out, rows.Err()
}

// IntelDraftCount 统计待确认草稿数(状态接口用),按情报条目去重。
func (d *DB) IntelDraftCount() (int, error) {
	var n int
	err := d.QueryRow(`
SELECT COUNT(*) FROM vuln_intel_analysis a
JOIN vuln_intel v ON v.id = a.vuln_intel_id
WHERE (a.nuclei_tpl <> '' AND COALESCE(v.nuclei_tpl_id,'') = '')
   OR (a.fingerprint <> '' AND COALESCE(v.fingerprint_id,'') = '')`).Scan(&n)
	return n, err
}

// ClearIntelNucleiDraft 丢弃一条模板草稿(旁表 YAML 与主表时间戳一起清掉)。
// 已入库的模板(nuclei_tpl_id 非空)不动 —— 撤下已入库的模板请走模板库的
// 删除接口,那条路径会有模板索引热加载。
func (d *DB) ClearIntelNucleiDraft(id int64) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`
UPDATE vuln_intel_analysis SET nuclei_tpl = '', updated_at = now() WHERE vuln_intel_id = $1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`
UPDATE vuln_intel SET nuclei_tpl_at = NULL WHERE id = $1 AND COALESCE(nuclei_tpl_id,'') = ''`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearIntelFingerprintDraft 丢弃一条指纹草稿。已入库的指纹(fingerprint_id
// 非空)不动 —— 撤下规则请走指纹库的删除路径,否则匹配缓存与库会不同步。
func (d *DB) ClearIntelFingerprintDraft(id int64) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`
UPDATE vuln_intel_analysis SET fingerprint = '', fingerprint_id = '', updated_at = now()
WHERE vuln_intel_id = $1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`
UPDATE vuln_intel SET fingerprint_at = NULL WHERE id = $1 AND COALESCE(fingerprint_id,'') = ''`, id); err != nil {
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
       poc_origin, poc_note, nuclei_tpl, fingerprint, fingerprint_id, model, updated_at
FROM vuln_intel_analysis WHERE vuln_intel_id = $1`, id,
	).Scan(&a.VulnIntelID, &a.Principle, &a.AttackScope, &a.DescriptionZh,
		&a.PocCode, &a.PocLang, &a.PocOrigin, &a.PocNote, &a.NucleiTemplate,
		&a.Fingerprint, &a.FingerprintID, &a.Model, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// analysisPendingGate 是待分析条目的内容门槛:要有足以支撑分析的情报内容。
// 裸 CVE 列表项(只有编号+等级+披露时间、无描述、标题也就是个编号)分析不出
// 任何东西——模型按「不臆造」的铁律只会回一句「信息不足」,白烧一次调用还
// 把条目冻结成「已分析」7 天。所以要求描述 ≥20 字,或标题 ≥30 字(标题常含
// 产品+组件+漏洞类型,如「NGINX ngx_http_core_module 远程代码执行漏洞」)。
const analysisPendingGate = `(analyzed_at IS NULL OR analyzed_at < now() - interval '7 days')
  AND (length(btrim(COALESCE(description,''))) >= 20
       OR length(btrim(COALESCE(title,''))) >= 30)`

// PendingIntelAnalysis 挑待分析条目:未分析或超 7 天,且情报内容足够。
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
WHERE `+analysisPendingGate+`
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

// IntelAnalysisPendingCount 统计待分析条目数(状态接口用),与分析 worker 用
// 同一道门槛,两边看到的积压数一致。
func (d *DB) IntelAnalysisPendingCount() (int, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(*) FROM vuln_intel WHERE ` + analysisPendingGate).Scan(&n)
	return n, err
}

// IntelAnalyzedCount 统计已产出分析产物的条目数(状态接口用)。
func (d *DB) IntelAnalyzedCount() (int, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(*) FROM vuln_intel WHERE analyzed_at IS NOT NULL`).Scan(&n)
	return n, err
}
