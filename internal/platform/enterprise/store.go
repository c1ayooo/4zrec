package enterprise

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Store 企业采集持久化。上限按平台硬限制控制，防止任务无限膨胀。
type Store struct {
	db        *sql.DB
	maxNodes  int
	maxEntity int
	maxAsset  int
}

func NewStore(db *sql.DB) *Store {
	s := &Store{db: db, maxNodes: 200, maxEntity: 500, maxAsset: 2000}
	s.migrate()
	return s
}

func (s *Store) migrate() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS enterprise_jobs (
			id TEXT PRIMARY KEY, project_id TEXT NOT NULL, owner TEXT NOT NULL,
			provider TEXT NOT NULL, keyword TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'running',
			depth INT NOT NULL DEFAULT 1, max_nodes INT NOT NULL DEFAULT 50,
			nodes INT NOT NULL DEFAULT 0, entities INT NOT NULL DEFAULT 0, domains INT NOT NULL DEFAULT 0,
			imported INT NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
			fingerprint_status TEXT NOT NULL DEFAULT 'pending', fingerprint_total INT NOT NULL DEFAULT 0,
			fingerprint_completed INT NOT NULL DEFAULT 0, fingerprint_matched INT NOT NULL DEFAULT 0,
			fingerprint_failed INT NOT NULL DEFAULT 0, fingerprint_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL, finished_at TIMESTAMPTZ)`,
		`CREATE TABLE IF NOT EXISTS enterprise_entities (
			id TEXT PRIMARY KEY, job_id TEXT NOT NULL, ext_id TEXT NOT NULL, name TEXT NOT NULL,
			entity_type TEXT NOT NULL, parent_ext_id TEXT NOT NULL DEFAULT '', depth INT NOT NULL DEFAULT 0,
			legal_person TEXT NOT NULL DEFAULT '', open_status TEXT NOT NULL DEFAULT '',
			phone TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL, UNIQUE(job_id, ext_id, entity_type))`,
		`CREATE TABLE IF NOT EXISTS enterprise_assets (
				id TEXT PRIMARY KEY, job_id TEXT, kind TEXT NOT NULL, value TEXT NOT NULL,
				project_id TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'enterprise',
				entity_name TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'candidate', authorized_at TIMESTAMPTZ, authorized_by TEXT NOT NULL DEFAULT '',
				fingerprint_status TEXT NOT NULL DEFAULT 'pending', fingerprint_error TEXT NOT NULL DEFAULT '',
				created_at TIMESTAMPTZ NOT NULL)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			log.Printf("[enterprise] 企业任务表结构语句执行失败: %v", err)
		}
	}
	for _, q := range []string{
		`ALTER TABLE enterprise_jobs ADD COLUMN IF NOT EXISTS fingerprint_status TEXT NOT NULL DEFAULT 'pending'`,
		`ALTER TABLE enterprise_jobs ADD COLUMN IF NOT EXISTS fingerprint_total INT NOT NULL DEFAULT 0`,
		`ALTER TABLE enterprise_jobs ADD COLUMN IF NOT EXISTS fingerprint_completed INT NOT NULL DEFAULT 0`,
		`ALTER TABLE enterprise_jobs ADD COLUMN IF NOT EXISTS fingerprint_matched INT NOT NULL DEFAULT 0`,
		`ALTER TABLE enterprise_jobs ADD COLUMN IF NOT EXISTS fingerprint_failed INT NOT NULL DEFAULT 0`,
		`ALTER TABLE enterprise_jobs ADD COLUMN IF NOT EXISTS fingerprint_error TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE enterprise_assets ADD COLUMN IF NOT EXISTS authorized_at TIMESTAMPTZ`,
		`ALTER TABLE enterprise_assets ADD COLUMN IF NOT EXISTS authorized_by TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE enterprise_assets ADD COLUMN IF NOT EXISTS fingerprint_status TEXT NOT NULL DEFAULT 'pending'`,
		`ALTER TABLE enterprise_assets ADD COLUMN IF NOT EXISTS fingerprint_error TEXT NOT NULL DEFAULT ''`,
		// v32 项目级候选：job_id 可空 + 项目归属/来源列 + 分域唯一索引（与
		// database.postBaselineMigrations v32 同构，两执行顺序收敛到同一形态）。
		`ALTER TABLE enterprise_assets ALTER COLUMN job_id DROP NOT NULL`,
		`ALTER TABLE enterprise_assets ADD COLUMN IF NOT EXISTS project_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE enterprise_assets ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'enterprise'`,
		`ALTER TABLE enterprise_assets DROP CONSTRAINT IF EXISTS enterprise_assets_job_id_kind_value_key`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_enterprise_assets_job_kind_value ON enterprise_assets (job_id, kind, value) WHERE job_id IS NOT NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_enterprise_assets_project_kind_value ON enterprise_assets (project_id, kind, value) WHERE job_id IS NULL`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			log.Printf("[enterprise] 企业任务表补列语句执行失败: %v", err)
		}
	}
	// 服务重启时把遗留 running 任务标记失败（采集器在内存中，不跨重启恢复）。
	if _, err := s.db.Exec(`UPDATE enterprise_jobs SET status='error', error='服务重启，任务中断', finished_at=now() WHERE status='running'`); err != nil {
		log.Printf("[enterprise] 重启中断任务状态修正失败: %v", err)
	}
}

// CreateJob 新建采集任务。
func (s *Store) CreateJob(ctx context.Context, job Job) (Job, error) {
	job.ID = uuid.NewString()
	job.CreatedAt = time.Now().UTC()
	job.Status = "running"
	_, err := s.db.ExecContext(ctx, `INSERT INTO enterprise_jobs (id,project_id,owner,provider,keyword,status,depth,max_nodes,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		job.ID, job.ProjectID, job.Owner, job.Provider, job.Keyword, job.Status, job.Depth, job.MaxNodes, job.CreatedAt)
	return job, err
}

// FinishJob 结束任务（done/error/canceled）。
func (s *Store) FinishJob(ctx context.Context, id, status, errMsg string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE enterprise_jobs SET status=$2, error=$3, finished_at=$4 WHERE id=$1`, id, status, errMsg, time.Now().UTC())
	return err
}

func (s *Store) SetFingerprintStatus(ctx context.Context, id, status, errMsg string, stats FingerprintStats) error {
	_, err := s.db.ExecContext(ctx, `UPDATE enterprise_jobs SET fingerprint_status=$2, fingerprint_total=$3, fingerprint_completed=$4, fingerprint_matched=$5, fingerprint_failed=$6, fingerprint_error=$7 WHERE id=$1`, id, status, stats.Total, stats.Completed, stats.Matched, stats.Failed, errMsg)
	return err
}

// SaveEntity 幂等写入实体节点（ON CONFLICT 跳过），返回是否新插入。
func (s *Store) SaveEntity(ctx context.Context, e *Entity) (bool, error) {
	e.ID = uuid.NewString()
	e.CreatedAt = time.Now().UTC()
	r, err := s.db.ExecContext(ctx, `INSERT INTO enterprise_entities (id,job_id,ext_id,name,entity_type,parent_ext_id,depth,legal_person,open_status,phone,email,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (job_id,ext_id,entity_type) DO NOTHING`,
		e.ID, e.JobID, e.ExtID, e.Name, e.EntityType, e.ParentExtID, e.Depth, e.LegalPerson, e.OpenStatus, e.Phone, e.Email, e.CreatedAt)
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n > 0, nil
}

// SaveDomain 幂等写入候选域名资产。
func (s *Store) SaveDomain(ctx context.Context, jobID, domain, site, icp, entityName string) (bool, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false, nil
	}
	r, err := s.db.ExecContext(ctx, `INSERT INTO enterprise_assets (id,job_id,kind,value,entity_name,evidence,created_at)
		VALUES ($1,$2,'domain',$3,$4,$5,$6) ON CONFLICT (job_id,kind,value) WHERE job_id IS NOT NULL DO NOTHING`,
		uuid.NewString(), jobID, domain, entityName, site+" "+icp, time.Now().UTC())
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n > 0, nil
}

// BumpJob 累加任务计数。
func (s *Store) BumpJob(ctx context.Context, id string, nodes, entities, domains int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE enterprise_jobs SET nodes=nodes+$2, entities=entities+$3, domains=domains+$4 WHERE id=$1`, id, nodes, entities, domains)
	return err
}

func scanJob(row interface{ Scan(...interface{}) error }) (Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.ProjectID, &j.Owner, &j.Provider, &j.Keyword, &j.Status, &j.Depth, &j.MaxNodes, &j.Nodes, &j.Entities, &j.Domains, &j.Imported, &j.Error, &j.CreatedAt, &j.FinishedAt, &j.FingerprintStatus, &j.FingerprintTotal, &j.FingerprintCompleted, &j.FingerprintMatched, &j.FingerprintFailed, &j.FingerprintError)
	return j, err
}

const jobColumns = `id,project_id,owner,provider,keyword,status,depth,max_nodes,nodes,entities,domains,imported,error,created_at,finished_at,fingerprint_status,fingerprint_total,fingerprint_completed,fingerprint_matched,fingerprint_failed,fingerprint_error`

// GetJob 查询单个任务。
func (s *Store) GetJob(ctx context.Context, id string) (Job, error) {
	return scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM enterprise_jobs WHERE id=$1`, id))
}

// ListJobs 按项目列出任务（owner="" 表示管理员视角全量）。
func (s *Store) ListJobs(ctx context.Context, projectID, owner string) ([]Job, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobColumns+` FROM enterprise_jobs WHERE project_id=$1 AND ($2='' OR owner=$2) ORDER BY created_at DESC LIMIT 50`, projectID, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Tree 返回任务的实体树 + 候选资产。实体按 depth 升序，前端按 parent_ext_id 组织。
// ListCandidateAssets returns candidate assets across jobs in a project with pagination.
// v32 起同时覆盖项目级候选（job_id 为空，信息收集发现面），JobName 回落为来源标签。
func (s *Store) ListCandidateAssets(ctx context.Context, projectID, status, query string, page, pageSize int) ([]CandidateAsset, int, error) {
	projectID = strings.TrimSpace(projectID)
	status = strings.TrimSpace(status)
	query = strings.TrimSpace(query)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize
	args := []any{projectID, status, query}
	where := `(j.project_id=$1 OR a.project_id=$1) AND ($2='' OR a.status=$2) AND ($3='' OR a.value ILIKE '%' || $3 || '%' OR a.entity_name ILIKE '%' || $3 || '%' OR a.evidence ILIKE '%' || $3 || '%' OR j.keyword ILIKE '%' || $3 || '%')`
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM enterprise_assets a LEFT JOIN enterprise_jobs j ON j.id=a.job_id WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, offset)
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,COALESCE(a.job_id,''),a.project_id,a.source,COALESCE(NULLIF(j.keyword,''),NULLIF(a.source,''),'enterprise'),a.kind,a.value,a.entity_name,a.evidence,a.status,a.authorized_at,a.authorized_by,a.fingerprint_status,a.fingerprint_error,a.created_at FROM enterprise_assets a LEFT JOIN enterprise_jobs j ON j.id=a.job_id WHERE `+where+` ORDER BY a.created_at DESC,a.id DESC LIMIT $4 OFFSET $5`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	assets := make([]CandidateAsset, 0)
	for rows.Next() {
		var a CandidateAsset
		if err := rows.Scan(&a.ID, &a.JobID, &a.ProjectID, &a.Source, &a.JobName, &a.Kind, &a.Value, &a.EntityName, &a.Evidence, &a.Status, &a.AuthorizedAt, &a.AuthorizedBy, &a.FingerprintStatus, &a.FingerprintError, &a.CreatedAt); err != nil {
			return nil, 0, err
		}
		assets = append(assets, a)
	}
	return assets, total, rows.Err()
}

// IsUnauthorizedCandidate reports whether target is an enterprise candidate awaiting authorization in projectID.
// v32 起项目级候选（信息收集发现面）同样视为待授权：指纹扫描前先拦。
func (s *Store) IsUnauthorizedCandidate(ctx context.Context, projectID, target string) (bool, error) {
	projectID = strings.TrimSpace(projectID)
	domain := normalizeDomain(target)
	if projectID == "" || domain == "" {
		return false, nil
	}
	var exists bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM enterprise_assets a LEFT JOIN enterprise_jobs j ON j.id=a.job_id WHERE (j.project_id=$1 OR a.project_id=$1) AND a.kind='domain' AND a.value=$2 AND a.status='candidate')`, projectID, domain).Scan(&exists)
	return exists, err
}

// CreateProjectCandidate 登记项目级候选（信息收集发现面，幂等）：同 (project,kind,value)
// 已存在为 candidate 时刷新 evidence，已授权则不动（授权结论不可被覆盖回待授权）。
func (s *Store) CreateProjectCandidate(ctx context.Context, projectID, kind, value, source, evidence string) error {
	projectID = strings.TrimSpace(projectID)
	value = strings.TrimSpace(value)
	if projectID == "" || value == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO enterprise_assets (id, job_id, project_id, kind, value, source, evidence, status, created_at)
		VALUES ($1, NULL, $2, $3, $4, $5, $6, 'candidate', $7)
		ON CONFLICT (project_id, kind, value) WHERE job_id IS NULL
		DO UPDATE SET evidence = EXCLUDED.evidence, source = EXCLUDED.source
		WHERE enterprise_assets.status = 'candidate'`,
		uuid.NewString(), projectID, strings.TrimSpace(kind), value, strings.TrimSpace(source), strings.TrimSpace(evidence), time.Now().UTC())
	return err
}

// AuthorizeProjectAssets 把项目级候选按 id 授权（status=candidate → authorized）。
func (s *Store) AuthorizeProjectAssets(ctx context.Context, projectID, userID string, ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := s.db.ExecContext(ctx, `UPDATE enterprise_assets SET status='authorized', authorized_at=$3, authorized_by=$4
		WHERE project_id=$1 AND status='candidate' AND id = ANY($2)`, projectID, ids, time.Now().UTC(), userID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected()
}

// IgnoreCandidateAssets 把项目内待授权候选标记为忽略（candidate → rejected，软删除）。
// 列表与指纹预检均按 status='candidate' 过滤，rejected 不再展示、也不阻拦扫描；
// CreateProjectCandidate 的 ON CONFLICT 刷新只发生在 status='candidate'，被忽略的候选
// 不会因再次发现被加回。覆盖任务级（job_id 非空）与项目级（job_id 为空）两类，已授权
// 的不在 wildcard 内（授权结论不可回退）。
func (s *Store) IgnoreCandidateAssets(ctx context.Context, projectID string, ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := s.db.ExecContext(ctx, `UPDATE enterprise_assets a SET status='rejected'
		WHERE a.status='candidate' AND a.id = ANY($2) AND (
			a.project_id = $1 OR EXISTS (SELECT 1 FROM enterprise_jobs j WHERE j.id = a.job_id AND j.project_id = $1)
		)`, projectID, ids)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected()
}

// AuthorizeProjectCandidatesByValues 把项目级候选按值授权（agent 授权闭环用：
// icp_expand(authorize=true) 确认后把对应待授权候选标记 authorized）。
func (s *Store) AuthorizeProjectCandidatesByValues(ctx context.Context, projectID, userID string, values []string) (int64, error) {
	if len(values) == 0 {
		return 0, nil
	}
	tag, err := s.db.ExecContext(ctx, `UPDATE enterprise_assets SET status='authorized', authorized_at=$3, authorized_by=$4
		WHERE project_id=$1 AND status='candidate' AND kind='domain' AND value = ANY($2)`, projectID, values, time.Now().UTC(), userID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected()
}

// ListProjectCandidatesByIDs 取项目级候选的选中子集（仅 candidate 状态，供授权流程取 value）。
func (s *Store) ListProjectCandidatesByIDs(ctx context.Context, projectID string, ids []string, authorizeAll bool) ([]CandidateAsset, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, nil
	}
	query := `SELECT id, COALESCE(job_id,''), project_id, source, '' AS job_name, kind, value, entity_name, evidence, status, authorized_at, authorized_by, fingerprint_status, fingerprint_error, created_at
		FROM enterprise_assets WHERE project_id=$1 AND status='candidate' AND job_id IS NULL`
	var args []any
	args = append(args, projectID)
	if !authorizeAll && len(ids) > 0 {
		query += ` AND id = ANY($2)`
		args = append(args, ids)
	}
	query += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	assets := make([]CandidateAsset, 0)
	for rows.Next() {
		var a CandidateAsset
		if err := rows.Scan(&a.ID, &a.JobID, &a.ProjectID, &a.Source, &a.JobName, &a.Kind, &a.Value, &a.EntityName, &a.Evidence, &a.Status, &a.AuthorizedAt, &a.AuthorizedBy, &a.FingerprintStatus, &a.FingerprintError, &a.CreatedAt); err != nil {
			return nil, err
		}
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

func (s *Store) Tree(ctx context.Context, jobID string) ([]Entity, []CandidateAsset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,job_id,ext_id,name,entity_type,parent_ext_id,depth,legal_person,open_status,phone,email,created_at FROM enterprise_entities WHERE job_id=$1 ORDER BY depth ASC, created_at ASC`, jobID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	entities := []Entity{}
	for rows.Next() {
		var e Entity
		if err := rows.Scan(&e.ID, &e.JobID, &e.ExtID, &e.Name, &e.EntityType, &e.ParentExtID, &e.Depth, &e.LegalPerson, &e.OpenStatus, &e.Phone, &e.Email, &e.CreatedAt); err != nil {
			return nil, nil, err
		}
		entities = append(entities, e)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	arows, err := s.db.QueryContext(ctx, `SELECT id,job_id,kind,value,entity_name,evidence,status,authorized_at,authorized_by,fingerprint_status,fingerprint_error,created_at FROM enterprise_assets WHERE job_id=$1 ORDER BY created_at ASC`, jobID)
	if err != nil {
		return nil, nil, err
	}
	defer arows.Close()
	assets := []CandidateAsset{}
	for arows.Next() {
		var a CandidateAsset
		if err := arows.Scan(&a.ID, &a.JobID, &a.Kind, &a.Value, &a.EntityName, &a.Evidence, &a.Status, &a.AuthorizedAt, &a.AuthorizedBy, &a.FingerprintStatus, &a.FingerprintError, &a.CreatedAt); err != nil {
			return nil, nil, err
		}
		assets = append(assets, a)
	}
	return entities, assets, arows.Err()
}

// MarkImported 将候选资产标记为已导入，返回实际更新的行数。
func (s *Store) AuthorizeAssets(ctx context.Context, jobID, userID string, ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	args := []any{jobID, userID}
	ph := make([]string, 0, len(ids))
	for i, id := range ids {
		args = append(args, id)
		ph = append(ph, "$"+strconv.Itoa(i+3))
	}
	r, err := s.db.ExecContext(ctx, `UPDATE enterprise_assets SET status='authorized', authorized_at=now(), authorized_by=$2, fingerprint_status='pending', fingerprint_error='' WHERE job_id=$1 AND id IN (`+strings.Join(ph, ",")+`) AND status='candidate'`, args...)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

func (s *Store) SetAssetFingerprintStatus(ctx context.Context, ids []string, status, errMsg string) error {
	if len(ids) == 0 {
		return nil
	}
	args := []any{status, errMsg}
	ph := make([]string, 0, len(ids))
	for i, id := range ids {
		args = append(args, id)
		ph = append(ph, "$"+strconv.Itoa(i+3))
	}
	_, err := s.db.ExecContext(ctx, `UPDATE enterprise_assets SET fingerprint_status=$1, fingerprint_error=$2 WHERE id IN (`+strings.Join(ph, ",")+`)`, args...)
	return err
}

func (s *Store) MarkImported(ctx context.Context, jobID string, ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, jobID)
	ph := make([]string, 0, len(ids))
	for i, id := range ids {
		args = append(args, id)
		ph = append(ph, "$"+strconv.Itoa(i+2))
	}
	r, err := s.db.ExecContext(ctx, `UPDATE enterprise_assets SET status='imported' WHERE job_id=$1 AND id IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return n, nil
}

// normalizeDomain 去协议/路径/端口，小写化，非法输入返回空。
func normalizeDomain(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
	if i := strings.IndexAny(v, "/:?#"); i >= 0 {
		v = v[:i]
	}
	if v == "" || len(v) > 253 || !strings.Contains(v, ".") {
		return ""
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return ""
	}
	return v
}

// ListRecentJobs 跨项目最近任务(平台数据页用;ListJobs 按项目过滤,这里全量)。
func (s *Store) ListRecentJobs(ctx context.Context, limit int) ([]Job, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobColumns+` FROM enterprise_jobs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// MarkCandidatesImportedByValue 按域名值把候选标为已导入(导入走资产库后调用)。
func (s *Store) MarkCandidatesImportedByValue(ctx context.Context, values []string) (int64, error) {
	if len(values) == 0 {
		return 0, nil
	}
	ph := make([]string, 0, len(values))
	args := make([]any, 0, len(values))
	for i, v := range values {
		ph = append(ph, fmt.Sprintf("$%d", i+1))
		args = append(args, strings.ToLower(strings.TrimSpace(v)))
	}
	r, err := s.db.ExecContext(ctx,
		`UPDATE enterprise_assets SET status='imported' WHERE lower(value) IN (`+strings.Join(ph, ",")+`) AND status='candidate'`, args...)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return n, nil
}
