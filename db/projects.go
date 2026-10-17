package db

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// =====================================================================
// 项目:一次渗透委托的授权根。
//
// 项目持有 project_scope(授权范围)并作为任务/对话/资产的归属父级;资产围栏
// 的白名单来自这里。公司(companies)仍是客户主体,项目可选挂在公司下。
// 授权状态语义见 schema.sql §R:assets.authz 只升不降,NULL 视为 approved。
// =====================================================================

// Project is a row in the projects table.
type Project struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	CompanyID   *int64         `json:"company_id,omitempty"`
	CompanyName string         `json:"company_name,omitempty"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status"`
	AssetCount  int64          `json:"asset_count"`
	PendingCnt  int64          `json:"pending_count"`
	TaskCount   int64          `json:"task_count"`
	Scope       []ProjectScope `json:"scope"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// ProjectScope is one authorization rule of a project (structure mirrors
// company_scope; parsing/validation reuses ParseScopeInput).
type ProjectScope struct {
	ID        int64     `json:"id"`
	ProjectID int64     `json:"project_id"`
	Kind      string    `json:"kind"` // domain|ip|cidr|icp|keyword
	Domain    string    `json:"domain,omitempty"`
	Net       string    `json:"net,omitempty"`
	Value     string    `json:"value,omitempty"`
	Raw       string    `json:"raw"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

const projectCols = `p.id, p.name, p.company_id, COALESCE(c.name,''), p.description, p.status, p.created_at, p.updated_at`

// ProjectStore operates on projects + project_scope.
type ProjectStore struct{ db *DB }

// Projects returns the project store.
func (d *DB) Projects() *ProjectStore { return &ProjectStore{db: d} }

// CreateProject inserts a project. companyID may be nil.
func (s *ProjectStore) CreateProject(name string, companyID *int64, description string) (Project, error) {
	var id int64
	err := s.db.QueryRow(`
INSERT INTO projects(name, company_id, description)
VALUES ($1, $2, $3) RETURNING id`, strings.TrimSpace(name), companyID, description).Scan(&id)
	if err != nil {
		return Project{}, err
	}
	return s.GetProject(id)
}

// UpdateProject replaces editable fields.
func (s *ProjectStore) UpdateProject(id int64, name string, companyID *int64, description, status string) (Project, error) {
	res, err := s.db.Exec(`
UPDATE projects SET name=$2, company_id=$3, description=$4, status=$5, updated_at=now()
WHERE id=$1`, id, strings.TrimSpace(name), companyID, description, status)
	if err != nil {
		return Project{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Project{}, fmt.Errorf("项目 %d 不存在", id)
	}
	return s.GetProject(id)
}

// DeleteProject removes the project; scope cascades, tasks/conversations/assets
// keep their rows with project_id set to NULL (FK ON DELETE SET NULL).
func (s *ProjectStore) DeleteProject(id int64) error {
	_, err := s.db.Exec(`DELETE FROM projects WHERE id=$1`, id)
	return err
}

// GetProject returns one project with scope + counters.
func (s *ProjectStore) GetProject(id int64) (Project, error) {
	row := s.db.QueryRow(`SELECT `+projectCols+` FROM projects p
LEFT JOIN companies c ON c.id = p.company_id
WHERE p.id=$1`, id)
	return scanProject(row, s.db)
}

// ListProjects returns all projects newest first with scope + counters.
func (s *ProjectStore) ListProjects() ([]Project, error) {
	rows, err := s.db.Query(`SELECT ` + projectCols + ` FROM projects p
LEFT JOIN companies c ON c.id = p.company_id
ORDER BY p.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows, s.db)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func scanProject(row interface{ Scan(...any) error }, d *DB) (Project, error) {
	var p Project
	var companyID sql.NullInt64
	if err := row.Scan(&p.ID, &p.Name, &companyID, &p.CompanyName, &p.Description, &p.Status, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	if companyID.Valid {
		cid := companyID.Int64
		p.CompanyID = &cid
	}
	// counters + scope are best-effort enrichments
	_ = d.QueryRow(`SELECT count(*), count(*) FILTER (WHERE authz='pending') FROM assets WHERE project_id=$1`, p.ID).
		Scan(&p.AssetCount, &p.PendingCnt)
	_ = d.QueryRow(`SELECT count(*) FROM tasks WHERE project_id=$1 AND deleted_at IS NULL`, p.ID).Scan(&p.TaskCount)
	scope, err := d.ProjectScopeRules(p.ID)
	if err == nil {
		p.Scope = scope
	}
	return p, nil
}

// AddProjectScope parses textarea lines and inserts them as the project's
// authorization scope. Returns added/skipped/invalid counts and error messages
// (mirrors CompanyStore.AddScope semantics).
func (s *ProjectStore) AddProjectScope(projectID int64, lines []string, reason string) (added, skipped, invalid int, errMsgs []string) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parsed, err := ParseScopeInput(ScopeInput{Value: line})
		if err != nil {
			invalid++
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", line, err))
			continue
		}
		if err := s.insertScopeRow(projectID, parsed, reason); err != nil {
			if strings.Contains(err.Error(), "duplicate key") {
				// normalize NULLs so the unique constraints (project_id, domain|net)
				// treat a re-added identical rule as a skip, not an error.
				skipped++
				continue
			}
			invalid++
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", line, err))
			continue
		}
		added++
	}
	return added, skipped, invalid, errMsgs
}

func (s *ProjectStore) insertScopeRow(projectID int64, p ParsedScope, reason string) error {
	var domain, value sql.NullString
	var net sql.NullString // CIDR as text
	switch p.Kind {
	case "domain":
		domain = sql.NullString{String: p.Domain, Valid: true}
	case "ip", "cidr":
		net = sql.NullString{String: p.Net, Valid: true}
	default:
		value = sql.NullString{String: p.Value, Valid: true}
	}
	_, err := s.db.Exec(`
INSERT INTO project_scope(project_id, kind, domain, net, value, raw, reason)
VALUES ($1, $2, NULLIF($3,''), NULLIF($4,'')::cidr, NULLIF($5,''), $6, NULLIF($7,''))`,
		projectID, p.Kind, domain.String, net.String, value.String, p.Raw, strings.TrimSpace(reason))
	return err
}

// DeleteProjectScope removes one scope rule.
func (s *ProjectStore) DeleteProjectScope(projectID, scopeID int64) error {
	_, err := s.db.Exec(`DELETE FROM project_scope WHERE id=$1 AND project_id=$2`, scopeID, projectID)
	return err
}

// ProjectScopeCandidates 从项目资产自动生成范围候选:扫 project_id 下全部
// root_domain,归一化(去端口/协议/尾点/大小写)后按可注册基域聚合(两级
// TLD 粗略规则 + 常见二级后缀白名单),带命中计数降序。脏数据天然出局:
// 代码标识符残留(f.write/data.get)、解析噪声(b23.tv$p)过不了域名合法性
// 校验。只有已在资产里实证存在的根域才入围——生成的是"从发现反推的授权
// 面快照",人工勾选确认后才写入 project_scope(授权是合规动作,不自动落)。
func (d *DB) ProjectScopeCandidates(projectID int64) ([]map[string]any, error) {
	rows, err := d.Query(`
SELECT COALESCE(root_domain, ''), count(*) FROM assets WHERE project_id=$1 GROUP BY root_domain`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var rd string
		var n int
		if err := rows.Scan(&rd, &n); err != nil {
			return nil, err
		}
		root := registrableRoot(rd)
		if root == "" {
			continue
		}
		counts[root] += n
	}
	out := make([]map[string]any, 0, len(counts))
	for root, n := range counts {
		out = append(out, map[string]any{"domain": root, "assets": n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["assets"].(int) > out[j]["assets"].(int) })
	return out, nil
}

// multiPartSuffixes 是多段公共后缀(cc.国别/地区 形态),取基域时多剥一段。
// 粗略覆盖主流项即可:候选仍要过人工勾选,漏一段只是多一条候选。
var multiPartSuffixes = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true,
	"com.hk": true, "org.hk": true, "edu.hk": true, "com.tw": true, "com.au": true,
	"co.kr": true, "co.in": true, "com.br": true, "com.sg": true,
}

// TLDAllowlist 是真实 TLD 后缀白名单:常见通用/国别 TLD + 内网伪 TLD +
// ICANN 保留字。两处消费:①范围候选生成器——把代码标识符化石(f.write、
// data.get、json.loads 这类旧 bug 存进资产的脏数据)挡在候选之外;②执行侧
// 围栏的裸 token 域名校验(guard 包引用本表,单一事实源)。冷门新 TLD 会
// 漏——宁漏勿扰:漏拦只是少问一次,误拦是每个脚本都要审批。
var TLDAllowlist = map[string]bool{
	// 通用/主流
	"com": true, "net": true, "org": true, "edu": true, "gov": true,
	"mil": true, "int": true, "info": true, "biz": true, "io": true,
	"co": true, "ai": true, "app": true, "dev": true, "cloud": true,
	"tech": true, "xyz": true, "top": true, "vip": true, "site": true,
	"online": true, "shop": true, "club": true, "fun": true, "ltd": true,
	"group": true, "work": true, "website": true, "space": true, "icu": true,
	"pro": true, "live": true, "life": true, "me": true, "tv": true, "cc": true,
	// 常见国家/地区
	"cn": true, "uk": true, "jp": true, "kr": true, "hk": true, "tw": true,
	"ru": true, "in": true, "de": true, "fr": true, "it": true, "nl": true,
	"se": true, "es": true, "br": true, "au": true, "ca": true, "us": true,
	"sg": true, "my": true, "th": true, "id": true, "vn": true, "ph": true,
	"nz": true, "za": true, "il": true, "ae": true, "sa": true, "mx": true,
	"ar": true, "cl": true, "ch": true, "pl": true, "pt": true, "cz": true,
	"gr": true, "hu": true, "ro": true, "ua": true,
	// 内网命名伪 TLD(渗透现场常见内部主机名)
	"local": true, "internal": true, "corp": true, "lan": true,
	"prod": true, "lab": true, "vpn": true, "staging": true, "intranet": true,
	// ICANN 保留(文档/测试用,测试夹具大量使用 *.example)
	"example": true, "invalid": true, "test": true,
}

// registrableRoot 把 host 归一化到可注册基域:去协议/端口/路径/尾点、转小写,
// 校验域名合法性(复用 guard 思路的形态校验:各 label 合法、末段纯字母),
// 再按两级 TLD 规则剥到基域。噪声(含 $ / 代码标识符 / 单段)返回空串。
func registrableRoot(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	// 剥协议与路径:取 // 后、第一个 / 前。
	if i := strings.Index(host, "//"); i >= 0 {
		if j := strings.Index(host[i+2:], "/"); j >= 0 {
			host = host[i+2 : i+2+j]
		} else {
			host = host[i+2:]
		}
	} else if j := strings.Index(host, "/"); j >= 0 {
		host = host[:j]
	}
	// 去端口与用户信息。
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	labels := strings.Split(host, ".")
	// 形态校验:≥2 段、末段纯字母 ≥2、各 label 非空且不含非法字符。
	if len(labels) < 2 {
		return ""
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return ""
		}
		for _, c := range l {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "" // $、_、中文等噪声在这里出局
			}
		}
	}
	tld := labels[len(labels)-1]
	if !TLDAllowlist[tld] {
		return "" // 代码标识符化石(write/get/loads)在这里出局
	}
	// 基域:两段(suffix=末段)或三段(suffix 命中多段后缀表)。
	n := 2
	if len(labels) >= 3 && multiPartSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
		n = 3
	}
	if len(labels) < n {
		n = len(labels)
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// ImportProjectScope 把候选根域批量写入 project_scope(复用 AddProjectScope 的
// 解析护栏),返回实际新增条数。已存在的相同规则按其内部 skip 逻辑去重。
func (d *DB) ImportProjectScope(projectID int64, domains []string, reason string) (added, skipped, invalid int, errMsgs []string) {
	return d.Projects().AddProjectScope(projectID, domains, reason)
}

// SuggestScope 把 LLM 收尾时给的范围建议落进建议池:域名做与围栏一致的形态
// 校验(TLD 白名单,防代码标识符/乱串入库),同项目同域幂等(重复建议保留
// 首条的 reason)。不自动生效——导入仍走人工确认,LLM 只提名不签授权。
func (d *DB) SuggestScope(projectID int64, domains []string, reason string) (accepted, rejected int, errs []string) {
	for _, raw := range domains {
		host := registrableRoot(raw)
		if host == "" {
			rejected++
			errs = append(errs, raw+": 不是合法的根域名")
			continue
		}
		if _, err := d.Exec(`
INSERT INTO project_scope_suggestions(project_id, domain, reason, source)
VALUES ($1, $2, $3, 'llm')
ON CONFLICT (project_id, domain) DO NOTHING`, projectID, host, strings.TrimSpace(reason)); err != nil {
			rejected++
			errs = append(errs, raw+": "+err.Error())
			continue
		}
		accepted++
	}
	return accepted, rejected, errs
}

// ScopeSuggestions 返回建议池(默认 pending 优先、时间倒序),供候选接口合并
// 与前端展示。
func (d *DB) ScopeSuggestions(projectID int64, statuses ...string) ([]map[string]any, error) {
	q := `SELECT id, domain, reason, source, status, created_at FROM project_scope_suggestions WHERE project_id=$1`
	args := []any{projectID}
	if len(statuses) > 0 {
		q += ` AND status = ANY($2)`
		args = append(args, statuses)
	}
	q += ` ORDER BY created_at DESC`
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var domain, reason, source, status string
		var createdAt time.Time
		if err := rows.Scan(&id, &domain, &reason, &source, &status, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": id, "domain": domain, "reason": reason,
			"source": source, "status": status, "created_at": createdAt,
		})
	}
	return out, rows.Err()
}

// ResolveScopeSuggestions 批量改建议状态:并入时把 pending 建议(含本次 LLM
// 新提的)标为 imported,人工否决标 dismissed。
func (d *DB) ResolveScopeSuggestions(projectID int64, domains []string, status string) error {
	if len(domains) == 0 {
		return nil
	}
	_, err := d.Exec(`
UPDATE project_scope_suggestions SET status=$3 WHERE project_id=$1 AND domain = ANY($2)`,
		projectID, domains, status)
	return err
}

// RecomputeProjectAttribution 把范围命中的资产认领进项目并升级授权——企业侧
// recomputeAttributionTx 的项目对应物,但遵循围栏「只升不降」:只处理未归属
// 或本项目已有的资产(不抢别项目的);authz 为空/pending 的提为 approved
// (范围命中=授权),rejected 不动(人工拒绝优先)。域名匹配 root_domain 优先,
// 其次 IP/CIDR 网段包含;ICP/关键词是提示规则,不参与。
// 删除范围规则不回收已认领资产(授权只增不减)。返回本轮认领/升级条数。
// 触发点:项目范围变更(server addProjectScope)与每轮同步收尾(同步入库
// 只做企业归属,项目侧在这里补)。
func (s *ProjectStore) RecomputeProjectAttribution() (int64, error) {
	// 范围规则正向生成资产:用户在项目里配置的授权域名,本身就是一条可见的
	// root_domain 资产——否则只有范围没有资产行,任务作用域继承得再对,
	// list_assets 也读到 0(2026-10-15 woniuxy 任务规划器两眼一抹黑,只能去翻
	// /etc/hosts 找目标)。幂等:已有同根 root_domain 资产则跳过(不抢别的
	// 项目的归属,唯一键兜底),存量规则在下一轮 recompute 补建。
	if _, err := s.db.Exec(`
INSERT INTO assets(type, domain, root_domain, project_id, authz)
SELECT 'root_domain', ps.domain, ps.domain, ps.project_id, 'approved'
FROM project_scope ps
WHERE ps.kind = 'domain' AND COALESCE(ps.domain, '') != ''
  AND NOT EXISTS (
    SELECT 1 FROM assets a WHERE a.type = 'root_domain' AND a.root_domain = ps.domain
  )`); err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`
WITH matched AS (
    SELECT DISTINCT ON (a.id) a.id AS asset_id, ps.project_id
    FROM assets a
    JOIN project_scope ps ON ps.kind = 'domain' AND a.root_domain = ps.domain
    WHERE (a.project_id IS NULL OR a.project_id = ps.project_id)
      AND a.type IN ('root_domain','subdomain','service','endpoint')
      AND a.root_domain IS NOT NULL
    ORDER BY a.id, length(ps.domain) DESC, ps.project_id
)
UPDATE assets a
SET project_id = matched.project_id,
    authz = CASE WHEN COALESCE(a.authz,'') IN ('','pending') THEN 'approved' ELSE a.authz END
FROM matched
WHERE a.id = matched.asset_id`)
	if err != nil {
		return 0, err
	}
	claimed, _ := res.RowsAffected()

	res, err = s.db.Exec(`
WITH matched AS (
    SELECT DISTINCT ON (a.id) a.id AS asset_id, ps.project_id
    FROM assets a
    JOIN project_scope ps ON ps.kind IN ('ip','cidr') AND ps.net >>= try_inet(a.ip)
    WHERE (a.project_id IS NULL OR a.project_id = ps.project_id)
      AND a.type IN ('ip','subdomain','service','endpoint')
      AND a.ip IS NOT NULL
    ORDER BY a.id, masklen(ps.net) DESC, ps.project_id
)
UPDATE assets a
SET project_id = matched.project_id,
    authz = CASE WHEN COALESCE(a.authz,'') IN ('','pending') THEN 'approved' ELSE a.authz END
FROM matched
WHERE a.id = matched.asset_id`)
	if err != nil {
		return claimed, err
	}
	n, _ := res.RowsAffected()
	return claimed + n, nil
}

// ProjectScopeRules returns all scope rules of a project.
func (d *DB) ProjectScopeRules(projectID int64) ([]ProjectScope, error) {
	rows, err := d.Query(`
SELECT id, project_id, kind, COALESCE(domain,''), COALESCE(net::text,''), COALESCE(value,''), raw, COALESCE(reason,''), created_at
FROM project_scope WHERE project_id=$1 ORDER BY id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectScope
	for rows.Next() {
		var r ProjectScope
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.Kind, &r.Domain, &r.Net, &r.Value, &r.Raw, &r.Reason, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MatchProjectScope reports whether the given domain/ip is covered by one of the
// scope rules. Domain rules match the registrable domain itself and any subdomain
// (suffix match); ip/cidr rules match by network containment. icp/keyword rules
// never match here (they are hints, not fence rules).
func MatchProjectScope(rules []ProjectScope, domain, ip string) (ProjectScope, bool) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	ip = strings.TrimSpace(ip)
	var pip net.IP
	if ip != "" {
		pip = net.ParseIP(ip)
	}
	// prefer the most specific domain rule (longest suffix)
	var best ProjectScope
	for _, r := range rules {
		switch r.Kind {
		case "domain":
			if domain == "" || r.Domain == "" {
				continue
			}
			if domain == r.Domain || strings.HasSuffix(domain, "."+r.Domain) {
				if best.ID == 0 || len(r.Domain) > len(best.Domain) {
					best = r
				}
			}
		case "ip", "cidr":
			if pip == nil || r.Net == "" {
				continue
			}
			if _, ipnet, err := net.ParseCIDR(r.Net); err == nil && ipnet.Contains(pip) {
				// net rules are exact; first hit wins
				return r, true
			}
		}
	}
	if best.ID != 0 {
		return best, true
	}
	return ProjectScope{}, false
}

// ---------------------------------------------------------------------
// 授权状态(assets.authz)操作。核心不变量:只升不降 ——
//   NULL/pending --(范围命中/人工批准)--> approved
//   NULL/pending/approved --(人工拒绝)--> rejected(终态,范围不再翻回)
// ---------------------------------------------------------------------

// StampDiscoveredAsset 打标"渗透过程发现的资产":命中项目范围 → approved,
// 否则 → pending。只在 NULL/pending 上生效,绝不降级 approved/rejected。
// projectID<=0 时无操作(未挂项目的任务保持旧行为,authz 留 NULL=视为 approved)。
func (s *AssetStore) StampDiscoveredAsset(assetID, projectID int64) (authz string, err error) {
	if projectID <= 0 {
		return "", nil
	}
	rules, err := s.db.ProjectScopeRules(projectID)
	if err != nil {
		return "", err
	}
	a, err := s.GetByIDs([]int64{assetID})
	if err != nil || len(a) == 0 {
		return "", err
	}
	domains, ips, _ := a[0].interceptCandidates()
	allowed := false
	for _, d := range domains {
		if _, ok := MatchProjectScope(rules, d, ""); ok {
			allowed = true
			break
		}
	}
	if !allowed {
		for _, ip := range ips {
			if _, ok := MatchProjectScope(rules, "", ip); ok {
				allowed = true
				break
			}
		}
	}
	state := "pending"
	if allowed {
		state = "approved"
	}
	// 只升不降:approved/rejected 已是终态或更高状态时保持不变。
	_, err = s.db.Exec(`
UPDATE assets SET authz=$3,
  project_id = COALESCE(project_id, $2)
WHERE id=$1 AND (authz IS NULL OR authz='pending' OR (authz='approved' AND $3='approved'))`,
		assetID, projectID, state)
	if err != nil {
		return "", err
	}
	// 回读实际生效状态(可能因只升不降与请求状态不同)
	_ = s.db.QueryRow(`SELECT COALESCE(authz,'approved') FROM assets WHERE id=$1`, assetID).Scan(&authz)
	return authz, nil
}

// SetAssetAuthz 人工批量设置授权状态(approve/reject)。terminal=true 时可为
// rejected(终态);approved 允许从 rejected 恢复(人工明确改判优先)。
func (s *AssetStore) SetAssetAuthz(ids []int64, state string) error {
	switch state {
	case "approved", "pending", "rejected":
	default:
		return fmt.Errorf("无效的授权状态: %s", state)
	}
	if len(ids) == 0 {
		return nil
	}
	_, err := s.db.Exec(`UPDATE assets SET authz=$2 WHERE id = ANY($1::bigint[])`, ids, state)
	return err
}

// ApproveAssetsWithProject 批量批准并把资产归属到项目(UI 待审批队列的批准动作)。
func (s *AssetStore) ApproveAssetsWithProject(ids []int64, projectID int64) error {
	if len(ids) == 0 {
		return nil
	}
	if projectID > 0 {
		_, err := s.db.Exec(`UPDATE assets SET authz='approved', project_id=$2 WHERE id = ANY($1::bigint[])`, ids, projectID)
		return err
	}
	return s.SetAssetAuthz(ids, "approved")
}

// ListPendingAssets 返回待审批资产(可按项目过滤),最新发现优先。
func (s *AssetStore) ListPendingAssets(projectID int64, limit, offset int) ([]*Asset, int64, error) {
	if limit <= 0 {
		limit = 20
	}
	where := `authz='pending'`
	args := []any{}
	if projectID > 0 {
		where += ` AND project_id=$1`
		args = append(args, projectID)
	}
	var total int64
	if err := s.db.QueryRow(`SELECT count(*) FROM assets WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(assetSelectCols+` WHERE `+where+` ORDER BY last_seen DESC LIMIT $`+
		fmt.Sprint(len(args)+1)+` OFFSET $`+fmt.Sprint(len(args)+2),
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	assets, err := scanAssets(rows)
	return assets, total, err
}

// ---------------------------------------------------------------------
// 上下文 → 项目 解析(guard 执行侧闸门用)
// ---------------------------------------------------------------------

// TaskProjectID 返回任务归属的项目;0=未挂项目。
func (d *DB) TaskProjectID(taskID int64) (int64, error) {
	if taskID <= 0 {
		return 0, nil
	}
	var pid sql.NullInt64
	err := d.QueryRow(`SELECT project_id FROM tasks WHERE id=$1`, taskID).Scan(&pid)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if pid.Valid {
		return pid.Int64, nil
	}
	return 0, nil
}

// ConvProjectID 返回会话归属的项目;0=未挂项目。
func (d *DB) ConvProjectID(convID int64) (int64, error) {
	if convID <= 0 {
		return 0, nil
	}
	var pid sql.NullInt64
	err := d.QueryRow(`SELECT project_id FROM conversations WHERE id=$1`, convID).Scan(&pid)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if pid.Valid {
		return pid.Int64, nil
	}
	return 0, nil
}

// AuthorizedTarget 判定"执行侧提取到的目标"是否已获授权——ALL 语义:
// 每一个目标(域名与 IP)都必须独立命中,任何一个未授权即整体返回 false
// (2026-10-16 围栏加固:此前任一命中即放行整条命令,混合目标里夹带未授权
// 目标可以借道放行)。单目标授权途径:
//  1. 命中项目范围规则 → 授权;
//  2. 库里存在 authz='approved' 且 host 精确相等的【本项目或未归属】资产
//     → 授权(项目隔离:他项目批准的资产不构成本项目授权,他项目 rejected
//     的终态也不会因本项目审批被翻回);
//  3. 其余 → 未授权(调用方决定 block/ask)。
//
// 全局黑名单不在本方法内(由 CheckAssetsIntercept/拦截规则层负责)。
func (d *DB) AuthorizedTarget(projectID int64, domains, ips []string) bool {
	if projectID <= 0 {
		// 无项目上下文:围栏不启用,只有已批准资产仍算授权(通常全放行)
		return true
	}
	rules, _ := d.ProjectScopeRules(projectID) // 出错时范围检查缺席,资产检查仍逐目标生效(fail-closed)
	authorizedDomain := func(dom string) bool {
		if _, ok := MatchProjectScope(rules, dom, ""); ok {
			return true
		}
		var one int
		return d.QueryRow(`SELECT 1 FROM assets WHERE authz='approved' AND (domain=$1 OR root_domain=$1)
			AND (project_id IS NULL OR project_id=$2) LIMIT 1`, dom, projectID).Scan(&one) == nil
	}
	authorizedIP := func(ip string) bool {
		if _, ok := MatchProjectScope(rules, "", ip); ok {
			return true
		}
		var one int
		return d.QueryRow(`SELECT 1 FROM assets WHERE authz='approved' AND ip=$1
			AND (project_id IS NULL OR project_id=$2) LIMIT 1`, ip, projectID).Scan(&one) == nil
	}
	for _, dom := range domains {
		if !authorizedDomain(dom) {
			return false
		}
	}
	for _, ip := range ips {
		if !authorizedIP(ip) {
			return false
		}
	}
	return true
}

// EnsureDiscoveredAsset 把执行侧撞到的未登记目标就地登记为 pending 资产(待审批),
// 供审批挂起流使用:人工批准后它就是一条 approved 资产。type 由调用方按目标形态
// 给出(domain→subdomain,ip→ip)。
//
// 单行模型下的项目语义(2026-10-16 围栏加固):assets 各类型有全局唯一索引,
// 同一 host 全库只有一行——本项目的审批若命中【他项目占据的行】,把归属移交
// 给本项目(授权随审批项目走):原项目的范围授权不受影响(范围匹配不依赖资产
// 行),而它经资产 approved 的旧通道同步失效,不会出现"他项目审批、本项目放行"
// 的漂移。未归属(NULL)的行照旧认领。
func (d *DB) EnsureDiscoveredAsset(projectID int64, typ, domain, ip string) (int64, error) {
	claimForeign := func(id int64) (int64, error) {
		if _, err := d.Exec(`UPDATE assets SET project_id=$1, updated_at=now() WHERE id=$2`, projectID, id); err != nil {
			return 0, err
		}
		return id, nil
	}
	if typ == "ip" {
		var id int64
		var owner sql.NullInt64
		err := d.QueryRow(`SELECT id, project_id FROM assets WHERE type='ip' AND ip=$1 LIMIT 1`, ip).Scan(&id, &owner)
		if err == nil {
			if owner.Valid && owner.Int64 != projectID {
				return claimForeign(id)
			}
			return id, nil
		}
		if err != sql.ErrNoRows {
			return 0, err
		}
		err = d.QueryRow(`
INSERT INTO assets(type, ip, authz, project_id) VALUES ('ip', $1, 'pending', $2) RETURNING id`,
			ip, projectID).Scan(&id)
		return id, err
	}
	var id int64
	var owner sql.NullInt64
	// 同域可能同时存在 root_domain 行(UpsertSubdomain 的副作用)与 subdomain
	// 行:围栏登记的目标优先落 subdomain 行(与插入形态一致),root 行兜底。
	err := d.QueryRow(`SELECT id, project_id FROM assets
		WHERE domain=$1 AND type IN ('subdomain','root_domain')
		ORDER BY (type='subdomain') DESC LIMIT 1`, domain).Scan(&id, &owner)
	if err == nil {
		if owner.Valid && owner.Int64 != projectID {
			return claimForeign(id)
		}
		return id, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	err = d.QueryRow(`
INSERT INTO assets(type, domain, root_domain, authz, project_id)
VALUES ('subdomain', $1, $2, 'pending', $3) RETURNING id`,
		domain, DomainKey(domain), projectID).Scan(&id)
	return id, err
}

// ClaimAssetToProject 手工资产归属项目(资产 API 显式指定 project_id 的写入路径,
// 与待审批队列的 ApproveAssetsWithProject 并列)。只认领 project_id IS NULL 的
// 资产——不抢别项目的归属;authz 空/pending 提为 approved(显式归属=授权),
// rejected 终态不复活(只升不降)。返回是否发生了认领。
func (s *AssetStore) ClaimAssetToProject(assetID, projectID int64) (bool, error) {
	if assetID <= 0 || projectID <= 0 {
		return false, nil
	}
	res, err := s.db.Exec(`
UPDATE assets
SET project_id=$2,
    authz = CASE WHEN COALESCE(authz,'') IN ('','pending') THEN 'approved' ELSE authz END
WHERE id=$1 AND project_id IS NULL`, assetID, projectID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ProjectCoverage 项目覆盖度总览:授权范围内的资产盘子、已测/未测分布与
// 未测样本(覆盖度缺口视图——list_untested_assets 是任务级,这是项目级)。
// "已测"= 存在事实锚点(exploration_anchors→fact 节点),与任务级口径一致。
type ProjectCoverage struct {
	ScopeRules int            `json:"scope_rules"`
	InScope    int            `json:"in_scope"`
	Tested     int            `json:"tested"`
	Untested   int            `json:"untested"`
	ByType     map[string]int `json:"by_type"`
	Sample     []CoverageItem `json:"sample"`
}

// CoverageItem 未测样本行。
type CoverageItem struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

// ProjectCoverageOverview 项目覆盖度查询。资产盘子=归属本项目的资产行 ∪ 命中
// 项目范围规则的资产(与读侧围栏谓词同语义,项目维度直查)。
func (d *DB) ProjectCoverageOverview(ctx context.Context, projectID int64) (*ProjectCoverage, error) {
	if projectID <= 0 {
		return nil, fmt.Errorf("project_id 无效")
	}
	out := &ProjectCoverage{ByType: map[string]int{}}
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM project_scope WHERE project_id=$1`, projectID).Scan(&out.ScopeRules); err != nil {
		return nil, err
	}
	inscope := `a.project_id = $1
     OR EXISTS (SELECT 1 FROM project_scope ps WHERE ps.project_id=$1
        AND ((ps.kind='domain' AND a.root_domain = ps.domain)
          OR (ps.kind IN ('ip','cidr') AND ps.net >>= try_inet(a.ip))))`
	tested := ` EXISTS (SELECT 1 FROM exploration_anchors ea
      JOIN exploration_nodes en ON en.id=ea.node_id AND en.kind='fact'
      WHERE ea.asset_id=a.id)`
	if err := d.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE `+tested+`) FROM assets a WHERE `+inscope, projectID).Scan(&out.InScope, &out.Tested); err != nil {
		return nil, err
	}
	out.Untested = out.InScope - out.Tested
	rows, err := d.QueryContext(ctx, `
SELECT a.type, count(*) FROM assets a WHERE `+inscope+` GROUP BY a.type`, projectID)
	if err == nil {
		for rows.Next() {
			var t string
			var n int
			if rows.Scan(&t, &n) == nil {
				out.ByType[t] = n
			}
		}
		rows.Close()
	}
	rows2, err := d.QueryContext(ctx, `
SELECT a.id, a.type, COALESCE(a.url, a.domain, a.ip, a.app_name, a.root_domain, '')
FROM assets a
WHERE NOT (`+tested+`) AND (
  a.project_id = $1
  OR EXISTS (SELECT 1 FROM project_scope ps WHERE ps.project_id=$1
     AND ((ps.kind='domain' AND a.root_domain = ps.domain)
       OR (ps.kind IN ('ip','cidr') AND ps.net >>= try_inet(a.ip)))))
ORDER BY a.id LIMIT 100`, projectID)
	if err == nil {
		for rows2.Next() {
			var it CoverageItem
			if rows2.Scan(&it.ID, &it.Type, &it.Label) == nil {
				out.Sample = append(out.Sample, it)
			}
		}
		rows2.Close()
	}
	return out, nil
}
