package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// CompanyAssetSummary 按公司聚合资产生成"开局态势"摘要（planner/mainagent 的
// AssetSummary 提示词变量，施工单变更3）。口径：公司名、各型计数、存活 service
// top、root domain 清单、技术栈 top；末行标注数据来源与资产库最近更新时间——防 agent
// 把库内资产当实时探测结论。无公司/无资产/查询失败一律返回空串（模板条件块吞掉，
// 不影响既有行为）。
func (s *AssetStore) CompanyAssetSummary(ctx context.Context, companyIDs []int64) string {
	if s == nil || s.DB() == nil || len(companyIDs) == 0 {
		return ""
	}
	d := s.DB()
	var b strings.Builder

	// 公司名（多公司时让 planner 知道数字覆盖了谁）。
	var names string
	if err := d.QueryRowContext(ctx, `SELECT string_agg(name, ', ') FROM companies WHERE id = ANY($1)`, companyIDs).Scan(&names); err == nil && names != "" {
		fmt.Fprintf(&b, "公司: %s\n", names)
	}

	// 各型计数（company_id 部分索引）。
	rows, err := d.QueryContext(ctx, `SELECT type, count(*) FROM assets WHERE company_id = ANY($1) GROUP BY type ORDER BY count(*) DESC`, companyIDs)
	if err != nil {
		return ""
	}
	defer rows.Close()
	var counts []string
	total := 0
	for rows.Next() {
		var typ string
		var n int
		if err := rows.Scan(&typ, &n); err != nil {
			return ""
		}
		counts = append(counts, fmt.Sprintf("%s:%d", typ, n))
		total += n
	}
	if err := rows.Err(); err != nil || total == 0 {
		return "" // 无资产 → 摘要整段省略
	}
	fmt.Fprintf(&b, "资产: %s\n", strings.Join(counts, " "))

	// 存活 http service top（status<500 视为存活，last_seen 优先）。
	srows, err := d.QueryContext(ctx, `SELECT url, COALESCE(page_title,''), COALESCE(status_code,0) FROM assets
		WHERE company_id = ANY($1) AND type='service' AND service_type='http' AND url <> '' AND status_code < 500
		ORDER BY last_seen DESC LIMIT 10`, companyIDs)
	if err == nil {
		defer srows.Close()
		var sites []string
		for srows.Next() {
			var u, title string
			var code int
			if err := srows.Scan(&u, &title, &code); err != nil {
				break
			}
			if title != "" {
				sites = append(sites, fmt.Sprintf("- %s [%d] %s", u, code, title))
			} else {
				sites = append(sites, fmt.Sprintf("- %s [%d]", u, code))
			}
		}
		if len(sites) > 0 {
			fmt.Fprintf(&b, "存活站点(top10):\n  %s\n", strings.Join(sites, "\n  "))
		}
	}

	// 根域名清单。
	var roots []string
	if rrows, rerr := d.QueryContext(ctx, `SELECT domain FROM assets
		WHERE company_id = ANY($1) AND type='root_domain' AND domain IS NOT NULL AND domain <> ''
		ORDER BY domain LIMIT 20`, companyIDs); rerr == nil {
		for rrows.Next() {
			var dm string
			if err := rrows.Scan(&dm); err != nil {
				break
			}
			roots = append(roots, dm)
		}
		_ = rrows.Close()
	}
	if len(roots) > 0 {
		fmt.Fprintf(&b, "根域名: %s\n", strings.Join(roots, ", "))
	}

	// 技术栈 top（service 资产的 technologies 数组展开计数）。
	if trows, terr := d.QueryContext(ctx, `SELECT tech, count(*) FROM assets, unnest(technologies) AS tech
		WHERE company_id = ANY($1) AND type='service' GROUP BY tech ORDER BY count(*) DESC, tech LIMIT 10`, companyIDs); terr == nil {
		var techs []string
		for trows.Next() {
			var t string
			var n int
			if err := trows.Scan(&t, &n); err != nil {
				break
			}
			techs = append(techs, fmt.Sprintf("%s:%d", t, n))
		}
		_ = trows.Close()
		if len(techs) > 0 {
			fmt.Fprintf(&b, "技术栈(top10): %s\n", strings.Join(techs, ", "))
		}
	}

	// 新鲜度标注：资产库的最近更新时间（max(last_seen)）。来源语义为平台原生
	// 采集（agent 写入 / DNS·HTTP 自动补全），非本任务实时探测——planner 仍应
	// 以"起点线索"对待，派意图时让 worker 先验证存活。
	line := "数据来源: 平台资产库（原生采集，非本任务实时探测——以此为起点验证，不要当作已验证结论）"
	var lastSeen *time.Time
	if err := d.QueryRowContext(ctx, `SELECT max(last_seen) FROM assets WHERE company_id = ANY($1)`, companyIDs).Scan(&lastSeen); err == nil && lastSeen != nil {
		line += fmt.Sprintf("，最近更新 %s", lastSeen.Local().Format("2006-01-02 15:04"))
	} else {
		line += "，更新时间未知"
	}
	b.WriteString(line)
	return b.String()
}

// ProjectAssetSummary 按项目聚合的"开局态势"摘要(项目为主轴后的替代口径):
// 盘子=归属本项目的资产 ∪ 命中项目授权范围的资产(与读侧围栏同语义);
// 口径/新鲜度语义与 CompanyAssetSummary 一致。
func (s *AssetStore) ProjectAssetSummary(ctx context.Context, projectID int64) string {
	if s == nil || s.DB() == nil || projectID <= 0 {
		return ""
	}
	d := s.DB()
	var b strings.Builder
	inscope := `a.project_id = $1
     OR EXISTS (SELECT 1 FROM project_scope ps WHERE ps.project_id=$1
        AND ((ps.kind='domain' AND a.root_domain = ps.domain)
          OR (ps.kind IN ('ip','cidr') AND ps.net >>= try_inet(a.ip))))`
	var n int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM project_scope WHERE project_id=$1`, projectID).Scan(&n); err == nil && n > 0 {
		fmt.Fprintf(&b, "授权范围: %d 条规则\n", n)
	}
	rows, err := d.QueryContext(ctx, `SELECT a.type, count(*) FROM assets a WHERE `+inscope+` GROUP BY a.type ORDER BY count(*) DESC`, projectID)
	if err != nil {
		return ""
	}
	var counts []string
	total := 0
	for rows.Next() {
		var typ string
		var cnt int
		if rows.Scan(&typ, &cnt) != nil {
			continue
		}
		counts = append(counts, fmt.Sprintf("%s:%d", typ, cnt))
		total += cnt
	}
	rows.Close()
	if total == 0 {
		return ""
	}
	fmt.Fprintf(&b, "资产: %s\n", strings.Join(counts, " "))
	srows, err := d.QueryContext(ctx, `SELECT url, COALESCE(page_title,''), COALESCE(status_code,0) FROM assets
		WHERE project_id=$1 AND type='service' AND service_type='http' AND url <> '' AND status_code < 500
		ORDER BY last_seen DESC LIMIT 10`, projectID)
	if err == nil {
		var sites []string
		for srows.Next() {
			var u, title string
			var code int
			if srows.Scan(&u, &title, &code) != nil {
				continue
			}
			if title != "" {
				sites = append(sites, fmt.Sprintf("- %s [%d] %s", u, code, title))
			} else {
				sites = append(sites, fmt.Sprintf("- %s [%d]", u, code))
			}
		}
		srows.Close()
		if len(sites) > 0 {
			fmt.Fprintf(&b, "存活站点(top10):\n  %s\n", strings.Join(sites, "\n  "))
		}
	}
	var roots []string
	if rrows, rerr := d.QueryContext(ctx, `SELECT domain FROM assets
		WHERE project_id=$1 AND type='root_domain' AND domain IS NOT NULL AND domain <> ''
		ORDER BY domain LIMIT 20`, projectID); rerr == nil {
		for rrows.Next() {
			var dm string
			if rrows.Scan(&dm) != nil {
				continue
			}
			roots = append(roots, dm)
		}
		rrows.Close()
	}
	if len(roots) > 0 {
		fmt.Fprintf(&b, "根域名: %s\n", strings.Join(roots, ", "))
	}
	var lastSeen *time.Time
	if err := d.QueryRowContext(ctx, `SELECT max(last_seen) FROM assets WHERE project_id=$1`, projectID).Scan(&lastSeen); err == nil && lastSeen != nil {
		fmt.Fprintf(&b, "数据来源: 平台资产库原生采集(项目维度),最近更新 %s——以此为起点验证,不要当作已验证结论", lastSeen.Local().Format("2006-01-02 15:04"))
	}
	return b.String()
}
