// spacemap_expand_tools.go ICP/证书/ASN 三路反查扩资产工具。查询语法注册表
// 直接搬自 4zreco(spacemap/icpquery、certquery、asnquery 三包,原样含测试);
// 工具壳按 4zrec 原生工具形态重写:授权动作(icp_expand authorize=true)在
// 权限层走 AskUser 人工确认,确认后写入项目授权范围并触发范围认领——
// 不静默扩范围。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/c1ayooo/4zrec/spacemap"
	"github.com/c1ayooo/4zrec/spacemap/asnquery"
	"github.com/c1ayooo/4zrec/spacemap/certquery"
	"github.com/c1ayooo/4zrec/spacemap/icpquery"
	actool "github.com/c1ayooo/4zrec/tools"
)

// domainsFromEngineRows 用 icp 行适配器从引擎原始行收集域名候选(各反查共用)。
func domainsFromEngineRows(engine string, rows []map[string]interface{}) []string {
	seen := map[string]bool{}
	var out []string
	for _, row := range rows {
		for _, d := range icpquery.DomainsFromRow(engine, row) {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	sort.Strings(out)
	return out
}

// expandSearch 在已配置的引擎上跑一个反查查询,返回原始行与跳过原因。
func (s *Server) expandSearch(ctx context.Context, engines []string, queryFor func(engine string) (string, bool)) (rowsByEngine map[string][]map[string]interface{}, notes []string) {
	c := s.spacemapClient()
	rowsByEngine = map[string][]map[string]interface{}{}
	for _, engine := range engines {
		q, ok := queryFor(engine)
		if !ok {
			notes = append(notes, fmt.Sprintf("%s: 不支持该反查键", spacemap.ProviderDisplayName(engine)))
			continue
		}
		if !c.SourceConfigured(engine) {
			notes = append(notes, fmt.Sprintf("%s: 未配置 key,跳过", spacemap.ProviderDisplayName(engine)))
			continue
		}
		resp, err := c.SearchProviderCtx(ctx, engine, spacemap.SearchRequest{Query: q, Size: 100})
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: %v", spacemap.ProviderDisplayName(engine), err))
			continue
		}
		rowsByEngine[engine] = resp.Results
	}
	return rowsByEngine, notes
}

// expandImportDomains 域名候选导入资产库(走 spacemapImport 的范围语义)。
func (s *Server) expandImportDomains(projectID int64, domains []string) (int, int) {
	results := make([]*spacemap.Result, 0, len(domains))
	for _, d := range domains {
		results = append(results, &spacemap.Result{Domain: d, Host: d})
	}
	d, _, _ := s.spacemapImport(projectID, 0, results)
	return d, len(results)
}

// toolIcpExpand ICP 备案号/主办单位反查:
//   - 无 authorize:返回候选域名清单 + 行内提取的关联备案键(供链式反查);
//   - authorize=true + domains + project_id:【人工确认后】把域名写入项目授权
//     范围(范围认领自动 approved + 正向建 root_domain 资产,enrich 链自动补全)。
func (s *Server) toolIcpExpand() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "icp_expand",
		Description: "ICP 备案反查扩资产:输入备案号(如 粤ICP备14006354号)或主办单位名,在支持的空间测绘引擎反查关联域名候选。" +
			"两段式:先查候选(不传 authorize);人工确认后带 authorize=true + domains + project_id 把选中域名写入项目授权范围" +
			"(写入即授权,范围内后续采集自动 approved)。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"icp":     map[string]any{"type": "string", "description": "ICP 备案号(与 company 二选一)"},
				"company": map[string]any{"type": "string", "description": "主办单位名(与 icp 二选一)"},
				"engines": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "限定引擎(缺省=全部已配置且支持的)"},
				"size":    map[string]any{"type": "integer", "description": "每引擎返回条数(默认 100)"},
				// —— 授权段(第二段调用) ——
				"authorize": map[string]any{"type": "boolean", "description": "true=把 domains 写入项目授权范围(需人工确认)"},
				"domains":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "authorize 时要写入的域名清单"},
				"project_id": map[string]any{
					"type": "integer", "description": "目标项目(authorize 必填;仅查询时可选传入以同步导入候选为待审批资产)",
				},
			},
		},
		Permissions: func(ctx context.Context, input json.RawMessage, pc actool.Context) actool.Decision {
			var in struct {
				Authorize bool     `json:"authorize"`
				Domains   []string `json:"domains"`
			}
			if json.Unmarshal(input, &in) != nil || !in.Authorize {
				return actool.Allowed()
			}
			if len(in.Domains) == 0 {
				return actool.Denied("authorize=true 需要 domains 清单")
			}
			return actool.AskUser("【范围扩容确认】即将把以下域名写入项目授权范围(写入即授权,后续采集与测试自动放行):\n" +
				strings.Join(in.Domains, "\n"))
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				ICP       string   `json:"icp"`
				Company   string   `json:"company"`
				Engines   []string `json:"engines"`
				Size      int      `json:"size"`
				Authorize bool     `json:"authorize"`
				Domains   []string `json:"domains"`
				ProjectID int64    `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}

			// ---- 授权段:写入项目范围 ----
			if in.Authorize {
				if in.ProjectID <= 0 || len(in.Domains) == 0 {
					return actool.Errorf("authorize=true 需要 domains 与 project_id"), nil
				}
				added, _, invalid, errMsgs := s.m.pg.Projects().AddProjectScope(in.ProjectID, in.Domains, "icp_expand")
				if added == 0 {
					return actool.Errorf(fmt.Sprintf("范围写入失败: %v", errMsgs)), nil
				}
				// 范围认领:命中的存量/新建资产自动 approved,范围规则正向建 root_domain 资产。
				if _, err := s.m.pg.Projects().RecomputeProjectAttribution(); err != nil {
					return actool.Text(fmt.Sprintf("已写入 %d 条范围规则,但范围认领重算失败: %v", added, err)), nil
				}
				msg := fmt.Sprintf("已把 %d 个域名写入项目 %d 的授权范围并完成认领", added, in.ProjectID)
				if invalid > 0 {
					msg += fmt.Sprintf(";%d 条非法输入被拒(%v)", invalid, errMsgs)
				}
				return actool.Text(msg), nil
			}

			// ---- 查询段:候选 + 关联键 ----
			kind := icpquery.KindICP
			value := strings.TrimSpace(in.ICP)
			if value == "" {
				value = strings.TrimSpace(in.Company)
				kind = icpquery.KindCompany
			}
			if value == "" {
				return actool.Errorf("icp 与 company 至少传一个"), nil
			}
			engines := in.Engines
			if len(engines) == 0 {
				engines = icpquery.AllEngines()
			}
			rowsByEngine, notes := s.expandSearch(ctx, engines, func(engine string) (string, bool) {
				return icpquery.QueryFor(engine, kind, value)
			})
			var (
				allRows  []map[string]interface{}
				byEngine = map[string][]string{}
			)
			for engine, rows := range rowsByEngine {
				allRows = append(allRows, rows...)
				byEngine[engine] = domainsFromEngineRows(engine, rows)
			}
			domains := map[string]bool{}
			for _, ds := range byEngine {
				for _, d := range ds {
					domains[d] = true
				}
			}
			var b strings.Builder
			fmt.Fprintf(&b, "反查键: %s = %s\n", kind, value)
			for _, n := range notes {
				fmt.Fprintf(&b, "- %s\n", n)
			}
			fmt.Fprintf(&b, "候选域名 %d 个(跨引擎去重):\n", len(domains))
			sorted := make([]string, 0, len(domains))
			for d := range domains {
				sorted = append(sorted, d)
			}
			sort.Strings(sorted)
			for _, d := range sorted {
				fmt.Fprintf(&b, "- %s\n", d)
			}
			// 行内关联键:支持链式反查(icp→company→icp)
			keySeen := map[string]bool{}
			for engine, rows := range rowsByEngine {
				for _, k := range icpquery.KeysFromRows(engine, rows) {
					if k.Value == "" || keySeen[k.ID()] {
						continue
					}
					keySeen[k.ID()] = true
					fmt.Fprintf(&b, "关联键: %s = %s\n", k.Kind, k.Value)
				}
			}
			if in.ProjectID > 0 {
				imported, total := s.expandImportDomains(in.ProjectID, sorted)
				fmt.Fprintf(&b, "已导入资产库 %d/%d(范围内自动授权,范围外待审批)\n", imported, total)
			}
			b.WriteString("\n人工确认后,带 authorize=true + domains + project_id 写入授权范围。")
			return actool.Text(b.String()), nil
		},
	})
}

// toolCertExpand 证书组织(O=)反查:默认只用精确引擎(专用字段),内容匹配
// 引擎(quake/zoomeye)噪音高需显式开启;通用主体组织(CDN/云/设备厂)黑名单拦截。
func (s *Server) toolCertExpand() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "cert_expand",
		Description: "证书组织(O=)反查扩资产:输入证书 Subject Organization(如从站点证书/引擎行取得的 org)," +
			"在支持的空间测绘引擎反查该组织名下的域名候选。默认只用精确匹配引擎;通用主体(CDN/云厂商默认证书)会被拒。" +
			"可带 project_id 同步导入候选为待审批资产。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"org":     map[string]any{"type": "string", "description": "证书组织名(必填)"},
				"engines": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "限定引擎(缺省=全部精确引擎)"},
				"include_content": map[string]any{
					"type": "boolean", "description": "含证书全文匹配引擎(quake/zoomeye,噪音高,结果需备案互证)",
				},
				"project_id": map[string]any{"type": "integer", "description": "导入目标项目(可选)"},
			},
			"required": []string{"org"},
		},
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Org            string   `json:"org"`
				Engines        []string `json:"engines"`
				IncludeContent bool     `json:"include_content"`
				ProjectID      int64    `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			org := certquery.NormalizeOrg(in.Org)
			if org == "" {
				return actool.Errorf("org 无效(过短或为空)"), nil
			}
			if certquery.GenericOrg(org) {
				return actool.Errorf("组织名命中通用主体黑名单(CDN/云厂商/设备厂默认证书)——反查会泛射海量无关资产,拒绝执行"), nil
			}
			engines := in.Engines
			if len(engines) == 0 {
				engines = certquery.ExactEngines()
				if in.IncludeContent {
					engines = certquery.AllEngines()
				}
			}
			rowsByEngine, notes := s.expandSearch(ctx, engines, func(engine string) (string, bool) {
				return certquery.QueryFor(engine, org)
			})
			domains := map[string]bool{}
			for engine, rows := range rowsByEngine {
				for _, d := range domainsFromEngineRows(engine, rows) {
					domains[d] = true
				}
			}
			sorted := make([]string, 0, len(domains))
			for d := range domains {
				sorted = append(sorted, d)
			}
			sort.Strings(sorted)
			var b strings.Builder
			fmt.Fprintf(&b, "证书组织反查: %q\n", org)
			for _, n := range notes {
				fmt.Fprintf(&b, "- %s\n", n)
			}
			fmt.Fprintf(&b, "候选域名 %d 个:\n", len(sorted))
			for _, d := range sorted {
				fmt.Fprintf(&b, "- %s\n", d)
			}
			if in.IncludeContent {
				b.WriteString("\n(含全文匹配引擎:结果可能混入签发者/同名词命中,建议用 icp_expand 备案互证)\n")
			}
			if in.ProjectID > 0 {
				imported, total := s.expandImportDomains(in.ProjectID, sorted)
				fmt.Fprintf(&b, "已导入资产库 %d/%d(范围内自动授权,范围外待审批)\n", imported, total)
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolAsnExpand ASN/网段/机构反查:键类型由传入字段判定。
func (s *Server) toolAsnExpand() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "asn_expand",
		Description: "ASN/BGP 反查扩资产:输入 ASN(如 AS15169)、网段(CIDR)或机构名,在支持的空间测绘引擎反查" +
			"其下的主机与域名候选。可带 project_id 同步导入候选为待审批资产。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"asn":        map[string]any{"type": "string", "description": "ASN 号(如 AS15169;三选一)"},
				"cidr":       map[string]any{"type": "string", "description": "网段(如 8.8.8.0/24;三选一)"},
				"org":        map[string]any{"type": "string", "description": "机构名(如 Google Inc.;三选一)"},
				"engines":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "限定引擎(缺省=全部已配置)"},
				"project_id": map[string]any{"type": "integer", "description": "导入目标项目(可选)"},
			},
		},
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				ASN       string   `json:"asn"`
				CIDR      string   `json:"cidr"`
				Org       string   `json:"org"`
				Engines   []string `json:"engines"`
				ProjectID int64    `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			var kind asnquery.KeyKind
			var value string
			switch {
			case strings.TrimSpace(in.ASN) != "":
				kind, value = asnquery.KindASN, strings.TrimSpace(in.ASN)
			case strings.TrimSpace(in.CIDR) != "":
				kind, value = asnquery.KindCIDR, strings.TrimSpace(in.CIDR)
			case strings.TrimSpace(in.Org) != "":
				kind, value = asnquery.KindOrg, strings.TrimSpace(in.Org)
			default:
				return actool.Errorf("asn / cidr / org 至少传一个"), nil
			}
			engines := in.Engines
			if len(engines) == 0 {
				engines = asnquery.AllEngines()
			}
			rowsByEngine, notes := s.expandSearch(ctx, engines, func(engine string) (string, bool) {
				return asnquery.QueryFor(engine, kind, value)
			})
			domains := map[string]bool{}
			hosts := map[string]bool{}
			for engine, rows := range rowsByEngine {
				for _, row := range rows {
					for _, d := range asnquery.DomainsFromRow(engine, row) {
						domains[d] = true
					}
					for _, h := range asnquery.HostsFromRow(engine, row) {
						hosts[h] = true
					}
				}
			}
			sortedDomains := make([]string, 0, len(domains))
			for d := range domains {
				sortedDomains = append(sortedDomains, d)
			}
			sort.Strings(sortedDomains)
			sortedHosts := make([]string, 0, len(hosts))
			for h := range hosts {
				sortedHosts = append(sortedHosts, h)
			}
			sort.Strings(sortedHosts)
			var b strings.Builder
			fmt.Fprintf(&b, "ASN 反查键: %s = %s\n", kind, value)
			for _, n := range notes {
				fmt.Fprintf(&b, "- %s\n", n)
			}
			fmt.Fprintf(&b, "候选域名 %d 个、主机/IP %d 个\n", len(sortedDomains), len(sortedHosts))
			for _, d := range sortedDomains {
				fmt.Fprintf(&b, "- 域名 %s\n", d)
			}
			hostCap := sortedHosts
			if len(hostCap) > 30 {
				hostCap = hostCap[:30]
			}
			for _, h := range hostCap {
				fmt.Fprintf(&b, "- 主机 %s\n", h)
			}
			if len(sortedHosts) > 30 {
				fmt.Fprintf(&b, "…等 %d 个主机\n", len(sortedHosts))
			}
			if in.ProjectID > 0 {
				imported, total := s.expandImportDomains(in.ProjectID, sortedDomains)
				fmt.Fprintf(&b, "已导入资产库 %d/%d(范围内自动授权,范围外待审批)\n", imported, total)
			}
			return actool.Text(b.String()), nil
		},
	})
}

// spacemapExpandTools 三路反查工具。
func (s *Server) spacemapExpandTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolIcpExpand(),
		s.toolCertExpand(),
		s.toolAsnExpand(),
	}
}
