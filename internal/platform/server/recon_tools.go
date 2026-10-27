// recon_tools.go 子域枚举工具面:被动聚合(recon/subdomain,直接搬自 4zreco)+
// 子域名爆破(recon/brute,新增)。命中经资产入库通道落库,范围语义同五引擎。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/recon/brute"
	"github.com/c1ayooo/4zrec/internal/capability/recon/permute"
	"github.com/c1ayooo/4zrec/internal/capability/recon/spacemap"
	"github.com/c1ayooo/4zrec/internal/capability/recon/subdomain"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// importSubdomains 域名列表导入资产库(范围内 approved/范围外 pending)。
func (s *Server) importSubdomains(ctx context.Context, projectID int64, domains []string) int {
	results := make([]*spacemap.Result, 0, len(domains))
	for _, d := range domains {
		results = append(results, &spacemap.Result{Domain: d, Host: d})
	}
	n, _, _ := s.spacemapImport(ctx, projectID, 0, results, "")
	return n
}

// toolSubdomainEnum 被动子域枚举:证书透明 + 公开被动 DNS + 国内被动源 +
// SecurityTrails(可选 key)+ 目标工件(robots/sitemap 等,artifacts.go)。
func (s *Server) toolSubdomainEnum() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "subdomain_enum",
		Description: "被动子域枚举(平台内置保底能力,不向目标发包):聚合证书透明日志(crt.sh/CertSpotter)、公开被动 DNS" +
			"(HackerTarget/OTX/RapidDNS)、国内被动源(千讯/ip138/chinaz)与目标工件(robots/sitemap/CSP/证书 SAN)," +
			"可选 permute 派生候选。适合开局建子域清单;主动探测用 subdomain_brute/recon 流水线。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"domain":     map[string]any{"type": "string", "description": "目标主域(如 example.com)"},
				"permute":    map[string]any{"type": "boolean", "description": "附带候选派生(alterx 式变形,默认 false)"},
				"project_id": map[string]any{"type": "integer", "description": "导入目标项目(可选)"},
			},
			"required": []string{"domain"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Domain    string `json:"domain"`
				Permute   bool   `json:"permute"`
				ProjectID int64  `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			opts := subdomain.Options{
				EnableCT:           true,
				EnablePassiveDNS:   true,
				EnableCNPassiveDNS: true,
				Timeout:            60 * time.Second,
				Limit:              5000,
			}
			res, err := subdomain.Enumerate(ctx, in.Domain, opts)
			if err != nil {
				return actool.Errorf("被动枚举失败: " + err.Error()), nil
			}
			found := map[string]bool{}
			for _, h := range res.Hits {
				found[h.Name] = true
			}
			var derived []string
			if in.Permute && len(found) > 0 {
				seeds := make([]string, 0, len(found))
				for d := range found {
					seeds = append(seeds, d)
				}
				derived = permute.Generate(seeds, strings.ToLower(strings.TrimSpace(in.Domain)), 2000)
			}
			sorted := make([]string, 0, len(found))
			for d := range found {
				sorted = append(sorted, d)
			}
			sort.Strings(sorted)
			var b strings.Builder
			fmt.Fprintf(&b, "被动枚举 %s:命中 %d 条(单源统计 %v)\n", in.Domain, len(sorted), res.PerSrc)
			for name, errMsg := range res.Errors {
				fmt.Fprintf(&b, "- 源 %s 失败: %s\n", name, errMsg)
			}
			for _, d := range sorted {
				fmt.Fprintf(&b, "- %s\n", d)
			}
			if len(derived) > 0 {
				fmt.Fprintf(&b, "派生候选 %d 个(未验证,需 subdomain_brute/解析确认):\n", len(derived))
				cap := derived
				if len(cap) > 50 {
					cap = cap[:50]
				}
				for _, d := range cap {
					fmt.Fprintf(&b, "- %s\n", d)
				}
				if len(derived) > 50 {
					fmt.Fprintf(&b, "…等 %d 个\n", len(derived))
				}
			}
			// 项目缺省取会话/任务挂载(信息收集自动归属)。
			importProject := s.roeProjectID(ctx, in.ProjectID)
			if importProject > 0 {
				imported := s.importSubdomains(ctx, importProject, sorted)
				fmt.Fprintf(&b, "已导入资产库 %d/%d(范围内自动授权,范围外待审批)\n", imported, len(sorted))
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolSubdomainBrute 子域名爆破:内置字典+用户词表,泛解析基线过滤,令牌桶限速。
func (s *Server) toolSubdomainBrute() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "subdomain_brute",
		Description: "子域名爆破(平台内置保底能力,主动 DNS 查询):内置 ~400 词中文 SRC 语境字典 + 追加词表,泛解析域自动基线过滤," +
			"令牌桶限速(默认 QPS 300,对权威 NS 友好)。只对授权范围内的主域使用。结果带解析 IP 与 CNAME," +
			"可导入资产库(范围内 approved/范围外待审批)。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"domain":     map[string]any{"type": "string", "description": "目标主域(如 example.com)"},
				"words":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "追加字典(内置之外)"},
				"qps":        map[string]any{"type": "integer", "description": "每秒解析上限(默认 300)"},
				"resolvers":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "自定义解析器列表(缺省公共 DNS)"},
				"project_id": map[string]any{"type": "integer", "description": "导入目标项目(可选)"},
			},
			"required": []string{"domain"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			// 主动 DNS 查询属于主动探测:默认经人工确认(与 Bash 同语义),
			// read-only 模式下也会问——爆破对象必须先经操作者过目。
			var in struct {
				Domain string `json:"domain"`
			}
			if json.Unmarshal(input, &in) == nil && strings.TrimSpace(in.Domain) != "" {
				return actool.AskUser("子域名爆破(主动 DNS 查询)目标主域: " + in.Domain)
			}
			return actool.AskUser("子域名爆破:确认目标主域")
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Domain    string   `json:"domain"`
				Words     []string `json:"words"`
				QPS       int      `json:"qps"`
				Resolvers []string `json:"resolvers"`
				ProjectID int64    `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			qps := in.QPS
			if qps <= 0 {
				qps = 300
			}
			hits, stats, err := brute.Brute(ctx, in.Domain, brute.Options{
				Words: in.Words, Resolvers: in.Resolvers, QPS: qps,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "爆破 %s:探测 %d,解析 %d,命中 %d", stats.Domain, stats.Probed, stats.Resolved, stats.Hits)
			if stats.Wildcard {
				fmt.Fprintf(&b, "(检出泛解析,基线过滤剔除 %d)", stats.WildcardFiltered)
			}
			b.WriteString("\n")
			for _, h := range hits {
				if h.CNAME != "" {
					fmt.Fprintf(&b, "- %s → %s [%s]\n", h.Name, strings.Join(h.IPs, ","), h.CNAME)
				} else {
					fmt.Fprintf(&b, "- %s [%s]\n", h.Name, strings.Join(h.IPs, ","))
				}
			}
			importProject := s.roeProjectID(ctx, in.ProjectID)
			if importProject > 0 && len(hits) > 0 {
				names := make([]string, 0, len(hits))
				for _, h := range hits {
					names = append(names, h.Name)
				}
				imported := s.importSubdomains(ctx, importProject, names)
				fmt.Fprintf(&b, "已导入资产库 %d/%d(范围内自动授权,范围外待审批)\n", imported, len(names))
			}
			return actool.Text(b.String()), nil
		},
	})
}

// reconTools 子域枚举 + 端口扫描工具族。
func (s *Server) reconTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolSubdomainEnum(),
		s.toolSubdomainBrute(),
		s.toolPortScan(),
		s.toolReconRun(),
		s.toolReconResults(),
	}
}
