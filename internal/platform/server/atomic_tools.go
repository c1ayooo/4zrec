// atomic_tools.go 原子侦察判定工具:六个判定包全部直接搬自 4zreco
// (cdnmatch/cdnorigin/cloudassets/legacyhunter/takeover/saasdetect,原样含测试)。
// 工具面收敛为四个:cdn_origin(源站被动发现)、legacy_hunter(遗留系统猎人,
// 探测开关)、takeover_check(子域接管)、edge_classify(CDN/云资产/SaaS 一把梭
// ——「这个目标能不能直接打」的语境判定)。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/recon/cdnmatch"
	"github.com/c1ayooo/4zrec/internal/capability/recon/cdnorigin"
	"github.com/c1ayooo/4zrec/internal/capability/recon/cloudassets"
	"github.com/c1ayooo/4zrec/internal/capability/recon/dnsres"
	"github.com/c1ayooo/4zrec/internal/capability/recon/legacyhunter"
	"github.com/c1ayooo/4zrec/internal/capability/recon/saasdetect"
	"github.com/c1ayooo/4zrec/internal/capability/recon/takeover"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// newPoolAddr 测试注入的解析器地址(空=公共解析器;atomic_tools_test 覆盖)。
var newPoolAddr = ""

// dnsPool 共享解析池(判定工具用;并发由池信号量兜底)。
func (s *Server) dnsPool() *dnsres.Pool {
	if newPoolAddr != "" {
		return dnsres.NewPool([]string{newPoolAddr}, 32, 0, 0)
	}
	return dnsres.NewPool(nil, 32, 0, 0)
}

// toolCdnOrigin CDN 源站被动发现:证书 SAN + DNS 历史(SecurityTrails 可选)。
func (s *Server) toolCdnOrigin() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "cdn_origin",
		Description: "CDN 源站被动发现:经证书 SAN 与 DNS 历史(需 SecurityTrails key,可选)推断藏在 CDN 后面的源站 IP," +
			"附带当前边缘类型判定(CDN/云/WAF)。只查第三方数据源与 DNS 记录,不直接探测目标。找到源站≈绕过 CDN 直接打的前提线索。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"domain": map[string]any{"type": "string", "description": "目标主域"},
			},
			"required": []string{"domain"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Domain string `json:"domain"`
			}
			if err := json.Unmarshal(input, &in); err != nil || strings.TrimSpace(in.Domain) == "" {
				return actool.Errorf("domain 必填"), nil
			}
			origins, err := cdnorigin.Find(ctx, strings.TrimSpace(in.Domain), cdnorigin.Options{
				Timeout: 30 * time.Second, Resolver: s.dnsPool(),
			})
			if err != nil {
				return actool.Errorf("源站发现失败: " + err.Error()), nil
			}
			var b strings.Builder
			if len(origins) == 0 {
				fmt.Fprintf(&b, "%s 未发现 CDN 后源站(可能本就直连,或历史数据不足)\n", in.Domain)
			} else {
				var cand int
				for _, o := range origins {
					if !o.IsCDN {
						cand++
					}
				}
				fmt.Fprintf(&b, "%s 源站候选 %d 个(证书 SAN/DNS 历史推断,验证后再用):\n", in.Domain, cand)
				for _, o := range origins {
					if o.IsCDN {
						continue
					}
					fmt.Fprintf(&b, "- %s (证据 %s)\n", o.IP, strings.Join(o.Sources, ";"))
				}
			}
			// 当前边缘判定作为对照。
			s.classifyInto(&b, []string{strings.TrimSpace(in.Domain)})
			return actool.Text(b.String()), nil
		},
	})
}

// classifyInto 把 CDN/云/SaaS 判定写入输出(共用)。
func (s *Server) classifyInto(b *strings.Builder, domains []string) {
	pool := s.dnsPool()
	var saas *saasdetect.Matcher
	if m, err := saasdetect.LoadBuiltin(); err == nil {
		saas = m
	}
	for _, d := range domains {
		ans, err := pool.Resolve(context.Background(), d)
		if err != nil || ans == nil {
			continue
		}
		edge := cdnmatch.Classify(ans.CNAME, ans.IPs)
		parts := []string{fmt.Sprintf("边缘=%s/%s", edge.EdgeType, edge.EdgeName)}
		if res, ok := cloudassets.ExtractCNAME(ans.CNAME); ok {
			parts = append(parts, fmt.Sprintf("云资源=%s/%s:%s", res.Provider, res.Kind, res.Name))
		}
		if saas != nil {
			if m, ok := saas.Match(d); ok {
				parts = append(parts, fmt.Sprintf("SaaS=%s", m.Name))
			}
		}
		verdict := "可直连测试"
		if edge.EdgeType == "cdn" || edge.EdgeType == "waf" {
			verdict = "经 CDN/WAF——直连源站或绕过面优先(cdn_origin 找源站)"
		} else if cloud, ok := cloudassets.ExtractCNAME(ans.CNAME); ok {
			_ = cloud
			verdict = "指向云资源——优先核云归属与接管面"
		}
		fmt.Fprintf(b, "- %s → CNAME=%s IP=%v | %s | %s\n", d, orDash(ans.CNAME), ans.IPs, strings.Join(parts, " "), verdict)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// toolEdgeClassify 边缘判定一把梭:CDN/云资产/SaaS/接管指纹。
func (s *Server) toolEdgeClassify() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "edge_classify",
		Description: "边缘判定一把梭(只读 DNS 查询):对域名列表判定 CDN/WAF/云边缘、云资源 CNAME 归属、第三方 SaaS 特征、" +
			"子域接管指纹——每个目标给出「能不能直接打/该走哪条面」的结论。测前分类,决定直连还是找源站/核接管。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"domains": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "域名列表"},
			},
			"required": []string{"domains"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Domains []string `json:"domains"`
			}
			if err := json.Unmarshal(input, &in); err != nil || len(in.Domains) == 0 {
				return actool.Errorf("domains 必填"), nil
			}
			if len(in.Domains) > 200 {
				in.Domains = in.Domains[:200]
			}
			pool := s.dnsPool()
			var saas *saasdetect.Matcher
			if m, err := saasdetect.LoadBuiltin(); err == nil {
				saas = m
			}
			var b strings.Builder
			var takeovers []string
			for _, d := range in.Domains {
				d = strings.ToLower(strings.TrimSpace(d))
				if d == "" {
					continue
				}
				ans, err := pool.Resolve(ctx, d)
				if err != nil || ans == nil || len(ans.IPs) == 0 {
					fmt.Fprintf(&b, "- %s: 无解析(死域?接管必查)\n", d)
					if f := takeover.MatchFingerprint(""); f != nil {
						takeovers = append(takeovers, fmt.Sprintf("%s → %s", d, f.Service))
					}
					continue
				}
				edge := cdnmatch.Classify(ans.CNAME, ans.IPs)
				parts := []string{fmt.Sprintf("边缘=%s/%s", edge.EdgeType, edge.EdgeName)}
				if res, ok := cloudassets.ExtractCNAME(ans.CNAME); ok {
					parts = append(parts, fmt.Sprintf("云资源=%s/%s:%s", res.Provider, res.Kind, res.Name))
				}
				if saas != nil {
					if m, ok := saas.Match(d); ok {
						parts = append(parts, fmt.Sprintf("SaaS=%s", m.Name))
					}
				}
				if f := takeover.MatchFingerprint(ans.CNAME); f != nil {
					parts = append(parts, fmt.Sprintf("接管指纹=%s(CNAME 指向可注册/可接管面)", f.Service))
					if fd := takeover.Detect(takeover.Candidate{Subdomain: d, CNAME: ans.CNAME}); fd != nil {
						takeovers = append(takeovers, fmt.Sprintf("%s → %s(%s)", d, fd.Service, fd.Evidence))
					} else {
						takeovers = append(takeovers, fmt.Sprintf("%s → %s(待验证)", d, f.Service))
					}
				}
				verdict := "可直连测试"
				switch {
				case edge.EdgeType == "cdn" || edge.EdgeType == "waf":
					verdict = "经 CDN/WAF——优先找源站(cdn_origin)或绕过面"
				case strings.Contains(strings.Join(parts, " "), "云资源="):
					verdict = "指向云资源——核云归属/接管面"
				case strings.Contains(strings.Join(parts, " "), "SaaS="):
					verdict = "第三方 SaaS——测租户面与配置,不打 SaaS 厂商"
				}
				fmt.Fprintf(&b, "- %s → CNAME=%s IP=%v | %s | %s\n", d, orDash(ans.CNAME), ans.IPs, strings.Join(parts, " "), verdict)
			}
			if len(takeovers) > 0 {
				fmt.Fprintf(&b, "\n接管线索 %d 条:\n", len(takeovers))
				for _, t := range takeovers {
					fmt.Fprintf(&b, "- %s\n", t)
				}
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolLegacyHunter 遗留系统猎人:wayback 历史 + 框架指纹 + 备份探测(预算内)。
func (s *Server) toolLegacyHunter() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "legacy_hunter",
		Description: "遗留系统猎人:拉 Wayback 历史端点做老框架/老系统指纹(零出网),可选开启预算内的当前状态与备份后缀探测" +
			"(找仍在线的老后台/备份文件)。probe=true 是主动探测,须经确认且只对授权范围。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"domain":     map[string]any{"type": "string", "description": "目标主域"},
				"probe":      map[string]any{"type": "boolean", "description": "主动探测当前状态/备份后缀(默认 false 仅历史指纹)"},
				"max_probes": map[string]any{"type": "integer", "description": "主动探测请求预算(默认 150)"},
			},
			"required": []string{"domain"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				Domain string `json:"domain"`
				Probe  bool   `json:"probe"`
			}
			_ = json.Unmarshal(input, &in)
			if in.Probe {
				return actool.AskUser("遗留猎人主动探测(历史端点现状+备份后缀)目标: " + in.Domain)
			}
			return actool.Allowed()
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Domain    string `json:"domain"`
				Probe     bool   `json:"probe"`
				MaxProbes int    `json:"max_probes"`
			}
			if err := json.Unmarshal(input, &in); err != nil || strings.TrimSpace(in.Domain) == "" {
				return actool.Errorf("domain 必填"), nil
			}
			history, err := legacyhunter.QueryCDX(ctx, strings.TrimSpace(in.Domain), legacyhunter.CDXOptions{Limit: 500})
			if err != nil {
				return actool.Errorf("Wayback 历史拉取失败: " + err.Error()), nil
			}
			h := legacyhunter.New(legacyhunter.Options{
				Domain: strings.TrimSpace(in.Domain), EnableProbe: in.Probe, MaxProbes: in.MaxProbes,
			})
			findings, err := h.Run(ctx, history)
			if err != nil {
				return actool.Errorf("猎人运行失败: " + err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "历史端点 %d 条;探测=%v\n", len(history), in.Probe)
			if findings == nil || (len(findings.Frameworks) == 0 && len(findings.Endpoints) == 0) {
				b.WriteString("未命中遗留系统特征\n")
				return actool.Text(b.String()), nil
			}
			for _, f := range findings.Frameworks {
				line := fmt.Sprintf("- 框架 %s %s(%s", f.Name, f.Priority, f.URL)
				if f.CVE != "" {
					line += " / " + f.CVE
				}
				line += ")\n"
				b.WriteString(line)
			}
			for _, ep := range findings.Endpoints {
				for _, bk := range ep.BackupHits {
					fmt.Fprintf(&b, "- 备份命中 %s\n", bk)
				}
			}
			if findings.EOLNote != "" {
				fmt.Fprintf(&b, "提示: %s\n", findings.EOLNote)
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolTakeoverCheck 子域接管检测:Dangling CNAME 指纹匹配。
func (s *Server) toolTakeoverCheck() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "takeover_check",
		Description: "子域接管检测(只读 DNS):对域名列表查 CNAME,命中已知可接管服务的指纹(GitHub Pages/Heroku/S3/泛域名服务等)" +
			"给出接管线索与验证建议。配合 subdomain_enum 的死域清单使用最佳。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"domains": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "域名列表"},
			},
			"required": []string{"domains"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Domains []string `json:"domains"`
			}
			if err := json.Unmarshal(input, &in); err != nil || len(in.Domains) == 0 {
				return actool.Errorf("domains 必填"), nil
			}
			sort.Strings(in.Domains)
			pool := s.dnsPool()
			var (
				b        strings.Builder
				hitCount int
			)
			for _, d := range in.Domains {
				d = strings.ToLower(strings.TrimSpace(d))
				if d == "" {
					continue
				}
				ans, err := pool.Resolve(ctx, d)
				cname := ""
				dead := err != nil || ans == nil || len(ans.IPs) == 0
				if ans != nil {
					cname = ans.CNAME
				}
				var fd *takeover.Finding
				if f := takeover.MatchFingerprint(cname); f != nil {
					fd = takeover.Detect(takeover.Candidate{Subdomain: d, CNAME: cname})
				}
				if fd == nil && !dead {
					continue
				}
				hitCount++
				if fd != nil {
					fmt.Fprintf(&b, "- %s → %s:接管证据 %s\n", d, fd.Service, fd.Evidence)
				} else {
					if f := takeover.MatchFingerprint(cname); f != nil {
						fmt.Fprintf(&b, "- %s(死域) CNAME=%s → %s 指纹,待验证\n", d, cname, f.Service)
					} else {
						fmt.Fprintf(&b, "- %s:死域无 CNAME(注册域接管方向)\n", d)
					}
				}
			}
			if hitCount == 0 {
				return actool.Text("无接管线索(全部健康或无已知指纹)"), nil
			}
			fmt.Fprintf(&b, "\n命中 %d 条,按服务对应的注册/认领流程验证后再利用\n", hitCount)
			return actool.Text(b.String()), nil
		},
	})
}

// atomicTools 原子判定工具族。
func (s *Server) atomicTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolCdnOrigin(),
		s.toolEdgeClassify(),
		s.toolLegacyHunter(),
		s.toolTakeoverCheck(),
	}
}
