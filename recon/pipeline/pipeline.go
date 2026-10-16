// Package pipeline 主动测绘四阶段流水线:子域(被动/派生/爆破)→ DNS 解析存活性
// → 端口扫描与服务识别 → HTTP 指纹。各阶段独立开关;评分走 recon/score(P0-P4);
// 逐阶段进度回写 recon_runs(异步事实源);入库走 AssetStore(范围语义由调用方
// 的 project_id 认领承担)。阶段组成件全部为已移植包(4zreco 同源),本包只做
// 4zrec 侧的编排与存储适配——对应 4zreco internal/recon/pipeline 的角色。
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/db"
	"github.com/c1ayooo/4zrec/fingerprint"
	"github.com/c1ayooo/4zrec/recon/brute"
	"github.com/c1ayooo/4zrec/recon/dnsres"
	"github.com/c1ayooo/4zrec/recon/permute"
	"github.com/c1ayooo/4zrec/recon/portscan"
	"github.com/c1ayooo/4zrec/recon/score"
	"github.com/c1ayooo/4zrec/recon/subdomain"
	"github.com/c1ayooo/4zrec/recon/svcid"
)

// Options 流水线配置(各开关独立;至少开一个阶段)。
type Options struct {
	Domains []string

	EnableSubdomain bool // 阶段1a:被动源枚举
	EnablePermute   bool // 阶段1b:候选派生
	EnableBrute     bool // 阶段1c:子域名爆破
	EnableDNS       bool // 阶段2:DNS 解析存活性过滤
	EnablePortscan  bool // 阶段3:端口扫描+服务识别
	EnableHTTP      bool // 阶段4:HTTP 指纹
	PortsSet        string
	QPS             int // 爆破限速
	Rate            int // 端口扫描限速

	ProjectID int64
	Resolvers []string
	// HTTPClient 阶段4 注入(测试打桩/代理);nil 用默认 10s 超时直连。
	HTTPClient *http.Client
	// FingerprintRules 指纹规则(EnabledRules 预取注入);nil 跳过规则匹配
	// (Observation 仍会建立 http 服务资产,只是不带 technologies)。
	FingerprintRules []fingerprint.CompiledRule
}

// Stats 逐阶段统计(回写 recon_runs.stats)。
type Stats struct {
	Candidates       int            `json:"candidates"` // 阶段1产出(含来源分布)
	FromPassive      int            `json:"from_passive"`
	FromPermute      int            `json:"from_permute"`
	FromBrute        int            `json:"from_brute"`
	WildcardFiltered int            `json:"wildcard_filtered"` // 泛解析基线剔除
	Live             int            `json:"live"`              // 解析成功(有 A 记录)
	NewAssets        int            `json:"new_assets"`        // 本轮新入库的子域(增量通知用)
	Dead             int            `json:"dead"`              // NXDOMAIN/无记录
	ScanIPs          int            `json:"scan_ips"`
	OpenPorts        int            `json:"open_ports"`
	HTTPProbed       int            `json:"http_probed"`
	HTTPAlive        int            `json:"http_alive"`
	Levels           map[string]int `json:"levels"` // p0..p4 分布
	Errors           []string       `json:"errors,omitempty"`
}

type liveName struct {
	name  string
	ips   []string
	cname string
	score int
	level string
}

// Progress 每阶段完成后的回调(stage: subdomain/dns/portscan/http)。
type Progress func(stage string, stats Stats)

// Run 执行流水线。pg 为 nil 时不入库(纯计算/测试);ctx 取消时尽快返回已得结果
// 并标记中断错误。
func Run(ctx context.Context, opts Options, pg *db.DB, progress Progress) (*Stats, error) {
	if len(opts.Domains) == 0 {
		return nil, fmt.Errorf("domains 为空")
	}
	stats := &Stats{Levels: map[string]int{}}
	as := func() *db.AssetStore {
		if pg == nil {
			return nil
		}
		return pg.Assets()
	}

	// ---------- 阶段1:候选收集 ----------
	type cand struct {
		name      string
		ips       []string
		cname     string
		fromBrute bool
	}
	cands := map[string]*cand{}
	addCand := func(name string, ips []string, fromBrute bool) {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name == "" || !strings.Contains(name, ".") {
			return
		}
		if c, ok := cands[name]; ok {
			if fromBrute && len(ips) > 0 {
				c.ips = ips
				c.fromBrute = true
			}
			return
		}
		cands[name] = &cand{name: name, ips: ips, fromBrute: fromBrute}
	}

	// 泛解析基线(爆破与被动候选共用;per domain)。
	pools := dnsres.NewPool(opts.Resolvers, 64, 0, 0)
	wildcards := map[string]map[string]bool{}
	detectWildcard := func(domain string) map[string]bool {
		if w, ok := wildcards[domain]; ok {
			return w
		}
		w := map[string]bool{}
		if wr, err := pools.DetectWildcard(ctx, domain, 3); err == nil && wr.IsWildcard {
			w = wr.IPs
		}
		wildcards[domain] = w
		return w
	}

	for _, domain := range opts.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}
		if opts.EnableSubdomain {
			res, err := subdomain.Enumerate(ctx, domain, subdomain.Options{
				EnableCT: true, EnablePassiveDNS: true, EnableCNPassiveDNS: true,
				Timeout: 60 * time.Second, Limit: 5000,
			})
			if err != nil {
				stats.Errors = append(stats.Errors, fmt.Sprintf("被动枚举 %s: %v", domain, err))
			} else {
				for _, h := range res.Hits {
					before := len(cands)
					addCand(h.Name, nil, false)
					if len(cands) > before {
						stats.FromPassive++
					}
				}
			}
		}
		if opts.EnableBrute {
			hits, _, err := brute.Brute(ctx, domain, brute.Options{Resolvers: opts.Resolvers, QPS: opts.QPS})
			if err != nil {
				stats.Errors = append(stats.Errors, fmt.Sprintf("爆破 %s: %v", domain, err))
			} else {
				baseline := detectWildcard(domain)
				for _, h := range hits {
					if len(baseline) > 0 && subsetOf(h.IPs, baseline) {
						stats.WildcardFiltered++
						continue
					}
					before := len(cands)
					addCand(h.Name, h.IPs, true)
					if len(cands) > before {
						stats.FromBrute++
					}
				}
			}
		}
	}
	// 派生:基于已知子域(被动+爆破)生成变形候选,交给阶段2解析验证。
	if opts.EnablePermute {
		for _, domain := range opts.Domains {
			var known []string
			for _, c := range cands {
				if strings.HasSuffix(c.name, "."+domain) {
					known = append(known, c.name)
				}
			}
			for _, d := range permute.Generate(known, domain, 2000) {
				before := len(cands)
				addCand(d, nil, false)
				if len(cands) > before {
					stats.FromPermute++
				}
			}
		}
	}
	stats.Candidates = len(cands)
	if progress != nil {
		progress("subdomain", *stats)
	}

	// ---------- 阶段2:DNS 存活性 ----------
	var live []liveName
	ipSeen := map[string]bool{}
	var scanIPs []string
	for _, c := range cands {
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}
		ips := c.ips
		if len(ips) == 0 && (opts.EnableDNS || opts.EnableSubdomain || opts.EnablePermute) {
			// 爆制命中自带 IP;其余解析确认。
			if ans, err := pools.Resolve(ctx, c.name); err == nil && ans != nil && len(ans.IPs) > 0 {
				// 泛解析过滤:候选解析到所在域基线 IP 集 → 视为噪音。
				domain := parentDomain(c.name, opts.Domains)
				if baseline := detectWildcard(domain); len(baseline) > 0 && subsetOf(ans.IPs, baseline) {
					stats.WildcardFiltered++
					continue
				}
				ips = ans.IPs
				c.cname = ans.CNAME
			}
		}
		if len(ips) == 0 {
			stats.Dead++
			continue
		}
		stats.Live++
		lv, lvl := scoreFor(c.name, ips, nil, score.Input{})
		live = append(live, liveName{name: c.name, ips: ips, cname: c.cname, score: lv, level: lvl})
		stats.Levels[lvl]++
		for _, ip := range ips {
			if !ipSeen[ip] {
				ipSeen[ip] = true
				scanIPs = append(scanIPs, ip)
			}
		}
	}
	if progress != nil {
		progress("dns", *stats)
	}

	// ---------- 入库:子域 + IP ----------
	if store := as(); store != nil {
		for _, ln := range live {
			var existed int
			_ = pg.QueryRow(`SELECT 1 FROM assets WHERE domain=$1 LIMIT 1`, ln.name).Scan(&existed)
			id, err := store.UpsertSubdomain(db.UpsertSubdomainReq{
				Domain: ln.name, RecordType: "A", RecordValue: ln.ips,
			})
			if err != nil {
				continue
			}
			if existed == 0 {
				stats.NewAssets++
			}
			if opts.ProjectID > 0 {
				_, _ = store.StampDiscoveredAsset(id, opts.ProjectID)
			}
			_, _ = pg.Exec(`UPDATE assets SET recon_level=$2 WHERE id=$1 AND (recon_level IS NULL OR recon_level>$2)`, id, ln.level)
		}
	}

	// ---------- 阶段3:端口扫描 + 服务识别 ----------
	type svcKey struct {
		ip   string
		port int
	}
	svcByIDPPort := map[svcKey]svcid.Service{}
	if opts.EnablePortscan && len(scanIPs) > 0 {
		pSet, pCustom := "top100", ""
		switch opts.PortsSet {
		case "", "top100", "web":
			pSet = opts.PortsSet
		default: // 逗号列表/范围段
			pCustom = opts.PortsSet
		}
		results := portscan.Scan(ctx, scanIPs, portscan.Options{Ports: portscan.ResolvePorts(pSet, pCustom), RatePerSec: opts.Rate})
		stats.ScanIPs = len(scanIPs)
		stats.OpenPorts = len(results)
		byIP := map[string][]portscan.Result{}
		for _, r := range results {
			byIP[r.IP] = append(byIP[r.IP], r)
		}
		if store := as(); store != nil {
			for ip, rs := range byIP {
				open := make([]db.PortService, 0, len(rs))
				for _, r := range rs {
					open = append(open, db.PortService{Port: r.Port, Service: r.Service})
				}
				if id, err := store.UpsertIP(db.UpsertIPReq{IP: ip, OpenPorts: open}); err == nil && opts.ProjectID > 0 {
					_, _ = store.StampDiscoveredAsset(id, opts.ProjectID)
				}
			}
		}
		for ip, rs := range byIP {
			ports := make([]int, 0, len(rs))
			for _, r := range rs {
				ports = append(ports, r.Port)
			}
			for _, sv := range svcid.Scan(ctx, ip, ports, svcid.Options{Timeout: 3 * time.Second}) {
				svcByIDPPort[svcKey{ip, sv.Port}] = sv
			}
		}
		if progress != nil {
			progress("portscan", *stats)
		}
	}

	// ---------- 阶段4:HTTP 指纹 ----------
	if opts.EnableHTTP {
		client := opts.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // 不跟跳转,指纹按首响应算
			}}
		}
		type httpTarget struct {
			host   string
			port   int
			scheme string
		}
		var targets []httpTarget
		for key, sv := range svcByIDPPort {
			if sv.Protocol == "http" || sv.Protocol == "https" {
				targets = append(targets, httpTarget{key.ip, key.port, sv.Protocol})
			}
		}
		// 80/443 直连目标(未开端口扫描时的兜底:活域名直接探 web)。
		if !opts.EnablePortscan {
			for _, ln := range live {
				targets = append(targets, httpTarget{ln.name, 80, "http"}, httpTarget{ln.name, 443, "https"})
			}
		}
		for _, tgt := range targets {
			if ctx.Err() != nil {
				break
			}
			url := fmt.Sprintf("%s://%s", tgt.scheme, net.JoinHostPort(tgt.host, fmt.Sprintf("%d", tgt.port)))
			stats.HTTPProbed++
			obs, err := fingerprint.ProbeHTTPObservation(ctx, url, client)
			if err != nil || obs.Status == 0 {
				continue
			}
			stats.HTTPAlive++
			techs := matchTechnologies(opts.FingerprintRules, obs)
			if store := as(); store != nil {
				var code = obs.Status
				if id, err := store.UpsertHTTPService(db.UpsertHTTPServiceReq{
					URL: url, StatusCode: &code, PageTitle: obs.Title,
					FaviconMMH3: obs.IconHash, Technologies: techs,
				}); err == nil && opts.ProjectID > 0 {
					_, _ = store.StampDiscoveredAsset(id, opts.ProjectID)
				}
			}
		}
		if progress != nil {
			progress("http", *stats)
		}
	}

	sort.Strings(stats.Errors)
	return stats, ctx.Err()
}

// scoreFor 计算单个活子域的 P0-P4。阶段2时 HTTP 维度未知(后续阶段补充评分
// 留给资产侧重算;首版以网络面维度定级)。
func scoreFor(name string, ips []string, ports []int, httpIn score.Input) (int, string) {
	total, _, _ := score.Compute(score.Input{
		OpenPorts: ports, Server: httpIn.Server, Title: httpIn.Title,
		Fingerprints: httpIn.Fingerprints, HTTPStatus: httpIn.HTTPStatus, HTTPSeen: httpIn.HTTPSeen,
	})
	return total, score.Level(total)
}

func subsetOf(ips []string, baseline map[string]bool) bool {
	for _, ip := range ips {
		if !baseline[ip] {
			return false
		}
	}
	return len(ips) > 0
}

func parentDomain(name string, domains []string) string {
	for _, d := range domains {
		if strings.HasSuffix(name, "."+d) {
			return d
		}
	}
	return domains[0]
}

func matchTechnologies(rules []fingerprint.CompiledRule, obs fingerprint.Observation) []string {
	if len(rules) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range fingerprint.MatchObservation(rules, obs) {
		if m.Product != "" && !seen[m.Product] {
			seen[m.Product] = true
			out = append(out, m.Product)
		}
	}
	sort.Strings(out)
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// MarshalStats 便捷序列化(避免每个调用方重复处理错误)。
func MarshalStats(s Stats) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
