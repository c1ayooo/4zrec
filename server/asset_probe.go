// asset_probe.go 待审批资产的轻量探活/归属线索:人工在批准前快速判断
// "这个 IP/域名是否还活着、是否真的属于本项目授权面"。
//
// 只做无害探测:PTR/DNS 解析、TCP connect、TLS 证书读取、GET / 取标题;
// 不发任何攻击载荷,单资产总超时 ~8s,批量并发上限 20。
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/db"
)

// AssetProbeResult 单个资产的探活结果(JSON 直接给 UI)。
type AssetProbeResult struct {
	ID         int64    `json:"id"`
	Alive      bool     `json:"alive"`
	Ports      []int    `json:"ports,omitempty"`
	PTR        []string `json:"ptr,omitempty"`
	CertNames  []string `json:"cert_names,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
	Server     string   `json:"server,omitempty"`
	Title      string   `json:"title,omitempty"`
	// Ownership 是"看起来属于本项目"的线索:PTR/证书 SAN 命中项目授权域。
	Ownership []string `json:"ownership,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// assetsProbe POST /api/assets/probe {ids:[...], project_id?}
// 对选中的待审批资产做轻量探活,返回逐资产结果。project_id 用于归属线索比对
// (不传时用资产自身 project_id)。
func (s *Server) assetsProbe(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		IDs       []int64 `json:"ids"`
		ProjectID int64   `json:"project_id"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, 400, "ids 不能为空")
		return
	}
	if len(req.IDs) > 300 {
		req.IDs = req.IDs[:300]
	}
	// 项目级 API Key:强制本项目,并拒绝包含他项目资产的批量请求。
	if scopeProject := scopedProjectID(r.Context()); scopeProject > 0 {
		if req.ProjectID > 0 && req.ProjectID != scopeProject {
			writeErr(w, 403, "项目级 API Key 只能探测本项目资产")
			return
		}
		req.ProjectID = scopeProject
		outside, err := pg.AssetsOutsideProject(req.IDs, scopeProject)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if len(outside) > 0 {
			writeErr(w, 403, "ids 包含其他项目的资产")
			return
		}
	}
	assets, err := pg.Assets().GetByIDs(req.IDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(assets) == 0 {
		writeJSON(w, 200, map[string]any{"results": []AssetProbeResult{}})
		return
	}

	// 每个项目只读一次范围规则(归属线索比对用)。
	rulesMu := sync.Mutex{}
	rulesByProject := map[int64][]db.ProjectScope{}
	rulesFor := func(projectID int64) []db.ProjectScope {
		pid := req.ProjectID
		if pid <= 0 {
			pid = projectID
		}
		if pid <= 0 {
			return nil
		}
		rulesMu.Lock()
		defer rulesMu.Unlock()
		if rules, ok := rulesByProject[pid]; ok {
			return rules
		}
		rules, _ := pg.ProjectScopeRules(pid)
		rulesByProject[pid] = rules
		return rules
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	out := make([]AssetProbeResult, 0, len(assets))
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	sem := make(chan struct{}, 20)
	for _, a := range assets {
		wg.Add(1)
		sem <- struct{}{}
		go func(a *db.Asset) {
			defer wg.Done()
			defer func() { <-sem }()
			res := probeAsset(ctx, a, rulesFor(derefProject(a.ProjectID)))
			mu.Lock()
			out = append(out, res)
			mu.Unlock()
		}(a)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, 200, map[string]any{"results": out})
}

func derefProject(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

var reHTMLTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

var probeHTTPClient = &http.Client{
	Timeout: 4 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 探活读取自签证书也是有效线索
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 3 * time.Second,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// probeAsset 对单个资产做探活。host 优先级:IP > 域名 > URL host。
func probeAsset(ctx context.Context, a *db.Asset, rules []db.ProjectScope) AssetProbeResult {
	res := AssetProbeResult{ID: a.ID}
	host, scheme, urlPort := assetProbeHost(a)
	if host == "" {
		res.Error = "无可用主机"
		return res
	}

	// PTR:光有 IP 时,反查域名是最直接的归属线索。
	if net.ParseIP(host) != nil {
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		names, _ := net.DefaultResolver.LookupAddr(lookupCtx, host)
		cancel()
		for _, n := range names {
			n = strings.TrimSuffix(strings.TrimSpace(n), ".")
			if n != "" {
				res.PTR = append(res.PTR, n)
			}
		}
	} else {
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ips, _ := net.DefaultResolver.LookupHost(lookupCtx, host)
		cancel()
		if len(ips) > 0 {
			res.Alive = true // DNS 可解析即视为存活线索
		}
	}

	ports := assetProbePorts(a, urlPort)
	for _, port := range ports {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		res.Ports = append(res.Ports, port)
		res.Alive = true
		if port == 443 || port == 8443 {
			readTLSCert(conn, host, a, &res)
		}
		_ = conn.Close()
	}

	// HTTP:优先资产自带的 URL,否则按 443/80 猜协议。
	targets := assetProbeURLs(a, host, ports, scheme)
	for _, target := range targets {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		resp, err := probeHTTPClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		res.HTTPStatus = resp.StatusCode
		res.Server = resp.Header.Get("Server")
		if m := reHTMLTitle.FindSubmatch(body); len(m) > 1 {
			title := strings.Join(strings.Fields(string(m[1])), " ")
			if len(title) > 160 {
				title = title[:160]
			}
			res.Title = title
		}
		res.Alive = true
		break
	}

	res.Ownership = ownershipHints(a, rules, res.PTR, res.CertNames)
	return res
}

// readTLSCert 读取对端证书的 CN/SAN(归属判定最硬的线索之一)。
func readTLSCert(rawConn net.Conn, host string, a *db.Asset, res *AssetProbeResult) {
	serverName := a.Domain
	if serverName == "" && net.ParseIP(host) == nil {
		serverName = host
	}
	conn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true, ServerName: serverName}) //nolint:gosec
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := conn.Handshake(); err != nil {
		return
	}
	state := conn.ConnectionState()
	_ = conn.Close()
	for _, cert := range state.PeerCertificates {
		seen := map[string]bool{}
		for _, name := range append(append([]string{}, cert.DNSNames...), cert.Subject.CommonName) {
			name = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(name)), ".")
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			res.CertNames = append(res.CertNames, name)
		}
	}
}

// ownershipHints 把 PTR / 证书 SAN 与项目授权域比对,给出"像是本项目"的线索。
func ownershipHints(a *db.Asset, rules []db.ProjectScope, ptr, certNames []string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, n := range ptr {
		if rule, ok := db.MatchProjectScope(rules, n, ""); ok {
			add(fmt.Sprintf("PTR %s 命中授权域 %s", n, rule.Domain))
		} else if a.RootDomain != "" && (n == a.RootDomain || strings.HasSuffix(n, "."+a.RootDomain)) {
			add(fmt.Sprintf("PTR %s 与资产同根域", n))
		}
	}
	for _, n := range certNames {
		if rule, ok := db.MatchProjectScope(rules, n, ""); ok {
			add(fmt.Sprintf("证书 SAN 含授权域 %s", rule.Domain))
		} else if a.RootDomain != "" && (n == a.RootDomain || strings.HasSuffix(n, "."+a.RootDomain)) {
			add(fmt.Sprintf("证书 SAN 含同根域 %s", n))
		}
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

// assetProbeHost 返回探活主机/URL scheme/URL 端口。
func assetProbeHost(a *db.Asset) (host, scheme string, port int) {
	if a.URL != "" {
		if u, err := url.Parse(a.URL); err == nil && u.Hostname() != "" {
			host, scheme = u.Hostname(), strings.ToLower(u.Scheme)
			if p, err := strconv.Atoi(u.Port()); err == nil {
				port = p
			}
			if port == 0 {
				if scheme == "https" {
					port = 443
				} else {
					port = 80
				}
			}
			return
		}
	}
	if a.IP != "" {
		return a.IP, "", 0
	}
	if a.Domain != "" {
		return a.Domain, "", 0
	}
	return "", "", 0
}

func assetProbePorts(a *db.Asset, urlPort int) []int {
	seen := map[int]bool{}
	var ports []int
	add := func(p int) {
		if p <= 0 || p > 65535 || seen[p] || len(ports) >= 4 {
			return
		}
		seen[p] = true
		ports = append(ports, p)
	}
	if urlPort > 0 {
		add(urlPort)
	}
	if a.Port != nil {
		add(*a.Port)
	}
	for _, op := range a.OpenPorts {
		if n, ok := op["port"].(float64); ok {
			add(int(n))
		}
	}
	add(80)
	add(443)
	return ports
}

func assetProbeURLs(a *db.Asset, host string, ports []int, scheme string) []string {
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		for _, e := range out {
			if e == s {
				return
			}
		}
		out = append(out, s)
	}
	if a.URL != "" && scheme != "" {
		add(a.URL)
	}
	for _, p := range ports {
		switch p {
		case 443:
			add("https://" + net.JoinHostPort(host, "443") + "/")
		case 80:
			add("http://" + net.JoinHostPort(host, "80") + "/")
		default:
			// 非标准端口两种都试,但总量有限。
			add("http://" + net.JoinHostPort(host, strconv.Itoa(p)) + "/")
			add("https://" + net.JoinHostPort(host, strconv.Itoa(p)) + "/")
		}
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}
