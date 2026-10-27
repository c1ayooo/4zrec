// crawl_tools.go 本地基础收集补齐:web_crawl(同域爬虫)与 dir_scan(目录探测)。
// 与 4zreark 的 crawler/dir_scan 任务类型对齐——平台自身保底能力,轻量、单点、
// 离线可用;批量/重采集走 4zreark MCP 增强通道(已配置时)。
// RoE 门控同 portscan_tools:挂项目上下文时目标必须命中项目授权范围,范围外硬拒绝;
// 无项目上下文时以人工确认为门。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/recon/directhttp"
	"github.com/c1ayooo/4zrec/internal/capability/recon/fingerprint"
	"github.com/c1ayooo/4zrec/internal/domain/db"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// crawlMaxPages 单次爬取页数上限(灌库红线)。
const crawlMaxPages = 100

// dirScanMaxRequests 单次目录探测请求上限。
const dirScanMaxRequests = 400

// dirScanDict 内置目录字典:认证入口/管理面/API/敏感文件/备份残留,常规清单。
var dirScanDict = []string{
	"/admin", "/admin/", "/admin/login", "/administrator/", "/manage/", "/manager/", "/dashboard",
	"/login", "/login/", "/signin", "/auth/login", "/sso/login", "/user/login", "/adminer.php",
	"/api", "/api/", "/api/v1", "/api/v2", "/api-docs", "/v2/api-docs", "/swagger", "/swagger/",
	"/swagger/index.html", "/swagger-ui.html", "/swagger-ui/", "/openapi.json", "/doc.html",
	"/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/mappings", "/druid", "/druid/",
	"/nacos/", "/eureka/", "/consul", "/apollo/", "/solr/", "/elasticsearch/", "/kibana/",
	"/.env", "/.env.bak", "/.git/config", "/.git/HEAD", "/.svn/entries", "/.DS_Store",
	"/backup", "/backup/", "/backup.zip", "/backup.tar.gz", "/bak/", "/db.sql", "/dump.sql",
	"/robots.txt", "/sitemap.xml", "/crossorigin.xml", "/security.txt", "/WEB-INF/web.xml",
	"/phpinfo.php", "/info.php", "/test.php", "/admin.php",
	"/register", "/signup", "/reset-password", "/forgot-password",
	"/upload", "/uploads/", "/static/", "/assets/", "/media/",
	"/graphql", "/graphiql", "/playground", "/console", "/jetty/", "/jmx-console/",
	"/server-status", "/server-info", "/.well-known/security.txt", "/debug/", "/trace",
	"/config", "/config.json", "/config.yml", "/application.properties", "/application.yml",
	"/jenkins/", "/job/", "/view/All/", "/sonar/", "/gitlab/", "/jira/", "/confluence/",
	"/index.php", "/index.bak", "/login.bak", "/old/", "/test/", "/dev/", "/uat/", "/beta/",
}

// crawlFetch 抓取单页:返回 (状态码, body 截断, 最终 URL)。
func crawlFetch(ctx context.Context, client *http.Client, rawURL string) (int, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", rawURL
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; 4zrec-crawl/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", rawURL
	}
	defer resp.Body.Close()
	body := readBodyCapped(resp, 512<<10)
	return resp.StatusCode, body, resp.Request.URL.String()
}

// readBodyCapped 读取响应体,超 max 字节截断(爬虫/探测都不要无界读)。
func readBodyCapped(resp *http.Response, max int64) string {
	defer resp.Body.Close()
	if max <= 0 {
		max = 512 << 10
	}
	buf := make([]byte, 0, 32*1024)
	for int64(len(buf)) < max {
		chunk := make([]byte, 32*1024)
		n, err := resp.Body.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			break
		}
	}
	if int64(len(buf)) > max {
		buf = buf[:max]
	}
	return string(buf)
}

// crawlScopeCheck RoE 门控:目标 host 必须命中项目授权范围(域名后缀或 IP)。
func (s *Server) crawlScopeCheck(projectID int64, host string) error {
	if projectID <= 0 {
		return nil
	}
	rules, err := s.m.pg.ProjectScopeRules(projectID)
	if err != nil {
		return fmt.Errorf("RoE 校验失败(读取项目范围): %w", err)
	}
	if _, ok := db.MatchProjectScope(rules, host, ""); ok {
		return nil
	}
	return fmt.Errorf("【RoE 拒绝】目标 %s 不在项目 %d 授权范围内。请只采集授权内目标", host, projectID)
}

// toolWebCrawl 同域爬虫:BFS 抓取同域页面,页内链接入 endpoint 资产,外域仅提示。
func (s *Server) toolWebCrawl() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "web_crawl",
		Description: "同域 Web 爬虫(平台内置保底能力):从起点 BFS 抓取同域页面(默认深度 2、上限 30 页)," +
			"页内链接落 endpoint 资产;外域链接只提示不抓。适合摸清单站路由面;批量/多站采集走 4zreark MCP 增强通道" +
			"(已配置时)。挂项目上下文时目标必须命中项目授权范围,范围外硬拒绝。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":        map[string]any{"type": "string", "description": "起点 URL(如 https://www.example.com/)"},
				"max_pages":  map[string]any{"type": "integer", "description": "最多抓取页面数(默认 30,上限 100)"},
				"max_depth":  map[string]any{"type": "integer", "description": "最大 BFS 深度(默认 2)"},
				"project_id": map[string]any{"type": "integer", "description": "归属项目(可选;缺省取任务/会话挂载)"},
			},
			"required": []string{"url"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			// 主动探测:过操作者的目(与 port_scan/subdomain_brute 同语义)。
			var in struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(input, &in)
			if u := strings.TrimSpace(in.URL); u != "" {
				return actool.AskUser("同域爬虫(主动抓取)起点: " + u)
			}
			return actool.AskUser("同域爬虫:确认起点 URL")
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				URL       string `json:"url"`
				MaxPages  int    `json:"max_pages"`
				MaxDepth  int    `json:"max_depth"`
				ProjectID int64  `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			seed := strings.TrimSpace(in.URL)
			if !isHTTPURL(seed) {
				seed = "https://" + seed
			}
			u, err := url.Parse(seed)
			if err != nil || u.Host == "" {
				return actool.Errorf("起点 URL 不合法: " + in.URL), nil
			}
			projectID := s.roeProjectID(ctx, in.ProjectID)
			if err := s.crawlScopeCheck(projectID, u.Hostname()); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			maxPages := in.MaxPages
			if maxPages <= 0 {
				maxPages = 30
			}
			if maxPages > crawlMaxPages {
				maxPages = crawlMaxPages
			}
			maxDepth := in.MaxDepth
			if maxDepth <= 0 {
				maxDepth = 2
			}

			result := crawlSameHost(ctx, directhttp.Client(&http.Client{Timeout: 12 * time.Second}), seed, maxPages, maxDepth)
			// 入库:endpoint 资产(GET),归属项目时打授权状态。
			as := s.m.Assets()
			imported := 0
			endpoints := result.endpoints
			sort.Strings(endpoints)
			for _, ep := range endpoints {
				id, err := as.UpsertEndpoint(db.UpsertEndpointReq{URL: ep, Method: "GET"})
				if err != nil {
					continue
				}
				imported++
				if projectID > 0 {
					_, _ = as.StampDiscoveredAsset(id, projectID)
				}
			}

			var b strings.Builder
			fmt.Fprintf(&b, "爬取 %s:抓取 %d 页(状态分布 %v),入 endpoint 资产 %d 条\n", u.Hostname(), result.fetched, result.statuses, imported)
			if len(result.errs) > 0 {
				fmt.Fprintf(&b, "抓取失败示例: %s\n", strings.Join(result.errs, ", "))
			}
			show := endpoints
			if len(show) > 40 {
				show = show[:40]
			}
			for _, ep := range show {
				b.WriteString("- " + ep + "\n")
			}
			if len(endpoints) > len(show) {
				fmt.Fprintf(&b, "…等 %d 条\n", len(endpoints)-len(show))
			}
			if len(result.external) > 0 {
				fmt.Fprintf(&b, "外域链接主机(未抓取): %v\n", sortedKeysStr(result.external))
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolDirScan 轻量目录探测:内置字典+可选自定义词表,命中(非 404/410)入库。
func (s *Server) toolDirScan() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "dir_scan",
		Description: "目录探测(平台内置保底能力):内置 ~130 条常规路径(管理面/API/敏感文件/备份/认证入口)" +
			"+ 可选自定义词表,小并发(≤10)探测,非 404/410 视为命中并落 endpoint 资产。" +
			"适合单站快速摸路;重型目录爆破走 4zreark MCP 增强通道(已配置时)。" +
			"挂项目上下文时目标必须命中项目授权范围,范围外硬拒绝。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":        map[string]any{"type": "string", "description": "目标基址(如 https://www.example.com)"},
				"words":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "追加路径(内置之外,如 /myapp/admin)"},
				"project_id": map[string]any{"type": "integer", "description": "归属项目(可选;缺省取任务/会话挂载)"},
			},
			"required": []string{"url"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(input, &in)
			if u := strings.TrimSpace(in.URL); u != "" {
				return actool.AskUser("目录探测(主动请求)目标: " + u)
			}
			return actool.AskUser("目录探测:确认目标 URL")
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				URL       string   `json:"url"`
				Words     []string `json:"words"`
				ProjectID int64    `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			base := strings.TrimSuffix(strings.TrimSpace(in.URL), "/")
			if !isHTTPURL(base) {
				base = "https://" + base
			}
			u, err := url.Parse(base)
			if err != nil || u.Host == "" {
				return actool.Errorf("目标 URL 不合法: " + in.URL), nil
			}
			projectID := s.roeProjectID(ctx, in.ProjectID)
			if err := s.crawlScopeCheck(projectID, u.Hostname()); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			paths := append(append([]string{}, dirScanDict...), in.Words...)
			if len(paths) > dirScanMaxRequests {
				paths = paths[:dirScanMaxRequests]
			}

			hits := dirProbe(ctx, directhttp.Client(&http.Client{Timeout: 8 * time.Second}), base, paths)

			as := s.m.Assets()
			imported := 0
			for _, h := range hits {
				id, err := as.UpsertEndpoint(db.UpsertEndpointReq{URL: base + h.path, Method: "GET"})
				if err != nil {
					continue
				}
				imported++
				if projectID > 0 {
					_, _ = as.StampDiscoveredAsset(id, projectID)
				}
			}

			var b strings.Builder
			fmt.Fprintf(&b, "目录探测 %s:探测 %d 条路径,命中 %d,入 endpoint 资产 %d 条\n", u.Hostname(), len(paths), len(hits), imported)
			for _, h := range hits {
				fmt.Fprintf(&b, "- %-3d %8d %s\n", h.status, h.length, h.path)
			}
			return actool.Text(b.String()), nil
		},
	})
}

// crawlResult 一次同域爬取的产物（纯数据，便于单测）。
type crawlResult struct {
	endpoints []string
	external  map[string]bool
	statuses  map[int]int
	errs      []string
	fetched   int
}

// crawlSameHost 同域 BFS 爬取：从 seed 出发，同域去重、静态资源不入队、
// 深度与页数封顶。只发请求不落库（入库由调用方做）。
func crawlSameHost(ctx context.Context, client *http.Client, seed string, maxPages, maxDepth int) crawlResult {
	out := crawlResult{external: map[string]bool{}, statuses: map[int]int{}}
	u, err := url.Parse(seed)
	if err != nil || u.Host == "" {
		out.errs = append(out.errs, "起点 URL 不合法: "+seed)
		return out
	}
	seedHost := strings.ToLower(u.Hostname())
	type item struct {
		raw   string
		depth int
	}
	root := strings.TrimSuffix(seed, "/") + "/"
	queue := []item{{root, 0}}
	seen := map[string]bool{root: true}
	var mu sync.Mutex
	enqueue := func(raw string, depth int) {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return
		}
		parsed.Fragment = ""
		raw = parsed.String()
		if strings.ToLower(parsed.Hostname()) != seedHost {
			mu.Lock()
			out.external[parsed.Host] = true
			mu.Unlock()
			return
		}
		if fingerprint.PathKind(parsed.Path) == "static" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if seen[raw] {
			return
		}
		seen[raw] = true
		if depth+1 <= maxDepth && len(queue) < crawlMaxPages {
			queue = append(queue, item{raw, depth + 1})
		}
	}
	for len(queue) > 0 && out.fetched < maxPages {
		cur := queue[0]
		queue = queue[1:]
		st, body, finalURL := crawlFetch(ctx, client, cur.raw)
		mu.Lock()
		out.fetched++
		out.statuses[st]++
		out.endpoints = append(out.endpoints, finalURL)
		mu.Unlock()
		if st == 0 {
			mu.Lock()
			if len(out.errs) < 5 {
				out.errs = append(out.errs, cur.raw)
			}
			mu.Unlock()
			continue
		}
		if st >= 200 && st < 400 {
			for _, link := range fingerprint.ExtractLinks(body, finalURL, 200) {
				enqueue(link, cur.depth)
			}
		}
	}
	return out
}

// dirHit 目录探测命中行。
type dirHit struct {
	path   string
	status int
	length int
}

// dirProbe 并发探测目录路径,非 404/410 视为命中。纯请求不落库。
func dirProbe(ctx context.Context, client *http.Client, base string, paths []string) []dirHit {
	var (
		hitsMu sync.Mutex
		hits   []dirHit
		wg     sync.WaitGroup
		sem    = make(chan struct{}, 10)
	)
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+p, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; 4zrec-dirscan/1.0)")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			// 命中语义:非 404/410 即存在(403 也算——权限墙本身就是线索)。
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == 410 {
				return
			}
			length := resp.ContentLength
			if length < 0 {
				length = int64(len(readBodyCapped(resp, 16<<10)))
			}
			hitsMu.Lock()
			hits = append(hits, dirHit{path: p, status: resp.StatusCode, length: int(length)})
			hitsMu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Slice(hits, func(i, j int) bool { return hits[i].path < hits[j].path })
	return hits
}

// crawlTools 爬虫 + 目录探测工具族(本地保底)。
func (s *Server) crawlTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolWebCrawl(), s.toolDirScan()}
}

func sortedKeysStr(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
