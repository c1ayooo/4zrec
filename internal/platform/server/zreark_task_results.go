// zreark_task_results.go 4zreark 指纹与爬虫结果的同步通道：
//   - syncZrearkSiteRoutes：整站同步时按站点调 list_asset_routes，把 site_routes
//     （爬虫沉淀、已清洗去重）落成 4zrec 的 endpoint 资产；
//   - zrearkTaskResults：按任务调 get_task_results，result_type=service（指纹：
//     data.technologies + data.fingerprints）并入站点技术栈，result_type=crawler
//     （katana 原始路由）落 endpoint。
//
// 指纹没有独立 result_type——HTTP 指纹在 service 结果里，非 HTTP（SSH banner 等）
// 是 service 结果的 type=other 变体。
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capability/recon/spacemap"
	"github.com/c1ayooo/4zrec/internal/domain/db"
)

const (
	zrearkRoutesPerSite = 200 // 单站点路由拉取上限（list_asset_routes 上限 1000）
	zrearkTaskPageSize  = 100 // get_task_results page_size 上限
	zrearkTaskMaxItems  = 10000
)

// zrearkRoute 是 list_asset_routes 返回的路由行。
type zrearkRoute struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Source     string `json:"source"`
}

// syncZrearkSiteRoutes 拉取一个 4zreark 站点的路由并落成 endpoint 资产，返回导入数。
func (s *Server) syncZrearkSiteRoutes(ctx context.Context, caller *mcpSyncCaller, as *db.AssetStore, site zrearkSite, base assetSyncItem) (int, error) {
	raw, err := caller.call(ctx, "list_asset_routes", map[string]any{
		"site_id": site.ID,
		"limit":   zrearkRoutesPerSite,
	})
	if err != nil {
		return 0, err
	}
	var payload struct {
		Items []zrearkRoute `json:"items"`
		Total int           `json:"total"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, fmt.Errorf("解析路由列表失败: %w", err)
	}
	imported := 0
	var firstErr error
	errCount := 0
	for _, rt := range payload.Items {
		endpointURL := joinZrearkRouteURL(base.URL, rt.Path)
		if endpointURL == "" {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(rt.Method))
		if method == "" {
			method = "GET"
		}
		if _, err := as.UpsertEndpoint(db.UpsertEndpointReq{
			URL:    endpointURL,
			Method: method,
			IP:     sanitizeZrearkIP(site.IP),
		}); err != nil {
			errCount++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		imported++
	}
	if imported == 0 && errCount > 0 {
		return 0, fmt.Errorf("%d 条路由落库失败, 首错: %w", errCount, firstErr)
	}
	return imported, nil
}

// joinZrearkRouteURL 站点基址 + 路由路径拼成完整 endpoint URL。
func joinZrearkRouteURL(base, path string) string {
	base = strings.TrimSpace(base)
	path = strings.TrimSpace(path)
	if base == "" || path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimSuffix(base, "/") + path
}

// ---------- 任务级结果同步：指纹(service) + 爬虫(crawler) ----------

type zrearkTaskResultsRequest struct {
	BaseURL         string   `json:"base_url"`
	APIKey          string   `json:"api_key"`
	TaskID          string   `json:"task_id"`
	Include         []string `json:"include"` // service(指纹)/crawler(路由)/subdomain(子域)/port(端口)，默认 service+crawler
	TargetProjectID int64    `json:"target_project_id"`
	Limit           int      `json:"limit"`
	DryRun          bool     `json:"dry_run"`
}

type zrearkTaskResultsResult struct {
	TaskID     string   `json:"task_id"`
	Fetched    int      `json:"fetched"`
	Services   int      `json:"services"`
	Endpoints  int      `json:"endpoints"`
	Subdomains int      `json:"subdomains"`
	Ports      int      `json:"ports"`
	Assigned   int      `json:"assigned"`
	Skipped    int      `json:"skipped"`
	Errors     []string `json:"errors"`
	DryRun     bool     `json:"dry_run"`
}

// zrearkTaskSyncParams 一次任务结果同步的参数（HTTP 端点与本地工具共用）。
type zrearkTaskSyncParams struct {
	TaskID          string
	Include         map[string]bool
	TargetProjectID int64
	Limit           int
	DryRun          bool
}

// zrearkSyncCore 按任务拉取 4zreark 结果并导入 4zrec 资产库（HTTP 端点与
// zreark_sync_results 工具共用）。crawler 与 service/subdomain/port 各自独立分页
// （total 不同，页码不能共用）。
func (s *Server) zrearkSyncCore(ctx context.Context, caller *mcpSyncCaller, params zrearkTaskSyncParams, result *zrearkTaskResultsResult) error {
	as := s.assetStore()
	if !params.DryRun && as == nil {
		return errZrearkNoDB
	}
	if params.TargetProjectID > 0 && !params.DryRun {
		if _, err := s.m.pg.Projects().GetProject(params.TargetProjectID); err != nil {
			return fmt.Errorf("%w: %v", errZrearkBadTarget, err)
		}
	}
	limit := params.Limit
	if limit <= 0 {
		limit = zrearkTaskMaxItems
	}
	if limit > zrearkTaskMaxItems {
		limit = zrearkTaskMaxItems
	}
	// 各 result_type 独立分页拉取。
	for _, typ := range []string{"crawler", "service", "subdomain", "port"} {
		if !params.Include[typ] {
			continue
		}
		for page := 1; result.Fetched < limit; page++ {
			pageSize := zrearkTaskPageSize
			if remaining := limit - result.Fetched; remaining < pageSize {
				pageSize = remaining
			}
			raw, err := caller.call(ctx, "get_task_results", map[string]any{
				"task_id":     params.TaskID,
				"result_type": typ,
				"page":        page,
				"page_size":   pageSize,
			})
			if err != nil {
				return err
			}
			var payload struct {
				Items []zrearkTaskResultItem `json:"items"`
				Total int64                  `json:"total"`
			}
			if err := json.Unmarshal(raw, &payload); err != nil {
				return fmt.Errorf("解析任务结果失败: %w", err)
			}
			if len(payload.Items) == 0 {
				break
			}
			for _, item := range payload.Items {
				if result.Fetched >= limit {
					break
				}
				result.Fetched++
				s.importZrearkTaskItem(ctx, as, item, params, result)
			}
			if int64(page*pageSize) >= payload.Total || len(payload.Items) < pageSize {
				break
			}
		}
	}
	return nil
}

// zrearkTaskResults 把一个 4zreark 任务的指纹/爬虫/子域/端口结果导入 4zrec。
func (s *Server) zrearkTaskResults(w http.ResponseWriter, r *http.Request) {
	var req zrearkTaskResultsRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	req.TaskID = strings.TrimSpace(req.TaskID)
	if req.TaskID == "" {
		writeErr(w, http.StatusBadRequest, "task_id 必填（可在「下发采集任务」弹窗查看远端任务 ID）")
		return
	}
	include := map[string]bool{}
	for _, item := range req.Include {
		include[strings.TrimSpace(item)] = true
	}
	if len(include) == 0 {
		include["service"] = true
		include["crawler"] = true
	}
	for k := range include {
		if !zrearkSyncTypes[k] {
			writeErr(w, http.StatusBadRequest, "include 只支持 service(指纹)/crawler(爬虫路由)/subdomain(子域)/port(端口)")
			return
		}
	}
	caller, err := s.zrearkCallerFromRequest(req.BaseURL, req.APIKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	result := zrearkTaskResultsResult{TaskID: req.TaskID, Errors: []string{}, DryRun: req.DryRun}
	err = s.zrearkSyncCore(r.Context(), caller, zrearkTaskSyncParams{
		TaskID:          req.TaskID,
		Include:         include,
		TargetProjectID: req.TargetProjectID,
		Limit:           req.Limit,
		DryRun:          req.DryRun,
	}, &result)
	if err != nil {
		switch {
		case errors.Is(err, errZrearkNoDB):
			writeErr(w, http.StatusServiceUnavailable, err.Error())
		case errors.Is(err, errZrearkBadTarget):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			writeErr(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// zrearkSyncTypes 支持同步入库的 result_type 集合。
var zrearkSyncTypes = map[string]bool{
	"service": true, "crawler": true, "subdomain": true, "port": true,
}

// zrearkTaskResultItem 是 get_task_results 的一行（data 为自由 map）。
type zrearkTaskResultItem struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

func (s *Server) importZrearkTaskItem(ctx context.Context, as *db.AssetStore, item zrearkTaskResultItem, params zrearkTaskSyncParams, result *zrearkTaskResultsResult) {
	if params.DryRun {
		// 预览按形态计数,不做入库。
		switch item.Type {
		case "subdomain":
			result.Subdomains++
		case "port":
			result.Ports++
		case "crawler":
			result.Endpoints++
		default:
			result.Services++
		}
		return
	}
	switch item.Type {
	case "service":
		s.importZrearkServiceData(ctx, as, item.Data, params, result)
	case "crawler":
		s.importZrearkCrawlerData(as, item.Data, result)
	case "subdomain":
		s.importZrearkSubdomainData(ctx, as, item.Data, params, result)
	case "port":
		s.importZrearkPortData(ctx, as, item.Data, params, result)
	default:
		result.Skipped++
	}
}

// importZrearkServiceData 指纹结果（HTTP 指纹或 type=other 的服务 banner）。
func (s *Server) importZrearkServiceData(ctx context.Context, as *db.AssetStore, data map[string]any, params zrearkTaskSyncParams, result *zrearkTaskResultsResult) {
	host := mapString(data, "host")
	ip := mapString(data, "ip")
	// 非 HTTP 服务（SSH/FTP banner 等）落 other service 资产。
	if mapString(data, "type") == "other" {
		domain := host
		if domain == "" {
			domain = ip
		}
		if domain == "" {
			result.Skipped++
			return
		}
		if _, err := as.UpsertOtherService(db.UpsertOtherServiceReq{
			Domain:      domain,
			IP:          ip,
			Port:        mapInt(data, "port"),
			ServiceName: mapString(data, "service"),
		}); err != nil {
			result.Skipped++
			appendSyncError(&result.Errors, fmt.Sprintf("%s: %v", domain, err))
			return
		}
		result.Services++
		return
	}

	serviceURL := mapString(data, "url")
	if serviceURL == "" && host != "" {
		serviceURL = buildZrearkHostURL(host, mapInt(data, "port"))
	}
	if !isHTTPURL(serviceURL) {
		result.Skipped++
		return
	}
	technologies := mapStrings(data, "technologies")
	technologies = append(technologies, mapStrings(data, "fingerprints")...)
	status := mapInt(data, "status_code")
	var statusPtr *int
	if status > 0 {
		statusPtr = &status
	}
	id, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL:          serviceURL,
		Technologies: technologies,
		StatusCode:   statusPtr,
		PageTitle:    mapString(data, "title"),
		IP:           ip,
	})
	if err != nil {
		result.Skipped++
		appendSyncError(&result.Errors, fmt.Sprintf("%s: %v", serviceURL, truncateSyncText(err.Error(), 120)))
		return
	}
	result.Services++
	as.DB().StampAssetSource(ctx, id, "4zreark")
	if params.TargetProjectID > 0 {
		if claimed, err := as.ClaimAssetToProject(id, params.TargetProjectID); err == nil && claimed {
			result.Assigned++
		}
	}
}

// importZrearkCrawlerData 爬虫路由结果 → endpoint 资产。
func (s *Server) importZrearkCrawlerData(as *db.AssetStore, data map[string]any, result *zrearkTaskResultsResult) {
	rawURL := mapString(data, "url")
	if !isHTTPURL(rawURL) {
		result.Skipped++
		return
	}
	method := strings.ToUpper(mapString(data, "method"))
	if method == "" {
		method = "GET"
	}
	if _, err := as.UpsertEndpoint(db.UpsertEndpointReq{URL: rawURL, Method: method}); err != nil {
		result.Skipped++
		appendSyncError(&result.Errors, fmt.Sprintf("%s: %v", rawURL, truncateSyncText(err.Error(), 120)))
		return
	}
	result.Endpoints++
}

// importZrearkSubdomainData 子域结果 → 走 spacemapImport 范围状态机
// （范围内 approved、范围外 pending，不静默丢），附带首个解析 IP。
func (s *Server) importZrearkSubdomainData(ctx context.Context, as *db.AssetStore, data map[string]any, params zrearkTaskSyncParams, result *zrearkTaskResultsResult) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(mapString(data, "subdomain")), "."))
	if name == "" || !strings.Contains(name, ".") {
		result.Skipped++
		return
	}
	res := &spacemap.Result{Domain: name, Host: name}
	if ips := mapStrings(data, "ips"); len(ips) > 0 {
		res.IP = strings.TrimSpace(ips[0])
	}
	s.spacemapImport(ctx, params.TargetProjectID, 0, []*spacemap.Result{res}, "")
	result.Subdomains++
}

// importZrearkPortData 端口结果 → IP 资产带开放端口；host 为域名时顺带补子域；
// http/https 端口补建 service 资产（portscan_tools 同款模式）。
func (s *Server) importZrearkPortData(ctx context.Context, as *db.AssetStore, data map[string]any, params zrearkTaskSyncParams, result *zrearkTaskResultsResult) {
	port := mapInt(data, "port")
	if port <= 0 || port > 65535 {
		result.Skipped++
		return
	}
	host := mapString(data, "host")
	ip := mapString(data, "ip")
	if ip == "" {
		ip = host
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		result.Skipped++
		return
	}
	svc := strings.ToLower(mapString(data, "service"))
	if id, err := as.UpsertIP(db.UpsertIPReq{
		IP:        addr.String(),
		OpenPorts: []db.PortService{{Port: port, Service: svc}},
	}); err == nil && params.TargetProjectID > 0 {
		_, _ = as.StampDiscoveredAsset(id, params.TargetProjectID)
	}
	// host 是域名（非 IP 字面量）时补子域资产。
	if host != "" && !isIPString(host) && strings.Contains(host, ".") {
		s.spacemapImport(ctx, params.TargetProjectID, 0,
			[]*spacemap.Result{{Domain: strings.ToLower(host), Host: strings.ToLower(host), IP: addr.String()}}, "")
	}
	if svc == "http" || svc == "https" {
		scheme := svc
		h := host
		if h == "" || !isIPString(h) {
			h = addr.String()
		}
		if sid, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{
			URL: fmt.Sprintf("%s://%s:%d", scheme, hostForURL(h), port),
		}); err == nil && params.TargetProjectID > 0 {
			_, _ = as.StampDiscoveredAsset(sid, params.TargetProjectID)
		}
	}
	result.Ports++
}

// buildZrearkHostURL host(:port) → https 形态 URL（80 端口回落 http）。
func buildZrearkHostURL(host string, port int) string {
	if host == "" {
		return ""
	}
	scheme := "https"
	if port == 80 {
		scheme = "http"
	}
	host = hostForURL(host)
	if port > 0 && !isDefaultHTTPPort(scheme, port) {
		return fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func mapString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%v", v)
	default:
		return ""
	}
}

func mapInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case string:
		n := 0
		_, _ = fmt.Sscanf(strings.TrimSpace(v), "%d", &n)
		return n
	default:
		return 0
	}
}

// isIPString 字符串是否为合法 IP 字面量。
func isIPString(s string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(s))
	return err == nil
}

func mapStrings(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}
