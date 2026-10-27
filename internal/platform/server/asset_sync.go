package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// 资产同步：从 4zreark 的 MCP 接口读取站点资产，映射成 4zrec 的 service 资产。
//
// 4zreark 暴露的是无状态 Streamable HTTP MCP（POST /api/mcp），资产侧只需要
// 两个只读工具：list_projects 和 list_assets。这里不引入 MCP SDK，发 JSON-RPC
// 请求即可；连接信息优先取请求显式传入（改 key 后先试再存），否则回落
// settings/env 持久化配置（zreark_config.go）。
const (
	assetSyncDefaultLimit = 1000
	assetSyncMaxLimit     = 5000
	assetSyncPageSize     = 200
	assetSyncMaxErrors    = 20
)

type assetSyncRequest struct {
	BaseURL         string `json:"base_url"`
	APIKey          string `json:"api_key"`
	SourceProjectID int64  `json:"source_project_id"`
	TargetProjectID int64  `json:"target_project_id"`
	Catalog         string `json:"catalog"`
	Limit           int    `json:"limit"`
	DryRun          bool   `json:"dry_run"`
	IncludeRoutes   bool   `json:"include_routes"`
}

type assetSyncProject struct {
	ID          int64  `json:"id"`
	Code        string `json:"code"`
	Name        string `json:"name"`
	AssetCount  int    `json:"asset_count"`
	LostCount   int    `json:"lost_count"`
	RecordCount int    `json:"record_count"`
	Paused      bool   `json:"collection_paused"`
}

type zrearkEndpoint struct {
	Scheme     string `json:"scheme"`
	Port       int    `json:"port"`
	StatusCode int    `json:"status_code"`
}

// zrearkSite 是 4zreark list_assets(kind=site) 返回的站点行。
type zrearkSite struct {
	ID                 int64            `json:"id"`
	ProjectID          int64            `json:"project_id"`
	ProjectCode        string           `json:"project_code"`
	ProjectName        string           `json:"project_name"`
	Host               string           `json:"host"`
	Port               int              `json:"port"`
	Protocol           string           `json:"protocol"`
	Value              string           `json:"value"`
	IP                 string           `json:"ip"`
	HTTPStatus         int              `json:"http_status"`
	Title              string           `json:"title"`
	Tech               []string         `json:"technology_stack"`
	State              string           `json:"state"`
	VerificationStatus string           `json:"verification_status"`
	RiskScore          int              `json:"risk_score"`
	Priority           string           `json:"priority"`
	FirstSeen          string           `json:"first_seen"`
	LastSeen           string           `json:"last_seen"`
	Endpoints          []zrearkEndpoint `json:"endpoints"`
	EndpointCount      int              `json:"endpoint_count"`
}

type zrearkAssetPage struct {
	Items    []zrearkSite `json:"items"`
	Total    int64        `json:"total"`
	Page     int          `json:"page"`
	PageSize int          `json:"page_size"`
	HasMore  bool         `json:"has_more"`
	Kind     string       `json:"kind"`
}

type assetSyncItem struct {
	Host       string `json:"host"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code,omitempty"`
	Title      string `json:"title,omitempty"`
	IP         string `json:"ip,omitempty"`
}

type assetSyncResult struct {
	Total       int64           `json:"total"`
	Fetched     int             `json:"fetched"`
	WouldImport int             `json:"would_import"`
	Imported    int             `json:"imported"`
	Assigned    int             `json:"assigned"`
	Routes      int             `json:"routes"`
	Skipped     int             `json:"skipped"`
	Errors      []string        `json:"errors"`
	Sample      []assetSyncItem `json:"sample"`
	DryRun      bool            `json:"dry_run"`
}

// mcpSyncCaller 是只够 4zreark 集成用的最小 MCP 客户端。
type mcpSyncCaller struct {
	endpoint string
	apiKey   string
	client   *http.Client
	nextID   int
}

// errZrearkAuth 4zreark 鉴权失败(API key 无效/禁用/过期/缺权限)。
// 定时同步靠 errors.Is 判定它触发指数退避熔断。
var errZrearkAuth = errors.New("4zreark 鉴权失败")

// errZrearkNoConfig 持久化配置里没有 API key 且请求也未显式携带。
var errZrearkNoConfig = errors.New("尚未配置 4zreark API Key")

// resolveZrearkCreds 请求显式传入的连接信息优先(便于改 key 后先试再存),
// 否则回落 settings/env 持久化配置。
func (s *Server) resolveZrearkCreds(reqBaseURL, reqAPIKey string) (string, string) {
	var get func(key string) (string, bool, error)
	if s.m.pg != nil {
		get = s.m.pg.GetSetting
	}
	baseURL := strings.TrimSpace(reqBaseURL)
	if baseURL == "" {
		baseURL = resolveZrearkBaseURL(get)
	}
	apiKey := strings.TrimSpace(reqAPIKey)
	if apiKey == "" {
		apiKey = resolveZrearkAPIKey(get)
	}
	return baseURL, apiKey
}

// zrearkCallerFromRequest 按请求体里的连接信息(可缺省,回落持久化配置)构造客户端。
func (s *Server) zrearkCallerFromRequest(reqBaseURL, reqAPIKey string) (*mcpSyncCaller, error) {
	baseURL, apiKey := s.resolveZrearkCreds(reqBaseURL, reqAPIKey)
	if apiKey == "" {
		return nil, errZrearkNoConfig
	}
	return newMCPSyncCaller(baseURL, apiKey)
}

func newMCPSyncCaller(baseURL, apiKey string) (*mcpSyncCaller, error) {
	endpoint, err := normalizeAssetSyncBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, errors.New("4zreark API Key 不能为空")
	}
	return &mcpSyncCaller{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func normalizeAssetSyncBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "http://127.0.0.1:8080"
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("4zreark 地址不合法: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("4zreark 地址只支持 http/https")
	}
	if u.Host == "" {
		return "", errors.New("4zreark 地址缺少主机名")
	}
	path := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(path, "/api/mcp") {
		path += "/api/mcp"
	}
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func (c *mcpSyncCaller) call(ctx context.Context, name string, args map[string]any) (json.RawMessage, error) {
	c.nextID++
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      c.nextID,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      name,
			"arguments": args,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接 4zreark 失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("读取 4zreark 响应失败: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w (%d)，请检查 API Key 与 assets:read 权限", errZrearkAuth, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("4zreark 返回 HTTP %d: %s", resp.StatusCode, truncateSyncText(string(raw), 300))
	}

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("4zreark 返回的不是 JSON-RPC: %w", err)
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("4zreark MCP 错误 %d: %s", envelope.Error.Code, envelope.Error.Message)
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
		IsError           bool            `json:"isError"`
	}
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return nil, fmt.Errorf("解析 4zreark 工具结果失败: %w", err)
	}
	if result.IsError {
		msg := "工具返回错误"
		for _, item := range result.Content {
			if strings.TrimSpace(item.Text) != "" {
				msg = item.Text
				break
			}
		}
		return nil, fmt.Errorf("4zreark %s: %s", name, truncateSyncText(msg, 300))
	}
	if len(result.StructuredContent) > 0 && string(result.StructuredContent) != "null" {
		return result.StructuredContent, nil
	}
	for _, item := range result.Content {
		if item.Type == "text" && json.Valid([]byte(item.Text)) {
			return json.RawMessage(item.Text), nil
		}
	}
	return nil, errors.New("4zreark 工具没有返回结构化结果")
}

func truncateSyncText(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// assetSyncProjectsHandler 读取 4zreark 可访问的项目，供前端选择源项目。
func (s *Server) assetSyncProjects(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	caller, err := s.zrearkCallerFromRequest(req.BaseURL, req.APIKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := caller.call(r.Context(), "list_projects", map[string]any{})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var payload struct {
		Items []assetSyncProject `json:"items"`
		Total int                `json:"total"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeErr(w, http.StatusBadGateway, "解析 4zreark 项目列表失败: "+err.Error())
		return
	}
	if payload.Items == nil {
		payload.Items = []assetSyncProject{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": payload.Items})
}

// zrearkSyncParams 是一次资产同步的参数（HTTP 端点与定时任务共用）。
type zrearkSyncParams struct {
	SourceProjectID int64
	TargetProjectID int64
	Catalog         string
	Limit           int
	DryRun          bool
	IncludeRoutes   bool
}

// errZrearkNoDB 非预览同步要求资产库可用。
var errZrearkNoDB = errors.New("database unavailable")

// errZrearkBadTarget 同步归属的目标项目不存在。
var errZrearkBadTarget = errors.New("目标项目不存在")

// runZrearkAssetSync 按页读取 4zreark 站点并写入 4zrec 资产库。
// DryRun=true 只做读取与映射，不写库，用于同步前预览。
func (s *Server) runZrearkAssetSync(ctx context.Context, caller *mcpSyncCaller, params zrearkSyncParams) (*assetSyncResult, error) {
	as := s.assetStore()
	if !params.DryRun && as == nil {
		return nil, errZrearkNoDB
	}
	if params.TargetProjectID > 0 && !params.DryRun {
		if _, err := s.m.pg.Projects().GetProject(params.TargetProjectID); err != nil {
			return nil, fmt.Errorf("%w: %v", errZrearkBadTarget, err)
		}
	}

	catalog := strings.TrimSpace(params.Catalog)
	if catalog != "all" && catalog != "verified" {
		catalog = "all"
	}
	limit := params.Limit
	if limit <= 0 {
		limit = assetSyncDefaultLimit
	}
	if limit > assetSyncMaxLimit {
		limit = assetSyncMaxLimit
	}

	result := assetSyncResult{
		Errors: []string{},
		Sample: []assetSyncItem{},
		DryRun: params.DryRun,
	}
	page := 1
	for {
		args := map[string]any{
			"kind":       "site",
			"catalog":    catalog,
			"page":       page,
			"page_size":  assetSyncPageSize,
			"site_group": true,
		}
		if params.SourceProjectID > 0 {
			args["project_id"] = params.SourceProjectID
		}
		raw, err := caller.call(ctx, "list_assets", args)
		if err != nil {
			return nil, err
		}
		var pageData zrearkAssetPage
		if err := json.Unmarshal(raw, &pageData); err != nil {
			return nil, fmt.Errorf("解析 4zreark 资产列表失败: %w", err)
		}
		result.Total = pageData.Total
		for _, site := range pageData.Items {
			if result.Fetched >= limit {
				break
			}
			result.Fetched++
			item, upsert, ok := mapZrearkSite(site)
			if !ok {
				result.Skipped++
				appendSyncError(&result.Errors, fmt.Sprintf("%s: 缺少 host", strings.TrimSpace(site.Host)))
				continue
			}
			result.WouldImport++
			if len(result.Sample) < 5 {
				result.Sample = append(result.Sample, item)
			}
			if params.DryRun {
				continue
			}
			id, err := as.UpsertHTTPService(upsert)
			if err != nil {
				result.Skipped++
				appendSyncError(&result.Errors, fmt.Sprintf("%s: %v", item.Host, err))
				continue
			}
			result.Imported++
			as.DB().StampAssetSource(ctx, id, "4zreark")
			if params.TargetProjectID > 0 {
				claimed, err := as.ClaimAssetToProject(id, params.TargetProjectID)
				if err != nil {
					appendSyncError(&result.Errors, fmt.Sprintf("%s: 归属项目失败: %v", item.Host, err))
				} else if claimed {
					result.Assigned++
				}
			}
			// 爬虫路由（site_routes）→ endpoint 资产：有爬虫沉淀的站点逐站拉取。
			// 不以 endpoint_count 为门槛——list_assets 聚合行里该字段可能不反映
			// 路由表实况（实测 179 项目 986 条路由被全滤），直接按站点拉，空页自会跳过。
			if params.IncludeRoutes && site.ID > 0 {
				imported, err := s.syncZrearkSiteRoutes(ctx, caller, as, site, item)
				if err != nil {
					appendSyncError(&result.Errors, fmt.Sprintf("%s: 路由同步失败: %v", item.Host, truncateSyncText(err.Error(), 120)))
				} else {
					result.Routes += imported
				}
			}
		}
		if result.Fetched >= limit || len(pageData.Items) == 0 ||
			(!pageData.HasMore && pageData.Total <= int64(result.Fetched)) {
			break
		}
		page++
		if page > 200 {
			break
		}
	}
	return &result, nil
}

// assetSyncHandler HTTP 入口：解析请求 → 构造客户端 → 复用同步核心。
func (s *Server) assetSync(w http.ResponseWriter, r *http.Request) {
	var req assetSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	caller, err := s.zrearkCallerFromRequest(req.BaseURL, req.APIKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := s.runZrearkAssetSync(r.Context(), caller, zrearkSyncParams{
		SourceProjectID: req.SourceProjectID,
		TargetProjectID: req.TargetProjectID,
		Catalog:         req.Catalog,
		Limit:           req.Limit,
		DryRun:          req.DryRun,
		IncludeRoutes:   req.IncludeRoutes,
	})
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

func appendSyncError(errs *[]string, msg string) {
	if len(*errs) >= assetSyncMaxErrors {
		return
	}
	*errs = append(*errs, msg)
}

func mapZrearkSite(site zrearkSite) (assetSyncItem, db.UpsertHTTPServiceReq, bool) {
	host := strings.TrimSpace(site.Host)
	value := strings.TrimSpace(site.Value)
	if host == "" && isHTTPURL(value) {
		if u, err := url.Parse(value); err == nil {
			host = u.Hostname()
		}
	}
	if host == "" {
		return assetSyncItem{}, db.UpsertHTTPServiceReq{}, false
	}
	siteURL := buildZrearkSiteURL(site, host)
	if siteURL == "" {
		return assetSyncItem{}, db.UpsertHTTPServiceReq{}, false
	}
	status := 0
	if site.HTTPStatus > 0 {
		status = site.HTTPStatus
	}
	var statusPtr *int
	if status > 0 {
		statusPtr = &status
	}
	item := assetSyncItem{
		Host:       host,
		URL:        siteURL,
		StatusCode: status,
		Title:      strings.TrimSpace(site.Title),
		IP:         sanitizeZrearkIP(site.IP),
	}
	return item, db.UpsertHTTPServiceReq{
		URL:          siteURL,
		Technologies: site.Tech,
		StatusCode:   statusPtr,
		PageTitle:    item.Title,
		IP:           item.IP,
	}, true
}

// sanitizeZrearkIP 4zreark 的站点 ip 字段可能带 CIDR 后缀（如 "1.2.3.4/32"），
// 4zrec 的资产校验只收裸地址：剥离 /32、/128；其它前缀的网段不是主机地址，丢弃。
func sanitizeZrearkIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" && strings.Contains(raw, "://") {
		raw = u.Hostname() // 容错：误填了 URL 的情况取主机名
	}
	if strings.Contains(raw, "/") {
		addr, bits, ok := strings.Cut(raw, "/")
		if !ok {
			return ""
		}
		if (strings.Contains(addr, ":") && bits == "128") || (!strings.Contains(addr, ":") && bits == "32") {
			raw = addr
		} else {
			return ""
		}
	}
	if u, err := netip.ParseAddr(raw); err != nil || u.Zone() != "" {
		return ""
	}
	return raw
}

func buildZrearkSiteURL(site zrearkSite, host string) string {
	if isHTTPURL(site.Value) {
		return strings.TrimSpace(site.Value)
	}
	scheme := strings.ToLower(strings.TrimSpace(site.Protocol))
	if scheme != "http" && scheme != "https" {
		scheme = "https"
		if site.Port == 80 {
			scheme = "http"
		}
	}
	host = hostForURL(host)
	if site.Port > 0 && !isDefaultHTTPPort(scheme, site.Port) {
		return fmt.Sprintf("%s://%s:%d", scheme, host, site.Port)
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func isHTTPURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func isDefaultHTTPPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

func hostForURL(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}
