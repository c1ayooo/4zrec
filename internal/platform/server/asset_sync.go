package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// 资产同步：从 4zreark 的 MCP 接口读取站点资产，映射成 4zrec 的 service 资产。
//
// 4zreark 暴露的是无状态 Streamable HTTP MCP（POST /api/mcp），资产侧只需要
// 两个只读工具：list_projects 和 list_assets。这里不引入 MCP SDK，发 JSON-RPC
// 请求即可；API key 只存在于本次请求内，不落库、不写日志。
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
	IP                  string           `json:"ip"`
	HTTPStatus          int              `json:"http_status"`
	Title               string           `json:"title"`
	Tech                []string         `json:"technology_stack"`
	State               string           `json:"state"`
	VerificationStatus  string           `json:"verification_status"`
	RiskScore           int              `json:"risk_score"`
	Priority            string           `json:"priority"`
	FirstSeen           string           `json:"first_seen"`
	LastSeen            string           `json:"last_seen"`
	Endpoints           []zrearkEndpoint `json:"endpoints"`
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
	Skipped     int             `json:"skipped"`
	Errors      []string        `json:"errors"`
	Sample      []assetSyncItem `json:"sample"`
	DryRun      bool            `json:"dry_run"`
}

// mcpSyncCaller 是只够资产同步用的最小 MCP 客户端。
type mcpSyncCaller struct {
	endpoint string
	apiKey   string
	client   *http.Client
	nextID   int
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
		return nil, fmt.Errorf("4zreark 鉴权失败 (%d)，请检查 API Key 与 assets:read 权限", resp.StatusCode)
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
	caller, err := newMCPSyncCaller(req.BaseURL, req.APIKey)
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

// assetSyncHandler 按页读取 4zreark 站点并写入 4zrec 资产库。
// dry_run=true 只做读取与映射，不写库，用于同步前预览。
func (s *Server) assetSync(w http.ResponseWriter, r *http.Request) {
	var req assetSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	caller, err := newMCPSyncCaller(req.BaseURL, req.APIKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	as := s.assetStore()
	if !req.DryRun && as == nil {
		writeErr(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	if req.TargetProjectID > 0 && !req.DryRun {
		if _, err := s.m.pg.Projects().GetProject(req.TargetProjectID); err != nil {
			writeErr(w, http.StatusBadRequest, "目标项目不存在: "+err.Error())
			return
		}
	}

	catalog := strings.TrimSpace(req.Catalog)
	if catalog != "all" && catalog != "verified" {
		catalog = "all"
	}
	limit := req.Limit
	if limit <= 0 {
		limit = assetSyncDefaultLimit
	}
	if limit > assetSyncMaxLimit {
		limit = assetSyncMaxLimit
	}

	result := assetSyncResult{
		Errors: []string{},
		Sample: []assetSyncItem{},
		DryRun: req.DryRun,
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
		if req.SourceProjectID > 0 {
			args["project_id"] = req.SourceProjectID
		}
		raw, err := caller.call(r.Context(), "list_assets", args)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}
		var pageData zrearkAssetPage
		if err := json.Unmarshal(raw, &pageData); err != nil {
			writeErr(w, http.StatusBadGateway, "解析 4zreark 资产列表失败: "+err.Error())
			return
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
			if req.DryRun {
				continue
			}
			id, err := as.UpsertHTTPService(upsert)
			if err != nil {
				result.Skipped++
				appendSyncError(&result.Errors, fmt.Sprintf("%s: %v", item.Host, err))
				continue
			}
			result.Imported++
			as.DB().StampAssetSource(r.Context(), id, "4zreark")
			if req.TargetProjectID > 0 {
				claimed, err := as.ClaimAssetToProject(id, req.TargetProjectID)
				if err != nil {
					appendSyncError(&result.Errors, fmt.Sprintf("%s: 归属项目失败: %v", item.Host, err))
				} else if claimed {
					result.Assigned++
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
		IP:         strings.TrimSpace(site.IP),
	}
	return item, db.UpsertHTTPServiceReq{
		URL:          siteURL,
		Technologies: site.Tech,
		StatusCode:   statusPtr,
		PageTitle:    item.Title,
		IP:           item.IP,
	}, true
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
