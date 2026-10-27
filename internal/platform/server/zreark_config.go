// zreark_config.go 4zreark 平台连接配置:settings 表持久化(base_url + api_key),
// 环境变量优先(容器部署友好),掩码回显。api_key 留空=保持不变,显式传 "clear"=清除。
package server

import (
	"net/http"
	"os"
	"strings"
)

const (
	// ZrearkBaseURLSetting / ZrearkAPIKeySetting 是 4zreark 连接信息的 settings 键。
	ZrearkBaseURLSetting = "zreark.base_url"
	ZrearkAPIKeySetting  = "zreark.api_key"
	// ZrearkDefaultProjectSetting 缺省源项目(4zreark 侧项目 ID),agent 下发采集时缺省使用。
	ZrearkDefaultProjectSetting = "zreark.default_project_id"

	zrearkDefaultBaseURL = "http://127.0.0.1:8080"
)

// resolveZrearkBaseURL 环境变量优先,settings 兜底,均未配置用内置默认。
func resolveZrearkBaseURL(get func(key string) (string, bool, error)) string {
	if v := strings.TrimSpace(os.Getenv("ZREARK_BASE_URL")); v != "" {
		return v
	}
	if get != nil {
		if v, ok, err := get(ZrearkBaseURLSetting); err == nil && ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return zrearkDefaultBaseURL
}

// resolveZrearkAPIKey 环境变量优先,settings 兜底,均未配置返回空。
func resolveZrearkAPIKey(get func(key string) (string, bool, error)) string {
	if v := strings.TrimSpace(os.Getenv("ZREARK_API_KEY")); v != "" {
		return v
	}
	if get != nil {
		if v, ok, err := get(ZrearkAPIKeySetting); err == nil && ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// zrearkAPIKeyFromEnv 回显时标注"来自环境变量,页面修改无效"。
func zrearkAPIKeyFromEnv() bool {
	return strings.TrimSpace(os.Getenv("ZREARK_API_KEY")) != ""
}

// zrearkConfigGet 读取 4zreark 连接配置(key 只回掩码)。无库时仍可回显 env 来源。
func (s *Server) zrearkConfigGet(w http.ResponseWriter, r *http.Request) {
	var get func(key string) (string, bool, error)
	if s.m.pg != nil {
		get = s.m.pg.GetSetting
	}
	baseURL := resolveZrearkBaseURL(get)
	apiKey := resolveZrearkAPIKey(get)
	defaultProject := ""
	if get != nil {
		if v, ok, _ := get(ZrearkDefaultProjectSetting); ok {
			defaultProject = strings.TrimSpace(v)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"base_url":        baseURL,
		"api_key_masked":  maskZrearkKey(apiKey),
		"configured":      apiKey != "",
		"from_env":        zrearkAPIKeyFromEnv(),
		"default_project": defaultProject,
	})
}

// zrearkConfigSet 保存连接配置。api_key 留空=保持不变;显式传 "clear"=清除;
// 环境变量来源时写库不生效,直接拒绝以免误导。
func (s *Server) zrearkConfigSet(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in struct {
		BaseURL        string `json:"base_url"`
		APIKey         string `json:"api_key"`
		DefaultProject string `json:"default_project_id"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if zrearkAPIKeyFromEnv() && strings.TrimSpace(in.APIKey) != "" {
		writeErr(w, http.StatusBadRequest, "API key 来自环境变量 ZREARK_API_KEY,页面修改无效")
		return
	}
	if strings.TrimSpace(in.APIKey) != "" {
		value := strings.TrimSpace(in.APIKey)
		if value == "clear" {
			value = ""
		}
		if err := pg.SetSetting(ZrearkAPIKeySetting, value); err != nil {
			writeErr(w, http.StatusInternalServerError, "db: "+err.Error())
			return
		}
	}
	if err := pg.SetSetting(ZrearkBaseURLSetting, strings.TrimSpace(in.BaseURL)); err != nil {
		writeErr(w, http.StatusInternalServerError, "db: "+err.Error())
		return
	}
	if err := pg.SetSetting(ZrearkDefaultProjectSetting, strings.TrimSpace(in.DefaultProject)); err != nil {
		writeErr(w, http.StatusInternalServerError, "db: "+err.Error())
		return
	}
	s.zrearkConfigGet(w, r)
}

// maskZrearkKey 掩码回显:保留前 4 后 2,中间打点;过短的完全打码。
func maskZrearkKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", 6) + key[len(key)-2:]
}
