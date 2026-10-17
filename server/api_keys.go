// api_keys.go 持久 API Key 管理接口(仅全局凭据可管理)。
//
//	GET    /api/api-keys
//	POST   /api/api-keys {name, scope:"global"|"project", project_id?, expires_in_days?}
//	DELETE /api/api-keys/{id}
//
// 明文 token 只在创建响应里返回一次,库里只存 SHA-256。
package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/db"
)

func (s *Server) apiKeysList(w http.ResponseWriter, r *http.Request) {
	if !APIScopeFrom(r.Context()).Global {
		writeErr(w, 403, "项目级 API Key 无权管理 API Key")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	keys, err := pg.ListAPIKeys()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if keys == nil {
		keys = []db.APIKey{}
	}
	writeJSON(w, 200, map[string]any{"keys": keys})
}

func (s *Server) apiKeysCreate(w http.ResponseWriter, r *http.Request) {
	if !APIScopeFrom(r.Context()).Global {
		writeErr(w, 403, "项目级 API Key 无权创建 API Key")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Name          string `json:"name"`
		Scope         string `json:"scope"`
		ProjectID     int64  `json:"project_id"`
		ExpiresInDays int    `json:"expires_in_days"` // 0/省略 = 永不过期
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, 400, "name 不能为空")
		return
	}
	if req.Scope != "global" && req.Scope != "project" {
		writeErr(w, 400, "scope 必须是 global 或 project")
		return
	}
	if req.Scope == "project" {
		if req.ProjectID <= 0 {
			writeErr(w, 400, "项目级 key 必须指定 project_id")
			return
		}
		if p, err := pg.Projects().GetProject(req.ProjectID); err != nil || p.ID == 0 {
			writeErr(w, 404, "项目不存在")
			return
		}
	}
	var expires *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresInDays)
		expires = &t
	}
	raw, key, err := pg.CreateAPIKey(req.Name, req.Scope, req.ProjectID, expires)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// token 只出现这一次;UI/调用方必须立即保存。
	writeJSON(w, 200, map[string]any{"key": key, "token": raw})
}

func (s *Server) apiKeysDelete(w http.ResponseWriter, r *http.Request) {
	if !APIScopeFrom(r.Context()).Global {
		writeErr(w, 403, "项目级 API Key 无权管理 API Key")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad key id")
		return
	}
	if err := pg.DeleteAPIKey(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
