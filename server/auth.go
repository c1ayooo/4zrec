package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/c1ayooo/4zrec/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	authUserKey    = "auth.username"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// defaultLoginUsername 是用户名存库(auth.username)之前的默认登录名。存量部署
	// 未显式改过名时继续用它;改名走 change-password 接口(见 authChangeUsername),
	// 登录比对实时读库,JWT sub 不参与校验,改名不踢现有登录态。
	defaultLoginUsername = "4zrec"
	maxUsernameRunes     = 64

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// loginUsernameOf 返回当前生效的登录名:库里有 auth.username 用库里的,否则回退默认。
// 读失败也回退默认(登录页因此拿不到自定义名只是体验问题,不能把登录整个堵死)。
func loginUsernameOf(pg *db.DB) string {
	if pg == nil {
		return defaultLoginUsername
	}
	v, ok, err := pg.GetSetting(authUserKey)
	if err != nil || !ok || strings.TrimSpace(v) == "" {
		return defaultLoginUsername
	}
	return strings.TrimSpace(v)
}

// validateUsername 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validateUsername(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "用户名不能为空"
	}
	if utf8.RuneCountInString(name) > maxUsernameRunes {
		return fmt.Sprintf("用户名最多 %d 个字符", maxUsernameRunes)
	}
	return ""
}

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// signJWT issues a 7-day HS256 token for the login user. sub 取默认名即可:
// verifyJWT 不校验 sub,用户名存库后改名不影响已签发 token。
func signJWT(key []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   defaultLoginUsername,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(key)
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token.
func verifyJWT(tokenStr string, key []byte) bool {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	return err == nil && t.Valid
}

// extractToken reads the JWT from Authorization: Bearer header, the login
// cookie, or ?token= query param (for SSE/download direct links).
//
// 前端登录写的是 artex_token(Next middleware 也读它),历史/SSE 侧用
// 4zrec_token;两种都认,否则浏览器直接打开导出链接会 401(无 Authorization 头)。
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if h := strings.TrimSpace(r.Header.Get("X-API-Key")); h != "" {
		return h
	}
	for _, name := range []string{"artex_token", "4zrec_token"} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return r.URL.Query().Get("token")
}

// APIScope is the authorization scope of the current request: JWT = global;
// a project-scoped API key = one project only.
type APIScope struct {
	Global    bool
	ProjectID int64
	KeyID     int64
}

type apiScopeCtxKey struct{}

func withAPIScope(ctx context.Context, sc APIScope) context.Context {
	return context.WithValue(ctx, apiScopeCtxKey{}, sc)
}

// APIScopeFrom returns the request scope; default global (internal handlers and
// paths outside requireAuth keep their previous behavior).
func APIScopeFrom(ctx context.Context) APIScope {
	if v, ok := ctx.Value(apiScopeCtxKey{}).(APIScope); ok {
		return v
	}
	return APIScope{Global: true}
}

// scopedProjectID returns the forced project id for a project-scoped key
// (0 = global / no restriction).
func scopedProjectID(ctx context.Context) int64 {
	sc := APIScopeFrom(ctx)
	if sc.Global {
		return 0
	}
	return sc.ProjectID
}

// projectKeyPathAllowed is the route allowlist for project-scoped API keys.
// Everything outside is global-only (settings/agents/tools/LLM/MCP/system).
func projectKeyPathAllowed(method, path string) bool {
	if path == "/api/projects" {
		return method == http.MethodGet
	}
	if strings.HasPrefix(path, "/api/projects/") {
		// 项目范围维护(读候选/追加/导入/删除)允许;项目本身的建/改/删仍全局。
		return strings.Contains(path, "/scope")
	}
	if path == "/api/tasks" {
		return true // GET 列表 / POST 创建(创建时强制本项目)
	}
	if strings.HasPrefix(path, "/api/tasks/") {
		rest := strings.TrimPrefix(path, "/api/tasks/")
		seg := strings.SplitN(rest, "/", 2)[0]
		if seg == "control" {
			return rest == "control/batch"
		}
		// 数值 id 的子路由由 requireAuth 统一校验任务归属;其余批量/归档类
		// 路由(archive/category/...)对项目 key 一律拒绝。
		_, err := strconv.ParseInt(seg, 10, 64)
		return err == nil
	}
	if path == "/api/assets" {
		return true // 列表/批量写入/删除都在 handler 内做项目边界
	}
	switch path {
	case "/api/assets/pending", "/api/assets/authz", "/api/assets/probe", "/api/assets/bind":
		return true
	}
	if path == "/api/exploration/findings" || path == "/api/exploration/findings/export" ||
		path == "/api/exploration/findings/groups" || path == "/api/exploration/findings/asset-tree" {
		return method == http.MethodGet
	}
	if strings.HasPrefix(path, "/api/exploration/findings/") {
		rest := strings.TrimPrefix(path, "/api/exploration/findings/")
		seg := strings.SplitN(rest, "/", 2)[0]
		if _, err := strconv.ParseInt(seg, 10, 64); err == nil {
			// 只允许 /{id} 与 /{id}/export;lineage 等子路由不开放。
			return method == http.MethodGet && (rest == seg || rest == seg+"/export")
		}
		return false
	}
	if strings.HasPrefix(path, "/api/intercept/pending") {
		return true
	}
	if path == "/api/intercept/history" {
		return method == http.MethodGet
	}
	if strings.HasPrefix(path, "/api/intercept/project/") {
		return method == http.MethodGet
	}
	return false
}

// checkProjectScope rejects a project-scoped key targeting another project.
func (s *Server) checkProjectScope(w http.ResponseWriter, r *http.Request, projectID int64) bool {
	sc := APIScopeFrom(r.Context())
	if sc.Global {
		return true
	}
	if projectID > 0 && sc.ProjectID == projectID {
		return true
	}
	writeErr(w, 403, "项目级 API Key 只能访问绑定项目")
	return false
}

// checkTaskScope rejects a project-scoped key targeting a task outside its
// project. Unknown/foreign tasks return 404 so existence isn't leaked.
func (s *Server) checkTaskScope(w http.ResponseWriter, r *http.Request, taskID string) bool {
	sc := APIScopeFrom(r.Context())
	if sc.Global {
		return true
	}
	id, err := strconv.ParseInt(strings.TrimSpace(taskID), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad task id")
		return false
	}
	pid, err := s.m.pg.TaskProjectID(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return false
	}
	if pid == sc.ProjectID {
		return true
	}
	writeErr(w, 404, "task not found")
	return false
}

// forceProjectQuery injects project_id into a filter-style query (findings
// groups/tree/export), so a project-scoped key can't widen the result set.
func forceProjectQuery(r *http.Request, projectID int64) {
	if projectID <= 0 {
		return
	}
	q := r.URL.Query()
	q.Set("project_id", strconv.FormatInt(projectID, 10))
	r.URL.RawQuery = q.Encode()
}

// checkFindingScope rejects findings whose owning task belongs to another project.
func (s *Server) checkFindingScope(w http.ResponseWriter, r *http.Request, ids ...int64) bool {
	sc := APIScopeFrom(r.Context())
	if sc.Global {
		return true
	}
	projects, err := s.m.pg.FindingTaskProjects(ids)
	if err != nil {
		writeErr(w, 500, err.Error())
		return false
	}
	for _, id := range ids {
		if projects[id] != sc.ProjectID {
			writeErr(w, 404, "finding not found")
			return false
		}
	}
	return true
}

// requireAuth wraps h with JWT / API-key validation.
// /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "未授权")
			return
		}
		// 持久 API Key(zrec_ 前缀):长期有效,按 scope 收紧到项目。
		if strings.HasPrefix(tok, db.APIKeyPrefix) {
			if s.m == nil || s.m.PG() == nil {
				writeErr(w, 503, errDataSourceUnavailable)
				return
			}
			key, ok := s.m.PG().AuthenticateAPIKey(tok)
			if !ok {
				writeErr(w, 401, "API Key 无效、已禁用或已过期")
				return
			}
			sc := APIScope{Global: key.Scope == "global", KeyID: key.ID}
			if key.ProjectID != nil {
				sc.ProjectID = *key.ProjectID
			}
			if !sc.Global && !projectKeyPathAllowed(r.Method, p) {
				writeErr(w, 403, "项目级 API Key 无权访问该接口")
				return
			}
			// /api/tasks/{id}/... 统一在入口做归属校验,覆盖所有子路由。
			if !sc.Global && strings.HasPrefix(p, "/api/tasks/") {
				seg := strings.SplitN(strings.TrimPrefix(p, "/api/tasks/"), "/", 2)[0]
				if id, err := strconv.ParseInt(seg, 10, 64); err == nil && id > 0 {
					pid, err := s.m.PG().TaskProjectID(id)
					if err != nil || pid != sc.ProjectID {
						writeErr(w, 404, "task not found")
						return
					}
				}
			}
			h.ServeHTTP(w, r.WithContext(withAPIScope(r.Context(), sc)))
			return
		}
		if !verifyJWT(tok, s.jwtKey) {
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		h.ServeHTTP(w, r.WithContext(withAPIScope(r.Context(), APIScope{Global: true})))
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != "", "username": loginUsernameOf(pg)})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "密码已设置")
		return
	}
	var req struct {
		Password string `json:"password"`
		Username string `json:"username"` // 首次设置可自定义登录名;空=默认
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, "密码不能为空")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if msg := validateUsername(req.Username); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if name := strings.TrimSpace(req.Username); name != "" && name != defaultLoginUsername {
		if err := pg.SetSetting(authUserKey, name); err != nil {
			writeErr(w, 500, "保存用户名失败: "+err.Error())
			return
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "密码已设置")
		return
	}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !verifyJWT(extractToken(r), s.jwtKey) {
		writeErr(w, 401, "未授权")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
		NewUsername string `json:"new_username"` // 可选;非空且不同时一并改登录名
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validateUsername(req.NewUsername); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if name := strings.TrimSpace(req.NewUsername); name != "" && name != loginUsernameOf(pg) {
		if err := pg.SetSetting(authUserKey, name); err != nil {
			writeErr(w, 500, "保存用户名失败: "+err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Username) != loginUsernameOf(pg) {
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
