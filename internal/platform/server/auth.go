package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/c1ayooo/4zrec/internal/domain/db"
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

// Online password guessing against the single admin account used to be
// unlimited. Keep a tiny in-memory per-IP failure window: five failures in five
// minutes lock the IP for fifteen minutes. No external dependency needed.
const (
	authMaxFailures   = 5
	authFailureWindow = 5 * time.Minute
	authLockout       = 15 * time.Minute
)

type authFailState struct {
	failures     int
	windowStart  time.Time
	blockedUntil time.Time
}

var authAttempts = struct {
	sync.Mutex
	m map[string]*authFailState
}{m: map[string]*authFailState{}}

func authClientKey(r *http.Request) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		host = "unknown"
	}
	// Forwarded headers are opt-in. In the default Docker port mapping every
	// external client appears as the private gateway, and the client controls
	// X-Forwarded-For — trusting it by default would let an attacker rotate the
	// limiter key on every request. Set ZREC_TRUST_PROXY_HEADERS=1 only behind a
	// reverse proxy that sanitizes/overwrites these headers.
	if trustProxyHeaders() {
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				first := strings.TrimSpace(strings.Split(xff, ",")[0])
				if net.ParseIP(first) != nil {
					return first
				}
			}
			if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(realIP) != nil {
				return realIP
			}
		}
	}
	return host
}

func trustProxyHeaders() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ZREC_TRUST_PROXY_HEADERS"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func authRetryAfter(key string) time.Duration {
	authAttempts.Lock()
	defer authAttempts.Unlock()
	st := authAttempts.m[key]
	if st == nil {
		return 0
	}
	if now := time.Now(); now.Before(st.blockedUntil) {
		return time.Until(st.blockedUntil)
	}
	return 0
}

func authRecordFailure(key string) {
	now := time.Now()
	authAttempts.Lock()
	defer authAttempts.Unlock()
	st := authAttempts.m[key]
	if st == nil {
		st = &authFailState{windowStart: now}
		authAttempts.m[key] = st
	}
	if now.Sub(st.windowStart) > authFailureWindow {
		st.failures = 0
		st.windowStart = now
	}
	st.failures++
	if st.failures >= authMaxFailures {
		st.blockedUntil = now.Add(authLockout)
		st.failures = 0
		st.windowStart = now
	}
	// Bound memory: drop entries whose window and lockout have both expired.
	if len(authAttempts.m) > 4096 {
		for k, v := range authAttempts.m {
			if now.After(v.blockedUntil) && now.Sub(v.windowStart) > authFailureWindow {
				delete(authAttempts.m, k)
			}
		}
	}
}

func authReset(key string) {
	authAttempts.Lock()
	delete(authAttempts.m, key)
	authAttempts.Unlock()
}

func tooManyAttempts(w http.ResponseWriter, retry time.Duration) bool {
	if retry <= 0 {
		return false
	}
	secs := int(retry.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("尝试过于频繁，请 %d 秒后再试", secs))
	return true
}

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
// 空值在调用方有特定含义（init=用默认名，change-password=保持原名），
// 因此这里把空串视为通过，只校验非空值的长度。
func validateUsername(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
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
				if werr := writeJWTKey(path, data); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		// Older installs may have created this file 0644. Anyone who can read it
		// can forge an admin JWT, so tighten it on every startup.
		_ = os.Chmod(path, 0o600)
		return []byte(strings.TrimSpace(string(data))), nil
	}
	key, err := generateJWTKey()
	if err != nil {
		return nil, err
	}
	if err := writeJWTKey(path, key); err != nil {
		return nil, err
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return key, nil
}

// generateJWTKey returns a 32-character key drawn from crypto/rand (~190 bits).
func generateJWTKey() ([]byte, error) {
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	return buf, nil
}

// writeJWTKey persists the key owner-only. os.WriteFile does not change the
// mode of an existing file, hence the explicit Chmod.
func writeJWTKey(path string, key []byte) error {
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return fmt.Errorf("write jwt key: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod jwt key: %w", err)
	}
	return nil
}

// initialAdminPasswordChars omits ambiguous glyphs (0/O, 1/l/I) so the
// password printed in the logs is easy to copy correctly.
const initialAdminPasswordChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func generateInitialAdminPassword() (string, error) {
	const length = 20
	buf := make([]byte, length)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(initialAdminPasswordChars))))
		if err != nil {
			return "", fmt.Errorf("generate initial admin password: %w", err)
		}
		buf[i] = initialAdminPasswordChars[n.Int64()]
	}
	return string(buf), nil
}

// BootstrapAdminPassword generates and persists a random admin password when
// the database has no auth.password_hash yet (first startup). The password is
// logged exactly once. Concurrent process starts race on InitSettingPair; only
// the winner prints, so the logged password is the one that actually works.
//
// This closes the first-run takeover window: without it, anyone who reaches
// /api/auth/init (or the /setup page) before the operator can claim admin.
func BootstrapAdminPassword(m *Manager) (generated bool, username, password string, err error) {
	if m == nil || m.pg == nil {
		return false, "", "", nil
	}
	hash, ok, err := m.pg.GetSetting(authPassKey)
	if err != nil {
		return false, "", "", fmt.Errorf("读取初始化状态失败: %w", err)
	}
	if ok && strings.TrimSpace(hash) != "" {
		return false, "", "", nil
	}
	password, err = generateInitialAdminPassword()
	if err != nil {
		return false, "", "", err
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, "", "", fmt.Errorf("密码加密失败: %w", err)
	}
	inserted := false
	if ok {
		// A row exists but holds an empty/corrupt hash; repair it. This can't
		// be a legitimate password, and leaving it would brick login while
		// also blocking InitSettingPair (the key already exists).
		if err := m.pg.SetSetting(authPassKey, string(hashed)); err != nil {
			return false, "", "", fmt.Errorf("修复空密码哈希失败: %w", err)
		}
		inserted = true
	} else {
		inserted, err = m.pg.InitSettingPair(authPassKey, string(hashed), "", "")
		if err != nil {
			return false, "", "", fmt.Errorf("保存初始密码失败: %w", err)
		}
	}
	if !inserted {
		// Another process won the race; its log line holds the valid password.
		return false, "", "", nil
	}
	username = loginUsernameOf(m.pg)
	log.Printf("============================================================")
	log.Printf("[auth] 首次启动：已生成随机管理员密码（仅打印一次）")
	log.Printf("[auth] 登录用户名: %s", username)
	log.Printf("[auth] 登录密码:   %s", password)
	log.Printf("[auth] 登录后请立即修改密码；忘记可执行 ./reset-password.sh")
	log.Printf("============================================================")
	return true, username, password, nil
}

// jwtKeyBytes returns the current signing key under the rotation lock.
func (s *Server) jwtKeyBytes() []byte {
	s.jwtMu.RLock()
	defer s.jwtMu.RUnlock()
	return s.jwtKey
}

// rotateJWTKey generates a fresh signing key, persists it, and swaps it in.
// Every previously issued token becomes invalid immediately.
func (s *Server) rotateJWTKey() ([]byte, error) {
	key, err := generateJWTKey()
	if err != nil {
		return nil, err
	}
	if s.jwtKeyPath != "" {
		if err := writeJWTKey(s.jwtKeyPath, key); err != nil {
			return nil, err
		}
	}
	s.jwtMu.Lock()
	s.jwtKey = key
	s.jwtMu.Unlock()
	return key, nil
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
// Expiration is mandatory: a token without exp must not be accepted even if
// signed with the right key.
func verifyJWT(tokenStr string, key []byte) bool {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	}, jwt.WithExpirationRequired())
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
	// Query-string tokens are only for GET streams/downloads (EventSource cannot
	// set headers). Accepting them on mutations makes a leaked URL a replayable
	// credential for side-effectful calls.
	if r.Method == http.MethodGet {
		return r.URL.Query().Get("token")
	}
	return ""
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
		// 项目范围是授权根(scope = RoE):项目级 Key 只能读,不能扩权。
		// 读候选允许(只读),追加/导入/删除一律全局。
		return method == http.MethodGet && strings.HasSuffix(path, "/scope/candidates")
	}
	if path == "/api/tasks" {
		return true // GET 列表 / POST 创建(创建时强制本项目)
	}
	if strings.HasPrefix(path, "/api/capkit/sessions") {
		// 会话按打开时的项目隔离(capkitOwnsSession):项目 Key 只能看、驱动
		// 本项目打开的 foothold,列表/打开/执行/关闭全部路由可进。
		return true
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
		// 项目 Key 只读列表;资产登记/删除属于授权或破坏性操作,只允许全局。
		return method == http.MethodGet
	}
	switch path {
	case "/api/assets/pending", "/api/assets/bind", "/api/assets/probe":
		return true
		// /api/assets/authz(批准/驳回)是授权动作,只允许全局凭据。
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
		// 项目 Key 只能查看待审批记录;批准/驳回是人工授权动作,只允许全局凭据。
		return method == http.MethodGet
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
// /api/auth/* and /api/health are exempt. /api/im/wecom/callback 豁免——企业微信
// 回调无法携带 JWT，端点内部用回调配置的 Token/EncodingAESKey 自验签。
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" || p == imWecomURLVerify {
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
		if !verifyJWT(tok, s.jwtKeyBytes()) {
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
	limitKey := "init:" + authClientKey(r)
	if tooManyAttempts(w, authRetryAfter(limitKey)) {
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
		authRecordFailure(limitKey)
		writeErr(w, 400, "密码不能为空")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		authRecordFailure(limitKey)
		writeErr(w, 400, msg)
		return
	}
	if msg := validateUsername(req.Username); msg != "" {
		authRecordFailure(limitKey)
		writeErr(w, 400, msg)
		return
	}
	name := strings.TrimSpace(req.Username)
	if name == defaultLoginUsername {
		name = ""
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// 用事务同时完成"密码仅首次可设"与用户名写入：上面那次 GetSetting 只是
	// 快速失败路径，真正保证落在主键约束上。bcrypt 要跑几十毫秒，这期间别的
	// 请求完全可能先把密码设好；若先写用户名再抢密码，输掉竞争的一方仍会改掉
	// 管理员登录名。InitSettingPair 只在密码插入成功时才写用户名。
	inserted, err := pg.InitSettingPair(authPassKey, string(hash), authUserKey, name)
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "密码已设置")
		return
	}
	authReset(limitKey)
	tok, err := signJWT(s.jwtKeyBytes())
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
	if !verifyJWT(extractToken(r), s.jwtKeyBytes()) {
		writeErr(w, 401, "未授权")
		return
	}
	limitKey := "chpw:" + authClientKey(r)
	if tooManyAttempts(w, authRetryAfter(limitKey)) {
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
		authRecordFailure(limitKey)
		writeErr(w, 401, "当前密码错误")
		return
	}
	authReset(limitKey)
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
	// 改密必须吊销旧会话:轮换 jwt.key 后所有已签发 token 立即失效。
	// 失败时保留旧 key(否则重启后旧 token 会复活)，并明确告知用户。
	if _, err := s.rotateJWTKey(); err != nil {
		log.Printf("[auth] 密码已修改但 JWT key 轮换失败: %v", err)
		writeErr(w, 500, "密码已修改，但轮换签名密钥失败；旧 token 仍未失效，请检查 jwt.key 可写后重试")
		return
	}
	tok, err := signJWT(s.jwtKeyBytes())
	if err != nil {
		writeErr(w, 500, "密码已修改，但新 token 生成失败，请重新登录")
		return
	}
	log.Printf("[auth] 密码已修改，JWT 签名密钥已轮换，旧 token 全部失效")
	writeJSON(w, 200, map[string]any{"ok": true, "token": tok})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	limitKey := "login:" + authClientKey(r)
	if tooManyAttempts(w, authRetryAfter(limitKey)) {
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
		authRecordFailure(limitKey)
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
		authRecordFailure(limitKey)
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	authReset(limitKey)
	tok, err := signJWT(s.jwtKeyBytes())
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
