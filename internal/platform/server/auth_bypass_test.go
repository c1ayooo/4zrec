package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func authTestServer() *Server {
	return &Server{jwtKey: []byte("01234567890123456789012345678901")}
}

func authTestHandler(s *Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tasks", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SECRET"))
	})
	root := http.NewServeMux()
	root.Handle("/api/", s.requireAuth(mux))
	return root
}

func TestRequireAuthRejectsPathNormalizationBypass(t *testing.T) {
	h := authTestHandler(authTestServer())
	for _, path := range []string{
		"/api/auth/../tasks",
		"/api/auth/%2e%2e/tasks",
		"/api/auth/..%2ftasks",
		"/api/auth/./../tasks",
		"//api/auth/../tasks",
		"/api//auth/../tasks",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		body := w.Body.String()
		loc := w.Header().Get("Location")
		if w.Code == http.StatusOK && strings.Contains(body, "SECRET") {
			t.Fatalf("%s bypassed requireAuth: %d %q", path, w.Code, body)
		}
		t.Logf("%s -> %d location=%q body=%q", path, w.Code, loc, body)
	}
}

func TestVerifyJWTRejectsForgedTokens(t *testing.T) {
	s := authTestServer()
	now := time.Now()

	// alg=none
	noneTok, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.RegisteredClaims{
		Subject: defaultLoginUsername, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if verifyJWT(noneTok, s.jwtKey) {
		t.Fatal("alg=none token accepted")
	}

	// signed with a different key
	other, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: defaultLoginUsername, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}).SignedString([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	if err != nil {
		t.Fatal(err)
	}
	if verifyJWT(other, s.jwtKey) {
		t.Fatal("token signed with another key accepted")
	}

	// expired
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: defaultLoginUsername, ExpiresAt: jwt.NewNumericDate(now.Add(-time.Minute)),
	}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	if verifyJWT(expired, s.jwtKey) {
		t.Fatal("expired token accepted")
	}

	// valid
	valid, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyJWT(valid, s.jwtKey) {
		t.Fatal("valid token rejected")
	}

	// no exp, correctly signed: expiration is mandatory
	noExp, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: defaultLoginUsername,
	}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	if verifyJWT(noExp, s.jwtKey) {
		t.Fatal("token without exp accepted")
	}
}

func TestValidateUsernameAllowsEmptyAsDefaultOrKeep(t *testing.T) {
	for _, name := range []string{"", "   "} {
		if msg := validateUsername(name); msg != "" {
			t.Fatalf("empty username %q rejected with %q; init/keep semantics need it", name, msg)
		}
	}
	if msg := validateUsername(strings.Repeat("a", maxUsernameRunes+1)); msg == "" {
		t.Fatal("over-long username accepted")
	}
}

func TestJWTKeyFilePermissionsAreTightened(t *testing.T) {
	keyDir := t.TempDir()
	path := filepath.Join(keyDir, jwtKeyFilename)
	want := "01234567890123456789012345678901"
	if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}
	key, err := loadOrCreateJWTKey(keyDir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != want {
		t.Fatalf("existing key not preserved: %q", key)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("jwt.key mode=%o want 600 (world-readable key allows token forgery)", got)
	}
}

func TestAuthClientKeyIgnoresForwardedHeadersByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "172.17.0.1:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.Header.Set("X-Real-IP", "198.51.100.8")

	t.Setenv("ZREC_TRUST_PROXY_HEADERS", "")
	if got := authClientKey(req); got != "172.17.0.1" {
		t.Fatalf("default key=%q, forwarded header must be ignored", got)
	}

	t.Setenv("ZREC_TRUST_PROXY_HEADERS", "1")
	if got := authClientKey(req); got != "198.51.100.7" {
		t.Fatalf("trusted-proxy key=%q want 198.51.100.7", got)
	}
}

func TestAuthChangePasswordRotatesJWTKey(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	oldHash, hadHash, err := m.pg.GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	oldUser, hadUser, err := m.pg.GetSetting(authUserKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadHash {
			_ = m.pg.SetSetting(authPassKey, oldHash)
		} else {
			_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
		}
		if hadUser {
			_ = m.pg.SetSetting(authUserKey, oldUser)
		} else {
			_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authUserKey)
		}
		authReset("chpw:203.0.113.9")
	})

	hash, err := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}

	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, jwtKeyFilename)
	oldKey := []byte("01234567890123456789012345678901")
	if err := os.WriteFile(keyPath, oldKey, 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m, jwtKey: oldKey, jwtKeyPath: keyPath}
	oldTok, err := signJWT(oldKey)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"old_password":"oldpassword","new_password":"newpassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.9:4567"
	req.Header.Set("Authorization", "Bearer "+oldTok)
	w := httptest.NewRecorder()
	s.authChangePassword(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Token == "" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if !verifyJWT(resp.Token, s.jwtKeyBytes()) {
		t.Fatal("new token rejected")
	}
	if verifyJWT(oldTok, s.jwtKeyBytes()) {
		t.Fatal("old token still valid after password change")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("rotated jwt.key mode=%o want 600", got)
	}
	onDisk, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != string(s.jwtKeyBytes()) {
		t.Fatal("rotated key not persisted")
	}
}

func TestBootstrapAdminPasswordGeneratesOnce(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	oldHash, hadHash, err := m.pg.GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	oldUser, hadUser, err := m.pg.GetSetting(authUserKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadHash {
			_ = m.pg.SetSetting(authPassKey, oldHash)
		} else {
			_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
		}
		if hadUser {
			_ = m.pg.SetSetting(authUserKey, oldUser)
		} else {
			_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authUserKey)
		}
	})
	if _, err := m.pg.Exec(`DELETE FROM settings WHERE key IN ($1,$2)`, authPassKey, authUserKey); err != nil {
		t.Fatal(err)
	}

	generated, username, password, err := BootstrapAdminPassword(m)
	if err != nil {
		t.Fatal(err)
	}
	if !generated {
		t.Fatal("fresh database should generate an initial password")
	}
	if username != defaultLoginUsername || len(password) != 20 {
		t.Fatalf("generated username=%q password length=%d", username, len(password))
	}
	for _, r := range password {
		if !strings.ContainsRune(initialAdminPasswordChars, r) {
			t.Fatalf("password contains unexpected rune %q", r)
		}
	}
	hash, ok, err := m.pg.GetSetting(authPassKey)
	if err != nil || !ok {
		t.Fatalf("hash not stored: ok=%v err=%v", ok, err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		t.Fatalf("stored hash does not match printed password: %v", err)
	}

	generated, _, secondPassword, err := BootstrapAdminPassword(m)
	if err != nil {
		t.Fatal(err)
	}
	if generated || secondPassword != "" {
		t.Fatal("second startup must not regenerate or reprint the password")
	}
	hash2, _, err := m.pg.GetSetting(authPassKey)
	if err != nil || hash2 != hash {
		t.Fatal("existing password hash was overwritten")
	}
}
