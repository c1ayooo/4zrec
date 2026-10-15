package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// GetSetting 对"键不存在"和"读取出错"的返回值只差一个 error：两种情况 value 都是
// 空串。密码相关的 handler 一旦把 error 当成"还没设置密码"，就会在数据库抖动期间
// 敞开初始化入口——authInit 会放行一个未认证请求去覆盖已有的管理员密码，
// authStatus 则会把前端直接送到 /setup 去照着做这件事。
//
// 这两个测试把 handler 的连接池关掉来制造读取失败，断言两处都 fail closed。
func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	// 关掉池子，让后续 GetSetting 返回 error 而不是 sql.ErrNoRows。
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败被当成未初始化会把用户送去 /setup 覆盖密码); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("读失败时不应回答 initialized，得到 %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"password":"correct horse battery"}`)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", body))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败时放行会让未认证请求覆盖已有密码); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("读失败时不应签发 token: %s", w.Body.String())
	}
}

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name, pw string
		wantErr  bool
	}{
		{"空", "", true},
		{"七位", "1234567", true},
		{"八位", "12345678", false},
		{"八个汉字按字符数而非字节数计", "密码密码密码密码", false},
		{"三个汉字够 9 字节但只有 3 个字符", "密码强", true},
		{"72 字节", strings.Repeat("a", 72), false},
		{"73 字节超出 bcrypt 上限", strings.Repeat("a", 73), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.pw); (got != "") != tc.wantErr {
				t.Fatalf("validatePassword(%q)=%q, wantErr=%v", tc.pw, got, tc.wantErr)
			}
		})
	}
}

// TestLoginUsernameStoredAndMutable 登录名存库后的完整链路:init 自定义名 →
// status 回显 → 旧名登录失败/新名成功 → change 改名 → 再改名后旧名失效。
func TestLoginUsernameStoredAndMutable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := New(t.Context(), m, t.TempDir(), t.TempDir(), t.TempDir())
	// 共享测试库会残留上次运行的 auth 键,先清干净再断言默认回退。
	if _, err := m.pg.Exec(`DELETE FROM settings WHERE key IN ('auth.username','auth.password_hash')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM settings WHERE key IN ('auth.username','auth.password_hash')`)
	})

	// 未设置时回退默认名
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))
	var st struct {
		Username string `json:"username"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st.Username != "4zrec" {
		t.Fatalf("未自定义时登录名应为默认 4zrec, got %q", st.Username)
	}

	// init 带自定义用户名
	body := `{"password":"init-pass-123","username":"ops"}`
	w = httptest.NewRecorder()
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", strings.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("init status=%d body=%s", w.Code, w.Body.String())
	}

	// 旧默认名登录失败,自定义名成功
	tryLogin := func(user, pass string) int {
		rec := httptest.NewRecorder()
		s.authLogin(rec, httptest.NewRequest("POST", "/api/auth/login",
			strings.NewReader(`{"username":"`+user+`","password":"`+pass+`"}`)))
		return rec.Code
	}
	if code := tryLogin("4zrec", "init-pass-123"); code == 200 {
		t.Fatal("自定义用户名后旧默认名不应能登录")
	}
	if code := tryLogin("ops", "init-pass-123"); code != 200 {
		t.Fatalf("自定义用户名登录应成功, status=%d", code)
	}

	// status 回显自定义名;改名需携带 token + 当前密码
	w = httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st.Username != "ops" {
		t.Fatalf("status 应回显 ops, got %q", st.Username)
	}

	// 用 init 签发的 token 调 change(需先取出 token)
	w = httptest.NewRecorder()
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", strings.NewReader(`{"password":"x-unused-1"}`)))
	// 已初始化会 403,改用登录拿 token
	w = httptest.NewRecorder()
	s.authLogin(w, httptest.NewRequest("POST", "/api/auth/login",
		strings.NewReader(`{"username":"ops","password":"init-pass-123"}`)))
	var lr struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Token == "" {
		t.Fatal("登录未返回 token")
	}

	req := httptest.NewRequest("POST", "/api/auth/change-password",
		strings.NewReader(`{"old_password":"init-pass-123","new_password":"next-pass-456","new_username":"admin"}`))
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	w = httptest.NewRecorder()
	s.authChangePassword(w, req)
	if w.Code != 200 {
		t.Fatalf("change status=%d body=%s", w.Code, w.Body.String())
	}
	if code := tryLogin("ops", "next-pass-456"); code == 200 {
		t.Fatal("改名后旧用户名不应能登录")
	}
	if code := tryLogin("admin", "next-pass-456"); code != 200 {
		t.Fatalf("新用户名登录应成功, status=%d", code)
	}
}
