package legacyhunter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseCDX(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"标准响应", `[["timestamp","original","statuscode"],["20200101000000","http://example.com/login","200"],["20200102000000","http://example.com/admin/.env","200"]]`, 2},
		{"无快照", `[["timestamp","original","statuscode"]]`, 0},
		{"空响应", ``, 0},
		{"字段缺失", `[["timestamp","original"],["20200101000000","http://x/"]]`, 1},
	}
	for _, c := range cases {
		got, err := parseCDX([]byte(c.in))
		if err != nil {
			t.Errorf("%s: 不应报错: %v", c.name, err)
			continue
		}
		if len(got) != c.want {
			t.Errorf("%s: len=%d, want %d", c.name, len(got), c.want)
			continue
		}
		if c.want > 0 && got[0].Timestamp == "" {
			t.Errorf("%s: timestamp 未解析", c.name)
		}
	}
}

func TestQueryCDXBadDomain(t *testing.T) {
	if _, err := QueryCDX(context.Background(), "", CDXOptions{}); err == nil {
		t.Fatal("空域名应报错")
	}
}

func TestFrameworkFingerprintMatch(t *testing.T) {
	cases := []struct {
		path   string
		hit    bool
		fwName string
	}{
		{"/login.action", true, "Apache Struts 2"},
		{"/user/show.do", true, "Apache Struts 2"},
		{"/index.jsp", true, "Java Servlet 旧应用"},
		{"/default.aspx", true, "旧版 ASP/ASP.NET"},
		{"/page.php", true, "旧版 PHP"},
		{"/old.php5", true, "旧版 PHP"},
		{"/app.cfm", true, "ColdFusion"},
		{"/weblogic/wls-wsat/CoordinatorPortType", true, "WebLogic wls-wsat"},
		{"/console/login/LoginForm.jsp", true, "旧版 WebSphere/WebLogic 管理端"},
		{"/index.html", false, ""},
		{"/api/v1/users", false, ""},
		{"/static/app.css", false, ""},
	}
	for _, c := range cases {
		got := false
		var name string
		for _, fp := range legacyFingerprints {
			if matchPathPattern(c.path, fp.PathRe) {
				got = true
				name = fp.Name
				break
			}
		}
		if got != c.hit {
			t.Errorf("matchPathPattern(%q) hit=%v, want %v", c.path, got, c.hit)
			continue
		}
		if c.hit && name != c.fwName {
			t.Errorf("matchPathPattern(%q) 命中 %s, want %s", c.path, name, c.fwName)
		}
	}
}

func TestUniquePaths(t *testing.T) {
	history := []CDXEntry{
		{Original: "http://example.com/login"},
		{Original: "http://example.com/login"},
		{Original: "http://example.com/admin/.env"},
		{Original: "http://example.com/img/logo.png"},
		{Original: "http://example.com"},
	}
	paths := uniquePaths(history)
	joined := strings.Join(paths, ",")
	if !strings.Contains(joined, "/login") || !strings.Contains(joined, "/admin/.env") {
		t.Errorf("应保留登录/环境配置路径: %v", paths)
	}
	if strings.Contains(joined, ".png") {
		t.Errorf("静态资源不应进入候选: %v", paths)
	}
	if len(paths) != 3 {
		t.Errorf("去重/排除后应为 3 条（login/admin/根）: %v", paths)
	}
}

// TestHunterRunIntrospect 零出网模式：无 HTTPClient 时只做历史指纹，不探测。
func TestHunterRunIntrospect(t *testing.T) {
	h := New(Options{Domain: "https://example.com", EnableProbe: true}) // 无 client → 探测自动关闭
	history := []CDXEntry{
		{Original: "http://example.com/login.action"},
		{Original: "http://example.com/admin.jsp"},
		{Original: "http://example.com/about.html"},
	}
	out, err := h.Run(context.Background(), history)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if len(out.Frameworks) != 2 {
		t.Fatalf("应命中 Struts + JSP 两个框架: %+v", out.Frameworks)
	}
	if len(out.Endpoints) != 0 || !strings.Contains(out.EOLNote, "遗留") {
		t.Fatalf("零出网模式不应探测端点且应给 EOL 提示: %+v", out)
	}
}

// TestHunterProbeBackupHTTP 用纯 http:// 域的探测分支（覆盖 httptest 环境，验证
// scheme 保留 + 当前 404 识别 + 备份后缀命中全链路）。
func TestHunterProbeBackupHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".bak") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("backup content"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// 直接用 probeEndpoint 单测（绕过 https 拼接差异）。
	u := srv.URL // http://127.0.0.1:port
	budget := 30
	ctx := context.Background()
	h := New(Options{Domain: u, HTTPClient: srv.Client(), EnableProbe: true, Timeout: 5e9})
	hit := func() EndpointHit { return h.probeEndpoint(ctx, "/config", &budget) }
	// 当前 /config 404 → 遗留端点；.bak 命中。
	got := hit()
	if got.Path == "" {
		t.Fatal("历史端点当前 404 应识别为遗留端点")
	}
	foundBackup := false
	for _, bh := range got.BackupHits {
		if strings.HasSuffix(bh, "config.bak") {
			foundBackup = true
		}
	}
	if !foundBackup {
		t.Fatalf("备份后缀 .bak 应命中: %+v", got)
	}
}
