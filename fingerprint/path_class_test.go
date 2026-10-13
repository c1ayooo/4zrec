package fingerprint

import "testing"

// 「把静态资源当目标」过滤的边界用例：三组扩展名各取代表 + 易误伤场景。
func TestPathKindGroups(t *testing.T) {
	cases := []struct{ path, want string }{
		// 动态页面组：裸 token 拒绝、带 scheme 放行的那一组
		{"/oa/login.jsp", "page"},
		{"/index.HTML", "page"},   // 大小写不敏感
		{"/admin.action", "page"}, // Struts 风格
		// 静态资源组：无论裸 token 还是带 scheme 都不是指纹目标
		{"/static/app.css", "static"},
		{"/js/app.mjs", "static"},
		{"/logo.PNG", "static"},
		{"/fonts/a.woff2", "static"},
		{"/docs/report.pdf", "static"},
		{"/backup/db.sql", "static"},
		{"/v1.2/jquery.min.map", "static"},
		{"/data/export.csv", "static"},
		// 不该被拦的
		{"/api/v2/users", ""},        // REST 路径
		{"/oa/login", ""},            // 无扩展名
		{"/download?file=a.css", ""}, // 扩展名在查询串里，不算
		{"/path/to/", ""},            // 以斜杠结尾
		{"https://x.com:8443", ""},   // 主机+端口无路径
	}
	for _, c := range cases {
		if got := PathKind(c.path); got != c.want {
			t.Errorf("PathKind(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// 页面里的静态资源链接不该进 links/link_hosts 候选；页面类链接保留。
func TestExtractLinksDropsStaticResources(t *testing.T) {
	page := `<html><body>
		<a href="/static/app.css">样式</a>
		<a href="/js/app.js">脚本</a>
		<a href="/logo.png">图片</a>
		<a href="/oa/login.jsp">OA 入口</a>
		<a href="https://other.example.com/help.pdf">帮助 PDF</a>
		<a href="/about">关于我们</a>
	</body></html>`
	links := ExtractLinks(page, "https://portal.example.com/", 50)
	for _, l := range links {
		if PathKind(l) == "static" {
			t.Fatalf("静态资源链接应被过滤: %v", links)
		}
	}
	if len(links) != 2 {
		t.Fatalf("应只剩页面类与无扩展名链接: %v", links)
	}
}
