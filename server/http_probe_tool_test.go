package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/c1ayooo/4zrec/tools"
)

// TestHTTPProbeBatchMatrix template+matrix 差分:两行变量代入,逐包摘要;
// requests 直用与上限校验。
func TestHTTPProbeBatchMatrix(t *testing.T) {
	// 直调展开层(免网络:验证归一/代入/上限语义)。
	var in httpProbeInput
	raw := `{
		"template": {"label": "user-{id}", "url": "http://h/api/user/{id}", "headers": {"X-Role": "{role}"}},
		"matrix": [{"id": "1", "role": "a"}, {"id": "2", "role": "b"}]
	}`
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	specs, errMsg := expandProbeSpecs(&in)
	if errMsg != "" || len(specs) != 2 {
		t.Fatalf("展开失败: %v %d", errMsg, len(specs))
	}
	if specs[0].URL != "http://h/api/user/1" || specs[0].Headers["X-Role"] != "a" || specs[1].URL != "http://h/api/user/2" {
		t.Fatalf("代入不符: %+v %+v", specs[0], specs[1])
	}
	if specs[0].Label != "user-1" || specs[1].Label != "user-2" {
		t.Fatalf("label 代入不符: %q %q", specs[0].Label, specs[1].Label)
	}

	// range 展开 + 上限 50。
	var in2 httpProbeInput
	raw2 := `{"template": {"url": "http://h/x?id={n}"}, "range": {"var": "n", "from": 1, "to": 100, "step": 1}}`
	_ = json.Unmarshal([]byte(raw2), &in2)
	specs2, _ := expandProbeSpecs(&in2)
	if len(specs2) != 50 {
		t.Fatalf("range 应封顶 50: %d", len(specs2))
	}

	// 便捷头合并:headers 显式优先。
	var in3 httpProbeInput
	raw3 := `{"url": "http://h/", "cookie": "s=1", "headers": {"Cookie": "explicit=2"}}`
	_ = json.Unmarshal([]byte(raw3), &in3)
	specs3, _ := expandProbeSpecs(&in3)
	if specs3[0].Headers["Cookie"] != "explicit=2" {
		t.Fatalf("显式 Cookie 应优先: %+v", specs3[0].Headers)
	}

	// requests 超限报错。
	var in4 httpProbeInput
	var many []map[string]any
	for i := 0; i < 51; i++ {
		many = append(many, map[string]any{"url": "http://h/x"})
	}
	b4, _ := json.Marshal(map[string]any{"requests": many})
	_ = json.Unmarshal(b4, &in4)
	if _, msg := expandProbeSpecs(&in4); !strings.Contains(msg, "上限 50") {
		t.Fatalf("超限应报错: %q", msg)
	}
	_ = context.Background()
}

// TestHTTPProbeChainingCookieJarAndSave 串行链:第一包从响应体提取 token,
// cookie_jar 收下 Set-Cookie;第二包用 {token} 回填头、自动带 Cookie,响应体落盘。
func TestHTTPProbeChainingCookieJarAndSave(t *testing.T) {
	var gotToken, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/"})
			_, _ = w.Write([]byte(`{"csrf":"tok-xyz"}`))
		case "/next":
			gotToken = r.Header.Get("X-CSRF")
			gotCookie = r.Header.Get("Cookie")
			_, _ = w.Write([]byte("secret-body"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	workDir := t.TempDir()
	in := map[string]any{
		"cookie_jar": true,
		"requests": []map[string]any{
			{
				"label": "login", "url": srv.URL + "/login",
				"extract": map[string]any{
					"token": map[string]any{"from": "body", "regex": `"csrf":"([^"]+)"`},
				},
			},
			{
				"label": "next", "url": srv.URL + "/next",
				"headers":      map[string]string{"X-CSRF": "{token}"},
				"save_to_file": "out/next.bin",
			},
		},
	}
	raw, _ := json.Marshal(in)
	s := &Server{}
	res, err := s.toolHTTPProbe().Call(context.Background(), raw, &actool.ToolContext{WorkingDir: workDir})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Flatten()
	if res.IsError {
		t.Fatalf("http_probe 失败: %s", out)
	}
	if gotToken != "tok-xyz" {
		t.Fatalf("第二包应收到回填的 token,got %q\n输出:\n%s", gotToken, out)
	}
	if !strings.Contains(gotCookie, "sid=abc123") {
		t.Fatalf("第二包应自动带 cookie_jar 里的 Cookie,got %q", gotCookie)
	}
	if !strings.Contains(out, "提取 token = tok-xyz") || !strings.Contains(out, "已保存 out/next.bin") {
		t.Fatalf("输出应包含提取/落盘提示: %s", out)
	}
	saved, rerr := os.ReadFile(filepath.Join(workDir, "out", "next.bin"))
	if rerr != nil {
		t.Fatalf("落盘文件缺失: %v", rerr)
	}
	if string(saved) != "secret-body" {
		t.Fatalf("落盘内容不符: %q", string(saved))
	}
}

// TestResolveProbeSavePath 落盘路径限制在工作目录内。
func TestResolveProbeSavePath(t *testing.T) {
	for _, bad := range []string{"/etc/passwd", "../x", "a/../../b"} {
		if _, err := resolveProbeSavePath("/work", bad); err == nil {
			t.Fatalf("%q 应被拒绝", bad)
		}
	}
	got, err := resolveProbeSavePath("/work", "out/a.txt")
	if err != nil || got != "/work/out/a.txt" {
		t.Fatalf("合法路径解析错误: %q %v", got, err)
	}
}
