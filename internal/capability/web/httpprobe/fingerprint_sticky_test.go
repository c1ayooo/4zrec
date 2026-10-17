package httpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStickyFingerprintPerHost 同一业务整套指纹恒定:同 host 多次请求 UA 与
// Accept-Language 不变;不同 host 允许不同(确定性取值)。
func TestStickyFingerprintPerHost(t *testing.T) {
	var got []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, map[string]string{
			"ua": r.Header.Get("User-Agent"),
			"al": r.Header.Get("Accept-Language"),
			"ac": r.Header.Get("Accept"),
		})
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	for i := 0; i < 3; i++ {
		if _, err := DoRequest(context.Background(), Request{Method: "GET", URL: srv.URL + "/x"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != 3 {
		t.Fatalf("应收到 3 请求: %d", len(got))
	}
	if got[0]["ua"] == "" || got[0]["al"] == "" {
		t.Fatalf("指纹头缺失: %+v", got[0])
	}
	for i := 1; i < 3; i++ {
		if got[i]["ua"] != got[0]["ua"] || got[i]["al"] != got[0]["al"] {
			t.Fatalf("同一业务指纹应恒定: %+v vs %+v", got[0], got[i])
		}
	}
	// 确定性:直接调两次取值函数,结果一致(跨进程也稳定,fnv 散列)。
	a1 := stickyAcceptLanguageForURL("http://example.com/a")
	a2 := stickyAcceptLanguageForURL("http://example.com/b")
	if a1 != a2 {
		t.Fatalf("同 host 取值应确定: %q vs %q", a1, a2)
	}
	// 显式 UA 关闭随机化。
	if _, err := DoRequest(context.Background(), Request{Method: "GET", URL: srv.URL + "/x",
		Headers: map[string]string{"User-Agent": "custom/1.0", "Accept-Language": "en"}}); err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last["ua"] != "custom/1.0" || last["al"] != "en" {
		t.Fatalf("显式头应优先: %+v", last)
	}
}
