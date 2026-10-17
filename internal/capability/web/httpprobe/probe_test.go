package httpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 随机指纹：默认 UA 来自浏览器池（非 Probe/Go 默认），且报文 dump 呈现实际头
func TestDoRequest_RandomFingerprint(t *testing.T) {
	var seenUA []string
	var seenAccept int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA = append(seenUA, r.Header.Get("User-Agent"))
		if r.Header.Get("Accept") != "" {
			seenAccept++
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	for i := 0; i < 6; i++ {
		res, err := DoRequest(nil2ctx(), Request{URL: srv.URL})
		if err != nil {
			t.Fatalf("请求失败: %v", err)
		}
		ua := firstHeaderLine(res.RequestText, "User-Agent:")
		if ua == "" || strings.Contains(ua, "Probe") || strings.Contains(ua, "Go-http") {
			t.Errorf("UA 未随机化或异常: %q", ua)
		}
		if !strings.Contains(res.RequestText, "Accept-Language:") {
			t.Error("报文缺少 Accept-Language")
		}
	}
	if seenAccept != 6 {
		t.Errorf("服务端应每次收到 Accept 头: %d/6", seenAccept)
	}
	distinct := map[string]bool{}
	for _, ua := range seenUA {
		distinct[ua] = true
	}
	if len(distinct) < 2 {
		t.Logf("UA 池采样 6 次仅 %d 个不同值（概率性，不判失败）", len(distinct))
	}
}

// 显式 UA 优先
func TestDoRequest_ExplicitUA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "MyCustom/1.0" {
			t.Errorf("显式 UA 被覆盖: %q", r.Header.Get("User-Agent"))
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, err := DoRequest(nil2ctx(), Request{URL: srv.URL, Headers: map[string]string{"User-Agent": "MyCustom/1.0"}})
	if err != nil {
		t.Fatal(err)
	}
}

// off 关闭随机化
func TestDoRequest_FingerprintOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Language") != "" {
			t.Error("off 时不应补 Accept-Language")
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, err := DoRequest(nil2ctx(), Request{URL: srv.URL, RandomFingerprint: "off"})
	if err != nil {
		t.Fatal(err)
	}
}

func firstHeaderLine(dump, prefix string) string {
	for _, line := range strings.Split(dump, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

// BodySink：响应体完整写入 sink（含超过内存捕获上限的部分），快照仍截断。
func TestDoRequest_BodySink(t *testing.T) {
	big := strings.Repeat("A", maxBodyCapture+4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	var sink strings.Builder
	res, err := DoRequest(nil2ctx(), Request{URL: srv.URL, BodySink: &sink})
	if err != nil {
		t.Fatal(err)
	}
	if got := sink.Len(); got != len(big) {
		t.Fatalf("sink 应收到完整响应体 %d 字节,got %d", len(big), got)
	}
	if res.BodyBytes != int64(len(big)) {
		t.Fatalf("BodyBytes=%d,want %d", res.BodyBytes, len(big))
	}
	if len(res.RespBody) != maxBodyCapture {
		t.Fatalf("内存快照应按上限截断到 %d,got %d", maxBodyCapture, len(res.RespBody))
	}
}

func nil2ctx() context.Context { return context.Background() }

// 粘性 UA：同 host 多次请求 UA 一致（会话内稳定），不同 host 各自独立
func TestStickyUserAgent(t *testing.T) {
	ua1 := stickyUserAgentForURL("http://t1.com/a")
	ua2 := stickyUserAgentForURL("http://t1.com/b?x=1")
	if ua1 == "" || ua1 != ua2 {
		t.Errorf("同 host UA 应粘性一致: %q vs %q", ua1, ua2)
	}
	ua3 := stickyUserAgentForURL("http://t2.com/")
	_ = ua3 // 不同 host 独立分配（可能相同也可能不同，池内即可）
	if stickyUserAgentForURL("http://t1.com/c") != ua1 {
		t.Error("粘性缓存失效")
	}
	// 显式 UA 仍优先（DoRequest 层逻辑，此处验证 helper 不干扰）
	if vulnutilUA(t) == "" {
		t.Error("UA 池为空")
	}
}
func vulnutilUA(t *testing.T) string {
	t.Helper()
	return stickyUserAgentForURL("http://pool-check.com/")
}
