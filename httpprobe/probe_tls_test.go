package httpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDoRequestInsecureTLS 渗透目标普遍是自签/私有 CA 证书：
// transport 必须忽略 x509 校验（与 httpsession/fingerprint 同语义），
// 否则自签目标 100% 报 "certificate signed by unknown authority"。
func TestDoRequestInsecureTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tls-ok"))
	}))
	defer srv.Close()

	res, err := DoRequest(context.Background(), Request{URL: srv.URL, TimeoutSeconds: 10})
	if err != nil {
		t.Fatalf("自签证书应被忽略，实际报错: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}

// TestDoRequestTimeoutFollowsRequest timeout_seconds 参数必须作用于 client.Timeout，
// 而不是被默认 20s 硬编码截胡（否则 25/40/45s 的合法取值形同虚设）。
// 这里用 3s server 延迟 + 1s 超时验证"小于默认值的取值真实生效"。
func TestDoRequestTimeoutFollowsRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
			_, _ = w.Write([]byte("late"))
		}
	}))
	defer srv.Close()

	if _, err := DoRequest(context.Background(), Request{URL: srv.URL, TimeoutSeconds: 1}); err == nil {
		t.Fatal("1s 超时应掐断 3s 的响应，实际未超时")
	}
}
