package fingerprint

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// 批次 A（GBK 入库崩溃定位）：某目标页面标题含 GBK 字节（0xce 0xf7="维"）时，
// 原实现把原始字节直接当字符串入库，PostgreSQL 报 invalid byte sequence，
// 聚合 upsert 整批失败。本批验证：GBK 页面（响应头声明 / meta 声明 / 未声明）
// 三种情况标题都能以合法 UTF-8 返回，body_hash 保持原始字节口径。

func encodeGBK(t *testing.T, s string) []byte {
	t.Helper()
	b, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatalf("GBK 编码失败: %v", err)
	}
	return b
}

func TestProbeGBKTitleDeclaredInHeader(t *testing.T) {
	title := "欢迎使用统一身份认证"
	// 真实 GBK 页面整页都是 GBK 字节（正文里的备案号也不例外）
	raw := append([]byte("<html><head><title>"), encodeGBK(t, title)...)
	raw = append(raw, encodeGBK(t, "</title></head><body>粤ICP备14006354号-1</body></html>")...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=gbk")
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	obs, err := ProbeHTTPObservation(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if obs.Title != title {
		t.Fatalf("GBK 标题应解码为 %q, got %q", title, obs.Title)
	}
	if !utf8.ValidString(obs.Title) {
		t.Fatal("标题必须是合法 UTF-8")
	}
	if obs.ICP != "粤ICP备14006354号" {
		t.Fatalf("GBK 页面的备案号提取失败: %q", obs.ICP)
	}
	// body_hash 保持原始字节口径（与外部测绘哈希可比），不随解码变化
	sum := md5.Sum(raw)
	if obs.BodyHash != hex.EncodeToString(sum[:]) {
		t.Fatal("body_hash 应基于原始字节而非解码后文本")
	}
}

func TestProbeGBKTitleDeclaredInMeta(t *testing.T) {
	title := "维持续办公系统"
	raw := append([]byte("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=gbk\"><title>"),
		encodeGBK(t, title)...)
	raw = append(raw, []byte("</title></head></html>")...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html") // 头里无 charset，靠 meta 嗅探
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	obs, err := ProbeHTTPObservation(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if obs.Title != title {
		t.Fatalf("meta 声明的 GBK 标题应解码为 %q, got %q", title, obs.Title)
	}
}

func TestProbeUndeclaredGBKTitleStillValidUTF8(t *testing.T) {
	// 未声明 charset 的 GBK 页面：无法正确解码，但非法字节必须被替换（\uFFFD），
	// 绝不能让非法 UTF-8 流进资产库
	raw := append([]byte("<html><head><title>"), encodeGBK(t, "统一身份认证平台")...)
	raw = append(raw, []byte("</title></head></html>")...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	obs, err := ProbeHTTPObservation(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if !utf8.ValidString(obs.Title) {
		t.Fatalf("标题含非法 UTF-8: %q", obs.Title)
	}
}

func TestProbeFiltersMalformedLinkHosts(t *testing.T) {
	page := `<html><body>
		<a href="/oa/login.html">OA</a>
		<a href="http://bad_host.example/">正常</a>
		<a href="http://under_score.example.com/">下划线主机</a>
		<a href="https://sub.ok-example.cn:8443/x">正常带端口</a>
	</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	obs, err := ProbeHTTPObservation(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	for _, link := range obs.Links {
		if strings.Contains(link, "under_score") {
			t.Fatalf("下划线主机不应进入 links: %v", obs.Links)
		}
	}
	if len(obs.Links) == 0 {
		t.Fatal("正常链接不应被过滤")
	}
}
