package fingerprint

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spaolacci/murmur3"
)

// 🔴 2026-09-28（EHole 对标 E1 golden 测试，docs/EHole指纹库对标-4zreco缺口盘点与补齐方案.md §五）：
// favicon mmh3 的值域必须与 dddd/EHole/FOFA 规则库同一空间 —— mmh3(StandBase64(favicon))，
// StandBase64 = 每 76 字符断行 + 无条件结尾补 \n（httpx lib/httpx/common/hashes 实现）。
// 边界语义：恰好整 76 列时输出两个换行（断行 + 尾换行），与 Python base64.encodebytes
// 在整倍数边界**不同** —— 以规则值的真实生成方（dddd/EHole 的 httpx 语义）为准；
// 非整倍数样本两侧逐字节一致。
//
// 期望值由独立 Python 基准计算：纯 Python murmur3 先以已知向量 mmh3("foo")=-156908512
// 校准，非整倍数样本同时用 base64.encodebytes 交叉验证编码。
// ⚠ 禁止把「当前实现输出」当期望值回填（会把 bug 钉死）；改算法必须携带新基准证明。

func seqBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 256)
	}
	return b
}

func TestFaviconMMH3Golden(t *testing.T) {
	samples := []struct {
		name     string
		data     []byte
		expected string // mmh3(StandBase64(data))，int32 有符号十进制
	}{
		{"tiny_png_28B_单行加尾换行", append([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, make([]byte, 20)...), "724282810"},
		{"exact_57B_整76列边界_双换行", seqBytes(57), "329978790"},
		{"exact_114B_整152列边界", seqBytes(114), "162474401"},
		{"multi_line_200B_非整倍数", seqBytes(200), "-1874651529"},
		{"real_ico_256B_ico头加序列", append([]byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x20}, seqBytes(248)...), "1902522198"},
	}
	for _, s := range samples {
		if got := faviconMMH3(s.data); got != s.expected {
			t.Errorf("%s: faviconMMH3 = %s, 期望 %s（算法空间漂移：库内 icon_hash 规则将全部失效）", s.name, got, s.expected)
		}
	}
}

// 编码形态断言：76 列断行 + 尾换行的 MIME 结构，与 httpx StandBase64 逐字节一致。
func TestStdBase64MIMEShape(t *testing.T) {
	std := []byte(stdBase64MIME(seqBytes(200)))
	if !bytes.HasSuffix(std, []byte("\n")) {
		t.Fatal("必须以换行结尾（MIME 语义，与 httpx StandBase64 一致）")
	}
	lines := bytes.Split(bytes.TrimSuffix(std, []byte("\n")), []byte("\n"))
	for i, line := range lines {
		if i < len(lines)-1 && len(line) != 76 {
			t.Fatalf("非末行长度必须恰为 76（第 %d 行 = %d）", i, len(line))
		}
	}
	// 整 76 列边界：断行 + 尾换行 = 两个换行（dddd/EHole 语义，区别于 Python encodebytes）
	boundary := []byte(stdBase64MIME(seqBytes(57)))
	if n := bytes.Count(boundary, []byte("\n")); n != 2 {
		t.Fatalf("整 76 列边界应输出两个换行（断行+尾换行），实际 %d", n)
	}
}

// 防回退：单行 base64（修复前的旧算法）必须产出不同的哈希空间。
// 旧空间基准值同样来自 Python 独立计算——两侧值域都被钉死。
func TestFaviconMMH3DiffersFromLegacySingleLine(t *testing.T) {
	data := seqBytes(200)
	h := murmur3.New32WithSeed(0)
	_, _ = h.Write([]byte(base64.StdEncoding.EncodeToString(data)))
	legacy := fmt.Sprint(int32(h.Sum32()))
	if legacy == faviconMMH3(data) {
		t.Fatal("单行 base64（旧算法）与 MIME 编码产出相同哈希——编码修复已失效或样本退化")
	}
	if legacy != "764223453" {
		t.Errorf("旧算法基准值漂移: %s（期望 764223453）", legacy)
	}
}

// 端到端链路：本地靶标 favicon → ProbeHTTPObservation 取哈希 → icon_hash 规则命中。
// 修复前该链路永不命中（扫描侧哈希与规则值域不同空间）；期望值 1902522198 为
// Python 独立基准（同 real_ico_256B 样本），非本实现自证。
func TestFaviconHashPipelineEndToEnd(t *testing.T) {
	favicon := append([]byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x20}, seqBytes(248)...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(favicon)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html><title>e2e</title><body>ok</body></html>")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	obs, err := ProbeHTTPObservation(ctx, srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if obs.IconHash != "1902522198" {
		t.Fatalf("IconHash = %s, 期望 1902522198（旧算法空间为 1213343739）", obs.IconHash)
	}

	expr, err := ParseExpression(`icon_hash="1902522198"`)
	if err != nil {
		t.Fatalf("规则解析失败: %v", err)
	}
	rules := []CompiledRule{{Name: "e2e-favicon-product", Expression: `icon_hash="1902522198"`, Expr: expr}}
	matches := MatchObservation(rules, obs)
	if len(matches) != 1 || matches[0].Product != "e2e-favicon-product" {
		t.Fatalf("icon_hash 规则未命中: %+v", matches)
	}
}
