package toolparse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readSample 读取 testdata 样本。
func readSample(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("读取 testdata %s 失败: %v", name, err)
	}
	return string(b)
}

// truncateHalf 截断到一半长度（截断输入用例）。
func truncateHalf(s string) string {
	if len(s) <= 1 {
		return s
	}
	return s[:len(s)/2]
}

// malformed 非预期格式输入。
const malformed = "random human readable output\nwith no json at all\n--help output--"

func TestRegistryRoundTrip(t *testing.T) {
	// init() 已注册全部 13 个解析器；此处幂等覆盖不影响注册表。
	Register(httpxParser{})
	Register(ffufParser{})
	Register(katanaParser{})
	Register(nucleiParser{})
	if Lookup("httpx", []string{"-json", "-silent"}) == nil {
		t.Fatal("httpx 带 -json 应命中解析器")
	}
	if Lookup("httpx", []string{"-u", "example.com"}) != nil {
		t.Fatal("httpx 不带 -json 不应命中（保持现状）")
	}
	if Lookup("exec", []string{}) != nil {
		t.Fatal("未注册工具不应命中")
	}
	if Lookup("nmap", []string{"-oX", "-"}) == nil {
		t.Fatal("nmap 带 -oX 应命中解析器")
	}
}

func TestSluggify(t *testing.T) {
	cases := []struct{ in, want string }{
		{"www.woniuxy.com", "www.woniuxy.com"},
		{"https://www.woniuxy.com", "www.woniuxy.com"},
		{"http://10.0.0.5:8080/path", "10.0.0.5:8080"},
		{"Alibaba Cloud CDN", "alibaba-cloud-cdn"},
		{" WordPress_5.9 ", "wordpress-5.9"},
	}
	for _, c := range cases {
		if got := Sluggify(c.in); got != c.want {
			t.Errorf("Sluggify(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateFactKey(t *testing.T) {
	valid := []string{
		"target/www.woniuxy.com",
		"infra/10.0.0.5:80-nginx",
		"finding/tech-detect-www.woniuxy.com",
	}
	for _, k := range valid {
		if err := ValidateFactKey(k); err != nil {
			t.Errorf("ValidateFactKey(%q) 不应失败: %v", k, err)
		}
	}
	invalid := []string{"", "foo/bar", "finding", "custom/whatever", "finding/"}
	for _, k := range invalid {
		if err := ValidateFactKey(k); err == nil {
			t.Errorf("ValidateFactKey(%q) 应失败", k)
		}
	}
}

func TestInjectionTable(t *testing.T) {
	// 注入表工具与解析器注册表一一对应（A/B/C 三档，见档案 §4.4）
	parsed := map[string]bool{}
	for _, t := range RegisteredTools() {
		parsed[t] = true
	}
	for _, inj := range injections {
		if !parsed[inj.Tool] {
			t.Errorf("注入表含 %s 但无对应解析器（脱节）", inj.Tool)
		}
	}
}

func TestInjectionResolve(t *testing.T) {
	inj := InjectionFor("httpx")
	if inj == nil {
		t.Fatal("httpx 应有注入描述")
	}
	args := inj.ResolveArgs("/tmp/x/tp")
	if len(args) != 2 || args[0] != "-json" || args[1] != "-silent" {
		t.Errorf("httpx 注入 = %v", args)
	}
	// 无落盘文件模式 → ResolveResultPath 为空
	if got := inj.ResolveResultPath("/tmp/x/tp"); got != "" {
		t.Errorf("无 ResultFileRel 时应返回空, got %q", got)
	}
	// 落盘模式占位符替换
	fileInj := &Injection{Tool: "dirsearch", Args: []string{"-o", "<TMPDIR>/result.json"}, ResultFileRel: "result.json"}
	fileArgs := fileInj.ResolveArgs("/tmp/x/tp")
	if fileArgs[0] != "-o" || fileArgs[1] != "/tmp/x/tp/result.json" {
		t.Errorf("落盘模式替换失败: %v", fileArgs)
	}
	if got := fileInj.ResolveResultPath("/tmp/x/tp"); got != "/tmp/x/tp/result.json" {
		t.Errorf("ResolveResultPath = %q", got)
	}
}

// ── 四类输入用例（正常/截断/空/畸形），各解析器逐一验证 ──

func TestHttpxParseReal(t *testing.T) {
	p := httpxParser{}
	if !p.Match("httpx", []string{"-json", "-silent"}) {
		t.Fatal("Match 失败")
	}
	res, err := p.Parse(readSample(t, "httpx_real.jsonl"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("正常样本应 OK=true: %s", res.Err)
	}
	// 两条真实行：1 个 target（www.woniuxy.com）+ 4 个 tech（Tengine/Alibaba Cloud CDN/Clipboard.js/jQuery）
	if res.Fields["hosts"] != 1 {
		t.Errorf("hosts = %v, want 1", res.Fields["hosts"])
	}
	if res.Fields["infra_tech"] != 4 {
		t.Errorf("infra_tech = %v, want 4", res.Fields["infra_tech"])
	}
	var hasTarget, hasInfra bool
	for _, f := range res.Facts {
		if f.FactKey == "target/www.woniuxy.com" && f.Confidence == "confirmed" {
			hasTarget = true
		}
		if f.FactKey == "infra/www.woniuxy.com-tengine" && f.Confidence == "tentative" {
			hasInfra = true
		}
		if err := ValidateFactKey(f.FactKey); err != nil {
			t.Errorf("非法 fact_key %q: %v", f.FactKey, err)
		}
	}
	if !hasTarget {
		t.Error("缺少 target/www.woniuxy.com")
	}
	if !hasInfra {
		t.Error("缺少 infra/www.woniuxy.com-tengine")
	}
}

func TestHttpxParseFailedRows(t *testing.T) {
	p := httpxParser{}
	res, err := p.Parse(readSample(t, "httpx_failed.jsonl"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatal("failed 行不应判整体失败（只是无事实）")
	}
	if len(res.Facts) != 0 {
		t.Errorf("failed=true 行不应产出事实, got %d", len(res.Facts))
	}
}

func TestHttpxParseTruncated(t *testing.T) {
	p := httpxParser{}
	res, err := p.Parse(truncateHalf(readSample(t, "httpx_real.jsonl")), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("截断输入应仍 OK=true（可解析部分有效）: %s", res.Err)
	}
	if len(res.Facts) == 0 {
		t.Error("截断样本应至少解析出部分事实")
	}
}

func TestHttpxParseEmpty(t *testing.T) {
	p := httpxParser{}
	res, err := p.Parse("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || len(res.Facts) != 0 {
		t.Errorf("空输入应 OK=true 且零事实, got ok=%v facts=%d", res.OK, len(res.Facts))
	}
}

func TestHttpxParseMalformed(t *testing.T) {
	p := httpxParser{}
	res, err := p.Parse(malformed, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatal("非 JSON 输入应判为可解析但零事实（不是整体失败）")
	}
	if len(res.Facts) != 0 {
		t.Errorf("畸形输入不应产出事实, got %d", len(res.Facts))
	}
}

func TestFfufParseReal(t *testing.T) {
	p := ffufParser{}
	res, err := p.Parse(readSample(t, "ffuf_real.jsonl"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["hits"] != 3 {
		t.Errorf("hits = %v, want 3", res.Fields["hits"])
	}
	var hasFinding bool
	for _, f := range res.Facts {
		if f.Category != "finding" || f.Confidence != "tentative" {
			t.Errorf("ffuf 事实应 finding/tentative, got %s/%s", f.Category, f.Confidence)
		}
		if f.FactKey == "finding/127.0.0.1-index.html" {
			hasFinding = true
		}
		if len(f.Links) != 1 || f.Links[0].Type != "discovered_on" || f.Links[0].From != "target/127.0.0.1" {
			t.Errorf("ffuf 边应为 discovered_on→target/<host>, got %+v", f.Links)
		}
	}
	if !hasFinding {
		t.Error("缺少 finding/127.0.0.1-index.html")
	}
}

func TestFfufParseTruncatedEmptyMalformed(t *testing.T) {
	p := ffufParser{}
	trunc, _ := p.Parse(truncateHalf(readSample(t, "ffuf_real.jsonl")), "", "")
	if !trunc.OK {
		t.Error("截断应 OK=true")
	}
	empty, _ := p.Parse("", "", "")
	if !empty.OK || len(empty.Facts) != 0 {
		t.Error("空输入应零事实")
	}
	mal, _ := p.Parse(malformed, "", "")
	if len(mal.Facts) != 0 {
		t.Error("畸形输入应零事实")
	}
}

func TestKatanaParseReal(t *testing.T) {
	p := katanaParser{}
	res, err := p.Parse(readSample(t, "katana_real.jsonl"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["urls"] != 2 || res.Fields["hosts"] != 1 {
		t.Errorf("urls/hosts = %v/%v, want 2/1", res.Fields["urls"], res.Fields["hosts"])
	}
	if len(res.Facts) != 1 {
		t.Fatalf("应只有 1 个 target 事实（body 累积）, got %d", len(res.Facts))
	}
	f := res.Facts[0]
	if f.FactKey != "target/127.0.0.1" || f.Confidence != "confirmed" {
		t.Errorf("katana target 事实异常: %+v", f)
	}
	if !strings.Contains(f.Body, "Crawled URLs:") {
		t.Error("body 应累积爬取 URL 清单")
	}
}

func TestKatanaParseTruncatedEmptyMalformed(t *testing.T) {
	p := katanaParser{}
	trunc, _ := p.Parse(truncateHalf(readSample(t, "katana_real.jsonl")), "", "")
	if !trunc.OK {
		t.Error("截断应 OK=true")
	}
	empty, _ := p.Parse("", "", "")
	if !empty.OK || len(empty.Facts) != 0 {
		t.Error("空输入应零事实")
	}
	mal, _ := p.Parse(malformed, "", "")
	if len(mal.Facts) != 0 {
		t.Error("畸形输入应零事实")
	}
}

func TestNucleiParseReal(t *testing.T) {
	p := nucleiParser{}
	res, err := p.Parse(readSample(t, "nuclei_real.jsonl"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	// matcher-status=false 的行（tech-detect 第二条）应被过滤
	if res.Fields["matches"] != 1 {
		t.Errorf("matches = %v, want 1（matcher-status=false 过滤）", res.Fields["matches"])
	}
	if len(res.Facts) != 1 {
		t.Fatalf("facts = %d, want 1", len(res.Facts))
	}
	f := res.Facts[0]
	if f.Category != "finding" || f.Confidence != "tentative" {
		t.Errorf("nuclei 事实应 finding/tentative, got %s/%s", f.Category, f.Confidence)
	}
	if !strings.HasPrefix(f.FactKey, "finding/http-missing-security-headers-www.woniuxy.com") {
		t.Errorf("fact_key = %q 不合规", f.FactKey)
	}
}

func TestNucleiParseEmptyMalformed(t *testing.T) {
	p := nucleiParser{}
	empty, _ := p.Parse("", "", "")
	if !empty.OK || len(empty.Facts) != 0 {
		t.Error("空输入应零事实")
	}
	mal, _ := p.Parse(malformed, "", "")
	if len(mal.Facts) != 0 {
		t.Error("畸形输入应零事实")
	}
}
