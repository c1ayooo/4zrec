package toolparse

import (
	"strings"
	"testing"
)

// ── P0-a2 解析器四类用例（正常/截断/空/畸形）──

func TestNmapParseReal(t *testing.T) {
	p := nmapParser{}
	if !p.Match("nmap", []string{"-oX", "-"}) {
		t.Fatal("Match 失败")
	}
	res, err := p.Parse(readSample(t, "nmap_real.xml"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	// 真实样本：127.0.0.1:18083 open（无服务版本 → tentative）
	if res.Fields["hosts"] != 1 {
		t.Errorf("hosts = %v, want 1", res.Fields["hosts"])
	}
	var hasTarget, hasInfra bool
	for _, f := range res.Facts {
		if f.FactKey == "target/127.0.0.1" && f.Confidence == "confirmed" {
			hasTarget = true
		}
		if f.FactKey == "infra/127.0.0.1:18083-unknown" && f.Confidence == "tentative" {
			hasInfra = true
		}
		if len(f.Links) == 1 && f.Links[0].Type == "contains" {
			if f.Links[0].From != "target/127.0.0.1" {
				t.Errorf("nmap 边 from 异常: %+v", f.Links)
			}
		}
	}
	if !hasTarget || !hasInfra {
		t.Errorf("nmap 事实缺失 target=%v infra=%v", hasTarget, hasInfra)
	}
}

func TestNmapParseMalformed(t *testing.T) {
	p := nmapParser{}
	// 人类可读 nmap 输出（非 XML）→ fail-closed
	res, _ := p.Parse("Starting Nmap 7.94 ( https://nmap.org )\nNmap scan report for 127.0.0.1\nPORT STATE SERVICE\n22/tcp closed ssh\n", "", "")
	if res.OK {
		t.Error("非 XML 输入应 OK=false（fail-closed）")
	}
	if len(res.Facts) != 0 {
		t.Error("fail-closed 时不应产出事实")
	}
}

func TestNmapParseEmpty(t *testing.T) {
	p := nmapParser{}
	res, _ := p.Parse("", "", "")
	if !res.OK || len(res.Facts) != 0 {
		t.Errorf("空输入应 OK=true 且零事实, got ok=%v", res.OK)
	}
}

func TestDirsearchParseReal(t *testing.T) {
	p := dirsearchParser{}
	if !p.Match("dirsearch", []string{"-O", "json", "-o", "/tmp/x.json"}) {
		t.Fatal("Match 失败")
	}
	res, err := p.Parse(readSample(t, "dirsearch_real.json"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["hits"] != 3 {
		t.Errorf("hits = %v, want 3", res.Fields["hits"])
	}
	var hasFinding bool
	for _, f := range res.Facts {
		if f.FactKey == "finding/127.0.0.1-search.php" && f.Confidence == "tentative" {
			hasFinding = true
		}
	}
	if !hasFinding {
		t.Error("缺少 finding/127.0.0.1-search.php")
	}
}

func TestDirsearchParseTruncatedEmptyMalformed(t *testing.T) {
	p := dirsearchParser{}
	// 整段 JSON 截断必然解析失败 → fail-closed（OK=false、零事实）
	trunc, _ := p.Parse(truncateHalf(readSample(t, "dirsearch_real.json")), "", "")
	if trunc.OK {
		t.Error("截断整段 JSON 应 OK=false（fail-closed）")
	}
	if len(trunc.Facts) != 0 {
		t.Error("fail-closed 时不应产出事实")
	}
	empty, _ := p.Parse("", "", "")
	if !empty.OK || len(empty.Facts) != 0 {
		t.Error("空输入应零事实")
	}
	mal, _ := p.Parse("not json at all", "", "")
	if mal.OK {
		t.Error("畸形输入应 OK=false（fail-closed）")
	}
}

func TestWhatwebParseReal(t *testing.T) {
	p := whatwebParser{}
	if !p.Match("whatweb", []string{"--log-xml=/tmp/x.xml"}) {
		t.Fatal("Match 失败")
	}
	res, err := p.Parse(readSample(t, "whatweb_real.xml"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["fingerprints"] != 3 {
		t.Errorf("fingerprints = %v, want 3", res.Fields["fingerprints"])
	}
	var hasInfra bool
	for _, f := range res.Facts {
		if f.FactKey == "infra/127.0.0.1-python" && f.Confidence == "tentative" {
			hasInfra = true
		}
		if len(f.Links) == 1 && f.Links[0].Type != "part_of" {
			t.Errorf("whatweb 边类型异常: %+v", f.Links)
		}
	}
	if !hasInfra {
		t.Error("缺少 infra/127.0.0.1-python")
	}
}

func TestWhatwebParseMalformed(t *testing.T) {
	p := whatwebParser{}
	res, _ := p.Parse("<html>not target log</html>", "", "")
	if res.OK {
		t.Error("非 whatweb XML 应 OK=false")
	}
}

func TestWafw00fParseReal(t *testing.T) {
	p := wafw00fParser{}
	if !p.Match("wafw00f", []string{"-f", "json", "-o", "/tmp/x.json"}) {
		t.Fatal("Match 失败")
	}
	res, err := p.Parse(readSample(t, "wafw00f_real.json"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	// 真实样本：detected=false（no WAF）→ 零事实但 OK
	if !res.OK {
		t.Error("no-waf 样本应 OK=true")
	}
	if len(res.Facts) != 0 || res.Fields["no_waf"] != 1 {
		t.Errorf("no-waf 样本应 0 事实/no_waf=1, got facts=%d", len(res.Facts))
	}
}

func TestWafw00fParseDetected(t *testing.T) {
	p := wafw00fParser{}
	sample := `[
	  {"url": "https://example.com/", "detected": true, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}
	]`
	res, err := p.Parse(sample, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["waf_detected"] != 1 {
		t.Errorf("waf_detected = %v, want 1", res.Fields["waf_detected"])
	}
	f := res.Facts[0]
	if f.FactKey != "infra/example.com-waf-cloudflare" || f.Confidence != "tentative" {
		t.Errorf("waf 事实异常: %+v", f)
	}
}

func TestNiktoParseReal(t *testing.T) {
	p := niktoParser{}
	if !p.Match("nikto", []string{"-Format", "xml", "-o", "/tmp/x.xml"}) {
		t.Fatal("Match 失败")
	}
	res, err := p.Parse(readSample(t, "nikto_real.xml"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["items"] != 2 {
		t.Errorf("items = %v, want 2", res.Fields["items"])
	}
	var hasFinding bool
	for _, f := range res.Facts {
		if f.Confidence != "tentative" || f.Category != "finding" {
			t.Errorf("nikto 事实应 finding/tentative: %+v", f)
		}
		if len(f.Links) == 1 && f.Links[0].Type != "discovered_on" {
			t.Errorf("nikto 边异常: %+v", f.Links)
		}
		if strings.HasPrefix(f.FactKey, "finding/127.0.0.1-") {
			hasFinding = true
		}
	}
	if !hasFinding {
		t.Error("缺少 nikto finding 事实")
	}
}

func TestArjunParseReal(t *testing.T) {
	p := arjunParser{}
	if !p.Match("arjun", []string{"-oJ", "/tmp/x.json"}) {
		t.Fatal("Match 失败")
	}
	res, err := p.Parse("TARGET: http://127.0.0.1:18083/search.php?id=1\n"+readSample(t, "arjun_real.json"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["param_count"] != 3 {
		t.Errorf("param_count = %v, want 3", res.Fields["param_count"])
	}
	if len(res.Facts) != 1 {
		t.Fatalf("facts = %d, want 1", len(res.Facts))
	}
	f := res.Facts[0]
	if f.FactKey != "infra/127.0.0.1-params" || f.Confidence != "tentative" {
		t.Errorf("arjun 事实异常: %+v", f)
	}
}

func TestArjunParseNoTarget(t *testing.T) {
	p := arjunParser{}
	// 无 TARGET 前缀（非 TargetAware 通道）：只报字段不落键（fail-closed）
	res, _ := p.Parse(readSample(t, "arjun_real.json"), "", "")
	if !res.OK {
		t.Error("无 target 应 OK=true")
	}
	if len(res.Facts) != 0 {
		t.Errorf("无 target 不应产出事实, got %d", len(res.Facts))
	}
}

func TestDalfoxParseReal(t *testing.T) {
	p := dalfoxParser{}
	if !p.Match("dalfox", []string{"--format", "jsonl", "-o", "/tmp/x.jsonl"}) {
		t.Fatal("Match 失败")
	}
	res, err := p.Parse(readSample(t, "dalfox_real.jsonl"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["issues"] != 1 {
		t.Errorf("issues = %v, want 1", res.Fields["issues"])
	}
	f := res.Facts[0]
	if f.FactKey != "finding/xss-127.0.0.1-q" || f.Confidence != "tentative" {
		t.Errorf("dalfox 事实异常: %+v", f)
	}
	if len(f.Links) != 1 || f.Links[0].Type != "exploits" {
		t.Errorf("dalfox 边异常: %+v", f.Links)
	}
}

func TestDalfoxParseEmptyMalformed(t *testing.T) {
	p := dalfoxParser{}
	empty, _ := p.Parse("", "", "")
	if !empty.OK || len(empty.Facts) != 0 {
		t.Error("空输入应零事实")
	}
	mal, _ := p.Parse("garbage line\nnot-json", "", "")
	if len(mal.Facts) != 0 {
		t.Error("畸形输入应零事实")
	}
}

func TestWpscanParseReal(t *testing.T) {
	p := wpscanParser{}
	if !p.Match("wpscan", []string{"-f", "json", "-o", "/tmp/x.json"}) {
		t.Fatal("Match 失败")
	}
	res, err := p.Parse("TARGET: http://127.0.0.1:18083/\n"+readSample(t, "wpscan_real.json"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	var hasVer, hasVuln bool
	for _, f := range res.Facts {
		if f.FactKey == "infra/127.0.0.1-wordpress-5.9.2" && f.Confidence == "confirmed" {
			hasVer = true
		}
		if f.FactKey == "finding/contact-form-7-127.0.0.1" && f.Confidence == "tentative" {
			hasVuln = true
		}
	}
	if !hasVer || !hasVuln {
		t.Errorf("wpscan 事实缺失 ver=%v vuln=%v", hasVer, hasVuln)
	}
}

func TestSqlmapParseReal(t *testing.T) {
	p := sqlmapParser{}
	if !p.Match("sqlmap", []string{"--batch", "--output-dir", "/tmp/x"}) {
		t.Fatal("Match 失败")
	}
	res, err := p.Parse("TARGET: http://127.0.0.1:18083/page.php?id=1\n"+readSample(t, "sqlmap_real.txt"), "", "/tmp/raw")
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["injection_points"] != 1 {
		t.Errorf("injection_points = %v, want 1", res.Fields["injection_points"])
	}
	if res.Fields["dbms"] != "MySQL" {
		t.Errorf("dbms = %v, want MySQL", res.Fields["dbms"])
	}
	f := res.Facts[0]
	if f.FactKey != "finding/sqli-127.0.0.1-id" || f.Confidence != "tentative" {
		t.Errorf("sqlmap 事实异常: %+v", f)
	}
	if len(f.Links) != 1 || f.Links[0].Type != "exploits" {
		t.Errorf("sqlmap 边异常: %+v", f.Links)
	}
}

func TestSqlmapParseNoHit(t *testing.T) {
	p := sqlmapParser{}
	res, _ := p.Parse("TARGET: http://x/\n[03:21:04] [INFO] testing connection to the target URL\n", "", "")
	if !res.OK || len(res.Facts) != 0 {
		t.Errorf("无命中应 OK=true 零事实, got ok=%v facts=%d", res.OK, len(res.Facts))
	}
}

func TestAllParsersRegistered(t *testing.T) {
	// 文档 §4.4 A/B/C 三档 13 个工具全注册（nuclei 走 vulnverify 不在注入表但在解析器表）
	parsers := RegisteredTools()
	for _, want := range []string{"httpx", "ffuf", "katana", "nuclei", "nmap", "sqlmap", "dirsearch", "dalfox", "arjun", "wpscan", "wafw00f", "nikto", "whatweb"} {
		found := false
		for _, got := range parsers {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("解析器 %s 未注册", want)
		}
	}
}
