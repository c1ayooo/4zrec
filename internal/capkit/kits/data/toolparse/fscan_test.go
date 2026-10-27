package toolparse

import (
	"strings"
	"testing"
)

// fscan 样本说明：
//   - fscan_real.txt：实测捕获的平台补丁版 fscan v2.2.1 经 socks 隧道扫描本机 http 服务的
//     stdout + result.txt 合流（模拟挂钩层把注入 -o 的结果文件并入 stdout），另按 upstream
//     v2.2.1 zh.yaml i18n 模板逐字构造弱口令/POC/未授权/MS17-010 命中行（本机无可爆破服务）。
//   - fscan_classic.txt：经典 1.x 形态（目标侧老二进制经 sliver/webshell 回传）。

// TestFscanParseReal 实测 v2.2.1 全形态：banner 特征、裸开放端口行、URL 服务识别行、
// Web 标题行、存活行、弱口令（高优先级/confirmed）、POC 命中（高优先级/tentative）、
// result.txt 三段（开放端口/服务信息/Web服务）。
func TestFscanParseReal(t *testing.T) {
	res, err := fscanParser{}.Parse(readSample(t, "fscan_real.txt"), "", "raw://fscan_real")
	if err != nil {
		t.Fatalf("Parse 不应报错: %v", err)
	}
	if !res.OK {
		t.Fatalf("实测样本应可解析: %s", res.Err)
	}
	wantFields := map[string]int{
		"hosts":          4, // 127.0.0.1 + 10.10.10.5/6/7
		"weak_passwords": 2,
		"vulns":          4,
	}
	for k, want := range wantFields {
		if got := res.Fields[k]; got != want {
			t.Errorf("Fields[%s] = %v, want %d", k, got, want)
		}
	}
	if got := res.Fields["open_ports"]; got.(int) < 2 {
		t.Errorf("open_ports = %v, 应 >= 2（18097/18099）", got)
	}
	if got := res.Fields["webs"]; got.(int) < 2 {
		t.Errorf("webs = %v, 应 >= 2（18097 code:200 / 18099 code:404）", got)
	}

	keys := map[string]FactCandidate{}
	for _, f := range res.Facts {
		keys[f.FactKey] = f
		if err := ValidateFactKey(f.FactKey); err != nil {
			t.Errorf("事实键 %q 不合法: %v", f.FactKey, err)
		}
	}
	// 弱口令（高优先级事实，confirmed：登录成功实证）
	if f, ok := keys["auth/10.10.10.5:3306-mysql-root"]; !ok {
		t.Error("缺弱口令事实 auth/10.10.10.5:3306-mysql-root")
	} else if f.Confidence != "confirmed" {
		t.Errorf("弱口令应为 confirmed（登录成功实证）, got %s", f.Confidence)
	}
	if _, ok := keys["auth/10.10.10.5:22-ssh-root"]; !ok {
		t.Error("缺弱口令事实 auth/10.10.10.5:22-ssh-root")
	}
	// POC/漏洞命中（高优先级事实，tentative 等复核）
	for _, k := range []string{
		"finding/poc-yaml-backup-file-10.10.10.5-8080",
		"finding/redis-unauthorized-10.10.10.6-6379",
		"finding/ms17-010-10.10.10.7",
	} {
		f, ok := keys[k]
		if !ok {
			t.Errorf("缺漏洞命中事实 %s", k)
			continue
		}
		if f.Confidence != "tentative" {
			t.Errorf("%s 应为 tentative（与 nuclei 同口径）, got %s", k, f.Confidence)
		}
	}
	// 存活与端口/服务
	if f, ok := keys["target/127.0.0.1"]; !ok || f.Confidence != "confirmed" {
		t.Error("缺 target/127.0.0.1（confirmed）")
	}
	if _, ok := keys["infra/127.0.0.1:18097-http"]; !ok {
		t.Error("缺 infra/127.0.0.1:18097-http（URL 服务识别行）")
	}
	// result.txt 开放端口段的裸行不应产生 -unknown 重复（服务行已升级）
	if _, ok := keys["infra/127.0.0.1:18097-unknown"]; ok {
		t.Error("18097 已有 http 服务名，不应残留 -unknown 事实")
	}
	// Web 标题进 target 正文（含空格标题不被截断）
	var target127 FactCandidate
	for _, f := range res.Facts {
		if f.FactKey == "target/127.0.0.1" {
			target127 = f
		}
	}
	if !strings.Contains(target127.Body, "Directory listing for /") {
		t.Errorf("target/127.0.0.1 正文应含 Web 标题（含空格完整）: %q", target127.Body)
	}
	if !strings.Contains(target127.Body, "状态码: 200") {
		t.Errorf("target/127.0.0.1 正文应含状态码 200: %q", target127.Body)
	}
}

// TestFscanParseClassic 经典 1.x 形态（任务口径的五种提取目标）。
func TestFscanParseClassic(t *testing.T) {
	res, err := fscanParser{}.Parse(readSample(t, "fscan_classic.txt"), "", "")
	if err != nil {
		t.Fatalf("Parse 不应报错: %v", err)
	}
	if !res.OK {
		t.Fatalf("经典样本应可解析: %s", res.Err)
	}
	keys := map[string]FactCandidate{}
	for _, f := range res.Facts {
		keys[f.FactKey] = f
	}
	// 存活（`[+] ip` + `[*] 存活主机数` 特征段）
	for _, k := range []string{"target/10.11.11.5", "target/10.11.11.8"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("缺存活事实 %s", k)
		}
	}
	// `ip:port open` + `[+] ip:port 服务`（unknown → mysql 升级）
	if _, ok := keys["infra/10.11.11.5:3306-mysql"]; !ok {
		t.Error("缺 infra/10.11.11.5:3306-mysql（open 行 + 服务行升级）")
	}
	if _, ok := keys["infra/10.11.11.8:445-unknown"]; !ok {
		t.Error("缺 infra/10.11.11.8:445-unknown（纯 open 行）")
	}
	// `http://ip:port [200] 标题`
	f, ok := keys["target/10.11.11.8"]
	if !ok || !strings.Contains(f.Body, "内部管理后台") || !strings.Contains(f.Body, "状态码: 200") {
		t.Errorf("缺 Web 标题事实/正文: %+v", f)
	}
	// `[+] ip:port user pass`（经典弱口令）
	if _, ok := keys["auth/10.11.11.5:3306-unknown-root"]; !ok {
		t.Error("缺经典弱口令 auth/10.11.11.5:3306-unknown-root")
	}
	// `[!] ip 漏洞名`（中文名 slug 兜底 vuln）
	if _, ok := keys["finding/vuln-10.11.11.8"]; !ok {
		t.Error("缺经典漏洞命中 finding/vuln-10.11.11.8")
	}
}

// TestFscanRejectsNonFscan 非 fscan 文本零误报（fail-closed）。
func TestFscanRejectsNonFscan(t *testing.T) {
	cases := []string{
		malformed,
		"Starting Nmap 7.94 ( https://nmap.org )\nNmap scan report for 10.0.0.5\nPORT     STATE SERVICE\n80/tcp   open  http\n",
		"[+] 10.0.0.5:8080 open\nrandom tool output without fscan banner\n",
		"Directory busting results\n200 GET 12l 34w /admin\n",
		strings.Repeat("some log line\n", 50),
	}
	for i, in := range cases {
		res, err := fscanParser{}.Parse(in, "", "")
		if err != nil {
			t.Fatalf("case %d Parse 不应报错: %v", i, err)
		}
		if res.OK {
			t.Errorf("case %d 非 fscan 输入应 OK=false（零误报）", i)
		}
		if len(res.Facts) != 0 {
			t.Errorf("case %d 拒绝时不得产事实, got %d", i, len(res.Facts))
		}
	}
}

// TestFscanTruncatedSafe 截断输入安全（不 panic、产出事实键全部合法）。
func TestFscanTruncatedSafe(t *testing.T) {
	sample := readSample(t, "fscan_real.txt")
	for _, in := range []string{truncateHalf(sample), sample[:len(sample)/3], sample[10:]} {
		res, err := fscanParser{}.Parse(in, "", "")
		if err != nil {
			t.Fatalf("截断输入不应报错: %v", err)
		}
		for _, f := range res.Facts {
			if err := ValidateFactKey(f.FactKey); err != nil {
				t.Errorf("截断产出非法事实键 %q: %v", f.FactKey, err)
			}
		}
	}
}

// TestFscanRegistryAndInjection 注册表 + 注入表 + 占位符解析。
func TestFscanRegistryAndInjection(t *testing.T) {
	if Lookup("fscan", []string{"-h", "10.0.0.0/24"}) == nil {
		t.Fatal("Lookup(fscan) 应命中（文本形态无标志门禁）")
	}
	inj := InjectionFor("fscan")
	if inj == nil {
		t.Fatal("fscan 应在 injections 表（C 档落文件模式）")
	}
	args := inj.ResolveArgs("/tmp/xx")
	if len(args) != 2 || args[0] != "-o" || args[1] != "/tmp/xx/result.txt" {
		t.Errorf("注入参数解析错误: %v", args)
	}
	if got := inj.ResolveResultPath("/tmp/xx"); got != "/tmp/xx/result.txt" {
		t.Errorf("结果文件路径错误: %s", got)
	}
	// 注册完备性：fscan 在 RegisteredTools 与 InjectedTools 双侧
	found := false
	for _, tool := range RegisteredTools() {
		if tool == "fscan" {
			found = true
		}
	}
	if !found {
		t.Error("RegisteredTools 缺 fscan")
	}
	found = false
	for _, tool := range InjectedTools() {
		if tool == "fscan" {
			found = true
		}
	}
	if !found {
		t.Error("InjectedTools 缺 fscan")
	}
}
