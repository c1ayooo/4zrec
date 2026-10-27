package toolparse

import (
	"strings"
	"testing"
)

// hashcat 样本说明：
//   - hashcat_real.txt：完整运行输出形态（banner + 设备行 + 运行期破解行 + 状态面
//     Status/Recovered/Candidates + 挂钩层并入的 potfile 破解行合流），覆盖
//     Kerberoast(13100)/AS-REP(18200)/NTLM(1000)/NetNTLMv2(5600) 四族。
//   - hashcat_show.txt：`--show` 纯破解行输出（无 banner/状态面，靠 ≥1 行合法
//     hash:plain 形态过门禁），含 pwdump 档案行与 $NT$ 前缀形态。

// TestHashcatParseReal 实测全形态：Kerberos user$realm/user@realm 解析、NTLM、NetNTLMv2、
// 状态面摘要（confirmed 高优先级事实：破出明文即哈希验证实证）。
func TestHashcatParseReal(t *testing.T) {
	res, err := hashcatParser{}.Parse(readSample(t, "hashcat_real.txt"), "", "raw://hashcat_real")
	if err != nil {
		t.Fatalf("Parse 不应报错: %v", err)
	}
	if !res.OK {
		t.Fatalf("实测样本应可解析: %s", res.Err)
	}
	wantFields := map[string]any{
		"cracked":    5,
		"kerberos":   3,
		"status":     "Exhausted",
		"recovered":  "5/5 (100.00%)",
		"candidates": "ServicePass2023!",
	}
	for k, want := range wantFields {
		if got := res.Fields[k]; got != want {
			t.Errorf("Fields[%s] = %v, want %v", k, got, want)
		}
	}

	keys := map[string]FactCandidate{}
	for _, f := range res.Facts {
		keys[f.FactKey] = f
		if err := ValidateFactKey(f.FactKey); err != nil {
			t.Errorf("事实键 %q 不合法: %v", f.FactKey, err)
		}
	}
	// Kerberoast（13100）：$krb5tgs$ 内嵌 *user$realm 解析
	f, ok := keys["auth/sqlservice-corp.local"]
	if !ok {
		t.Fatal("缺 Kerberoast 事实 auth/sqlservice-corp.local")
	}
	if f.Confidence != "confirmed" {
		t.Errorf("Kerberoast 应为 confirmed（破解实证）, got %s", f.Confidence)
	}
	if !strings.Contains(f.Summary, "Kerberoast TGS-REP(13100)") || !strings.Contains(f.Summary, "sqlservice@CORP.LOCAL") {
		t.Errorf("Kerberoast 摘要应含类型与 user@realm: %q", f.Summary)
	}
	if !strings.Contains(f.Body, "ServicePass2023!") {
		t.Errorf("Kerberoast 正文应含明文口令: %q", f.Body)
	}
	// @ 不在 fact_key 字符集，键转 -、user@realm 保留在摘要/正文
	if _, ok := keys["auth/webadmin-corp.local"]; !ok {
		t.Error("缺 Kerberoast 事实 auth/webadmin-corp.local")
	}
	// AS-REP（18200）：$krb5asrep$ 内嵌 user@realm 解析
	if f, ok := keys["auth/asrepuser-corp.local"]; !ok || !strings.Contains(f.Summary, "AS-REP Roast(18200)") {
		t.Errorf("缺/错 AS-REP 事实 auth/asrepuser-corp.local: %+v", f)
	}
	// 裸 NTLM hex32（无账号信息 → auth/ntlm-<哈希前缀>）
	if f, ok := keys["auth/ntlm-8846f7eaee8f"]; !ok || !strings.Contains(f.Body, "password") {
		t.Errorf("缺/错裸 NTLM 事实 auth/ntlm-8846f7eaee8f: %+v", f)
	}
	// NetNTLMv2（5600）：user::domain:challenge:proof:blob:plain
	if f, ok := keys["auth/jjones-corp"]; !ok || !strings.Contains(f.Summary, "NetNTLMv2(5600)") {
		t.Errorf("缺/错 NetNTLMv2 事实 auth/jjones-corp: %+v", f)
	}
	if len(res.Facts) != 5 {
		t.Errorf("事实数 = %d, want 5（五族各一条）", len(res.Facts))
	}
}

// TestHashcatParseShow --show 纯破解行输出（无 banner，门禁靠合法 hash:plain 形态）：
// pwdump 档案行解出账号、$NT$ 前缀与裸 hex32。
func TestHashcatParseShow(t *testing.T) {
	res, err := hashcatParser{}.Parse(readSample(t, "hashcat_show.txt"), "", "")
	if err != nil {
		t.Fatalf("Parse 不应报错: %v", err)
	}
	if !res.OK {
		t.Fatalf("--show 样本应可解析（合法 hash:plain 过门禁）: %s", res.Err)
	}
	if got := res.Fields["cracked"]; got != 3 {
		t.Errorf("cracked = %v, want 3", got)
	}
	keys := map[string]FactCandidate{}
	for _, f := range res.Facts {
		keys[f.FactKey] = f
		if err := ValidateFactKey(f.FactKey); err != nil {
			t.Errorf("事实键 %q 不合法: %v", f.FactKey, err)
		}
	}
	// pwdump 档案行：user:rid:lm:nt:::plain → 带账号的 NTLM 事实
	if f, ok := keys["auth/administrator-ntlm"]; !ok || !strings.Contains(f.Body, "Passw0rd!") {
		t.Errorf("缺/错 pwdump NTLM 事实 auth/administrator-ntlm: %+v", f)
	}
	// $NT$ 前缀（john 兼容形态）→ auth/ntlm-<哈希前缀>
	if _, ok := keys["auth/ntlm-32ed87bdb5fd"]; !ok {
		t.Error("缺 $NT$ 事实 auth/ntlm-32ed87bdb5fd")
	}
	if _, ok := keys["auth/ntlm-5f4dcc3b5aa7"]; !ok {
		t.Error("缺裸 hex32 事实 auth/ntlm-5f4dcc3b5aa7")
	}
}

// TestHashcatRejectsNonHashcat 非 hashcat 文本零误报（fail-closed）：
// 普通命令输出的冒号行（HTTP 头/时间日志/ passwd 档案行）不得因冒号形态误判。
func TestHashcatRejectsNonHashcat(t *testing.T) {
	cases := []string{
		malformed,
		"Starting Nmap 7.94 ( https://nmap.org )\nNmap scan report for 10.0.0.5\nPORT     STATE SERVICE\n80/tcp   open  http\n",
		"Host: example.com\nContent-Type: text/html\nDate: Tue, 29 Sep 2026 10:00:00 GMT\n",
		"time: 12:30:59\nduration: 5s\nelapsed: 1m2s\n",
		"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
		readSample(t, "fscan_real.txt"), // 跨工具：fscan 输出不得误判
		readSample(t, "john_show.txt"),  // 跨工具：john --show 输出不得误判（pot 破解行两工具同构，见 TestJohnParseRun）
		strings.Repeat("some: log: line\n", 50),
	}
	for i, in := range cases {
		res, err := hashcatParser{}.Parse(in, "", "")
		if err != nil {
			t.Fatalf("case %d Parse 不应报错: %v", i, err)
		}
		if res.OK {
			t.Errorf("case %d 非 hashcat 输入应 OK=false（零误报）", i)
		}
		if len(res.Facts) != 0 {
			t.Errorf("case %d 拒绝时不得产事实, got %d", i, len(res.Facts))
		}
	}
}

// TestHashcatTruncatedSafe 截断输入安全（不 panic、不报错、产出事实键全部合法）。
func TestHashcatTruncatedSafe(t *testing.T) {
	sample := readSample(t, "hashcat_real.txt")
	for _, in := range []string{truncateHalf(sample), sample[:len(sample)/3], sample[10:]} {
		res, err := hashcatParser{}.Parse(in, "", "")
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

// TestHashcatRegistryAndInjection 注册表 + 注入表 + 占位符解析。
func TestHashcatRegistryAndInjection(t *testing.T) {
	if Lookup("hashcat", []string{"-m", "1000", "hashes.txt", "/usr/share/wordlists/rockyou.txt"}) == nil {
		t.Fatal("Lookup(hashcat) 应命中（文本形态无标志门禁）")
	}
	inj := InjectionFor("hashcat")
	if inj == nil {
		t.Fatal("hashcat 应在 injections 表（C 档 potfile 落文件模式）")
	}
	args := inj.ResolveArgs("/tmp/xx")
	if len(args) != 2 || args[0] != "--potfile-path" || args[1] != "/tmp/xx/hashcat.potfile" {
		t.Errorf("注入参数解析错误: %v", args)
	}
	if got := inj.ResolveResultPath("/tmp/xx"); got != "/tmp/xx/hashcat.potfile" {
		t.Errorf("结果文件路径错误: %s", got)
	}
	// 注册完备性：hashcat 在 RegisteredTools 与 InjectedTools 双侧
	found := false
	for _, tool := range RegisteredTools() {
		if tool == "hashcat" {
			found = true
		}
	}
	if !found {
		t.Error("RegisteredTools 缺 hashcat")
	}
	found = false
	for _, tool := range InjectedTools() {
		if tool == "hashcat" {
			found = true
		}
	}
	if !found {
		t.Error("InjectedTools 缺 hashcat")
	}
}
