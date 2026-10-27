package toolparse

import (
	"strings"
	"testing"
)

// john 样本说明：
//   - john_real.txt：完整运行输出形态（Created directory + Warning 格式识别 + Loaded banner +
//     运行期判定行 `password (user)` + guesses 进度行 + Session 收尾 + 挂钩层并入的 pot 段，
//     pot 含 `$NT$hex32:plain` 与 krb5tgs 内嵌 user$realm 行）。
//   - john_show.txt：`--show` 输出（`login:password:uid:…:::` 档案行 + `N password hashes
//     cracked, M left.` 摘要），档案名=用户名、口令在第二段。

// TestJohnParseRun 运行形态：Loaded banner、判定行 `password (user)`、pot 段 krb 行
// user$realm 解析（confirmed 高优先级事实：破出明文即哈希验证实证）。
func TestJohnParseRun(t *testing.T) {
	res, err := johnParser{}.Parse(readSample(t, "john_real.txt"), "", "raw://john_real")
	if err != nil {
		t.Fatalf("Parse 不应报错: %v", err)
	}
	if !res.OK {
		t.Fatalf("实测样本应可解析: %s", res.Err)
	}
	wantFields := map[string]any{
		"cracked": 5, // 3 判定行 + $NT$ pot 行 + krb pot 行
		"loaded":  3,
		"format":  "NT",
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
	// 判定行 `password (user)` → auth/<user>（confirmed）
	for k, pass := range map[string]string{
		"auth/administrator": "Password1!",
		"auth/jjones":        "P@ssw0rd!",
		"auth/svc-sql":       "almostdone", // svc_sql → Sluggify 转 -
	} {
		f, ok := keys[k]
		if !ok {
			t.Errorf("缺判定行事实 %s", k)
			continue
		}
		if f.Confidence != "confirmed" {
			t.Errorf("%s 应为 confirmed（破解实证）, got %s", k, f.Confidence)
		}
		if !strings.Contains(f.Body, pass) {
			t.Errorf("%s 正文应含明文 %q: %q", k, pass, f.Body)
		}
	}
	// pot 段 krb 行：user$realm 内嵌解析（键形与 hashcat 侧一致）
	if f, ok := keys["auth/sqlservice-corp.local"]; !ok || !strings.Contains(f.Summary, "Kerberos") {
		t.Errorf("缺/错 krb pot 事实 auth/sqlservice-corp.local: %+v", f)
	}
	// $NT$ pot 行无账号信息 → 只计数不落事实
	if len(res.Facts) != 4 {
		t.Errorf("事实数 = %d, want 4（3 判定行 + 1 krb pot）", len(res.Facts))
	}
}

// TestJohnParseShow --show 形态：`login:password:uid:…:::` 档案行（档案名=用户名）+
// `N password hashes cracked, M left.` 摘要。
func TestJohnParseShow(t *testing.T) {
	res, err := johnParser{}.Parse(readSample(t, "john_show.txt"), "", "")
	if err != nil {
		t.Fatalf("Parse 不应报错: %v", err)
	}
	if !res.OK {
		t.Fatalf("--show 样本应可解析: %s", res.Err)
	}
	if got := res.Fields["cracked"]; got != 2 {
		t.Errorf("cracked = %v, want 2", got)
	}
	if got := res.Fields["left"]; got != 1 {
		t.Errorf("left = %v, want 1", got)
	}
	keys := map[string]FactCandidate{}
	for _, f := range res.Facts {
		keys[f.FactKey] = f
		if err := ValidateFactKey(f.FactKey); err != nil {
			t.Errorf("事实键 %q 不合法: %v", f.FactKey, err)
		}
	}
	if f, ok := keys["auth/administrator"]; !ok || !strings.Contains(f.Body, "Password1!") {
		t.Errorf("缺/错 --show 事实 auth/administrator: %+v", f)
	}
	if f, ok := keys["auth/jjones"]; !ok || !strings.Contains(f.Body, "P@ssw0rd!") {
		t.Errorf("缺/错 --show 事实 auth/jjones: %+v", f)
	}
}

// TestJohnRejectsNonJohn 非 john 文本零误报（fail-closed）：
// /etc/passwd 之类的 `user:x:…` 冒号档案行、普通命令输出的冒号行不得误判。
func TestJohnRejectsNonJohn(t *testing.T) {
	cases := []string{
		malformed,
		"Starting Nmap 7.94 ( https://nmap.org )\nNmap scan report for 10.0.0.5\nPORT     STATE SERVICE\n80/tcp   open  http\n",
		"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
		"Host: example.com\nContent-Type: text/html\nSet-Cookie: sid=abc123\n",
		readSample(t, "fscan_real.txt"),   // 跨工具：fscan 输出不得误判
		readSample(t, "hashcat_show.txt"), // 跨工具：hashcat --show 输出不得误判
		strings.Repeat("user:password\n", 50),
	}
	for i, in := range cases {
		res, err := johnParser{}.Parse(in, "", "")
		if err != nil {
			t.Fatalf("case %d Parse 不应报错: %v", i, err)
		}
		if res.OK {
			t.Errorf("case %d 非 john 输入应 OK=false（零误报）", i)
		}
		if len(res.Facts) != 0 {
			t.Errorf("case %d 拒绝时不得产事实, got %d", i, len(res.Facts))
		}
	}
}

// TestJohnTruncatedSafe 截断输入安全（不 panic、不报错、产出事实键全部合法）。
func TestJohnTruncatedSafe(t *testing.T) {
	sample := readSample(t, "john_real.txt")
	for _, in := range []string{truncateHalf(sample), sample[:len(sample)/3], sample[10:]} {
		res, err := johnParser{}.Parse(in, "", "")
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

// TestJohnRegistryAndInjection 注册表 + 注入表 + 占位符解析。
func TestJohnRegistryAndInjection(t *testing.T) {
	if Lookup("john", []string{"--wordlist=/usr/share/wordlists/rockyou.txt", "hashes.txt"}) == nil {
		t.Fatal("Lookup(john) 应命中（文本形态无标志门禁）")
	}
	inj := InjectionFor("john")
	if inj == nil {
		t.Fatal("john 应在 injections 表（C 档 pot 落文件模式）")
	}
	args := inj.ResolveArgs("/tmp/yy")
	if len(args) != 1 || args[0] != "--pot=/tmp/yy/john.pot" {
		t.Errorf("注入参数解析错误: %v", args)
	}
	if got := inj.ResolveResultPath("/tmp/yy"); got != "/tmp/yy/john.pot" {
		t.Errorf("结果文件路径错误: %s", got)
	}
	// 注册完备性：john 在 RegisteredTools 与 InjectedTools 双侧
	found := false
	for _, tool := range RegisteredTools() {
		if tool == "john" {
			found = true
		}
	}
	if !found {
		t.Error("RegisteredTools 缺 john")
	}
	found = false
	for _, tool := range InjectedTools() {
		if tool == "john" {
			found = true
		}
	}
	if !found {
		t.Error("InjectedTools 缺 john")
	}
}
