package guard

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFenceCommandObjectExtraction 覆盖“命令对象”解析：包装命令、shell -c、
// xargs/find -exec、解释器代码、目标列表文件、IPv6，以及无法静态确定对象
// 时的 Opaque 标记。
func TestFenceCommandObjectExtraction(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		domains []string
		ips     []string
		opaque  bool
	}{
		{
			name:    "sh -c 内部命令按对象解析",
			cmd:     `sh -c 'curl -s http://api.example.com/x'`,
			domains: []string{"api.example.com"},
		},
		{
			name: "sudo 包装后取真实命令对象",
			cmd:  `sudo -u root nmap -p 80 10.1.2.3`,
			ips:  []string{"10.1.2.3"},
		},
		{
			name:    "timeout 包装后取真实命令对象",
			cmd:     `timeout 10 curl -s http://api.example.com`,
			domains: []string{"api.example.com"},
		},
		{
			name: "env -S 内部命令按对象解析",
			cmd:  `env -S 'nmap 10.4.3.2'`,
			ips:  []string{"10.4.3.2"},
		},
		{
			name:    "script -c 内部命令按对象解析",
			cmd:     `script -q -c 'curl -s http://api.example.com' /dev/null`,
			domains: []string{"api.example.com"},
		},
		{
			name:    "find -exec 内部命令按对象解析",
			cmd:     `find . -type f -exec curl -s http://api.example.com {} \;`,
			domains: []string{"api.example.com"},
		},
		{
			name:   "xargs 动态目标 fail-closed",
			cmd:    `xargs -I{} curl http://{}`,
			opaque: true,
		},
		{
			name:   "xargs 内部出网命令无显式目标 fail-closed",
			cmd:    `xargs curl -s`,
			opaque: true,
		},
		{
			name:   "ssh 远程命令联网 fail-closed",
			cmd:    `ssh host 'curl -s http://evil.example.com'`,
			opaque: true,
		},
		{
			name:    "ssh 本地远程命令不 Opaque",
			cmd:     `ssh db01.prod uptime`,
			domains: []string{"db01.prod"},
		},
		{
			name:   "ssh ProxyCommand fail-closed",
			cmd:    `ssh -o ProxyCommand='curl http://evil.example.com' host`,
			opaque: true,
		},
		{
			name:    "解释器内联代码中的 URL 提取",
			cmd:     `python3 -c 'import requests; requests.get("https://api.example.com/x")'`,
			domains: []string{"api.example.com"},
			opaque:  true, // 代码含网络调用，静态只识别到部分目标
		},
		{
			name: "纯本地解释器代码不 Opaque",
			cmd:  `python3 -c 'print("hello")'`,
		},
		{
			name: "解释器版本查询不 Opaque",
			cmd:  `python3 --version`,
		},
		{
			name:   "解释器无脚本无代码 fail-closed",
			cmd:    `python3 -u`,
			opaque: true,
		},
		{
			name:   "未知命令 fail-closed",
			cmd:    `mytool 1.2.3.4`,
			opaque: true,
		},
		{
			name: "裸 IPv6 目标",
			cmd:  `nmap -p 443 2001:db8::1`,
			ips:  []string{"2001:db8::1"},
		},
		{
			name: "带方括号 IPv6 + 端口",
			cmd:  `curl -s 'http://[2001:db8::1]:8080/'`,
			ips:  []string{"2001:db8::1"},
		},
		{
			name: "bash -c 内部命令按对象解析",
			cmd:  `bash -c 'nmap 10.9.8.7'`,
			ips:  []string{"10.9.8.7"},
		},
		{
			name: "eval 内部命令按对象解析",
			cmd:  `eval 'nmap 10.9.8.7'`,
			ips:  []string{"10.9.8.7"},
		},
		{
			name: "watch 内部命令按对象解析",
			cmd:  `watch -n 2 'nmap 10.9.8.7'`,
			ips:  []string{"10.9.8.7"},
		},
		{
			name:    "循环体里的真实目标仍识别",
			cmd:     `for p in /a /b; do curl -s "http://api.example.com$p"; done`,
			domains: []string{"api.example.com"},
		},
		{
			name:    "openssl 连接对象",
			cmd:     `openssl s_client -connect api.example.com:443 </dev/null`,
			domains: []string{"api.example.com"},
		},
		{
			name:    "WebFetch 裸 URL 不按未知命令处理",
			cmd:     `https://api.example.com/x`,
			domains: []string{"api.example.com"},
		},
		{
			name:    "katana -u 按目标对象处理",
			cmd:     `katana -u http://api.example.com -silent`,
			domains: []string{"api.example.com"},
		},
		{
			name:    "sqlmap -u 按目标对象处理",
			cmd:     `sqlmap -u http://api.example.com/id=1 --batch`,
			domains: []string{"api.example.com"},
		},
		{
			name:    "subfinder -d 按目标对象处理",
			cmd:     `subfinder -d example.com -silent`,
			domains: []string{"example.com"},
		},
		{
			name: "本地数据处理不 Opaque",
			cmd:  `cat /etc/passwd | grep root | awk -F: '{print $1}'`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractFenceTargetsWithDir(tc.cmd, "")
			if tc.opaque != got.Opaque {
				t.Fatalf("Opaque = %v, want %v (reason=%q, domains=%v ips=%v)",
					got.Opaque, tc.opaque, got.Reason, got.Domains, got.IPs)
			}
			if !sameStrings(got.Domains, tc.domains) {
				t.Errorf("domains = %v, want %v", got.Domains, tc.domains)
			}
			if !sameStrings(got.IPs, tc.ips) {
				t.Errorf("ips = %v, want %v", got.IPs, tc.ips)
			}
		})
	}
}

// TestFenceTargetListFile 验证 -iL/目标列表文件只能从任务工作目录读取；
// 目录外文件或缺失文件 fail-closed。
func TestFenceTargetListFile(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(list, []byte("# comment\n10.7.6.5\napi.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := ExtractFenceTargetsWithDir(`nmap -iL targets.txt`, dir)
	if got.Opaque {
		t.Fatalf("readable target list should not be opaque: %s", got.Reason)
	}
	if !sameStrings(got.IPs, []string{"10.7.6.5"}) || !sameStrings(got.Domains, []string{"api.example.com"}) {
		t.Fatalf("file targets = domains %v ips %v", got.Domains, got.IPs)
	}

	// 目录外绝对路径必须拒绝。
	got = ExtractFenceTargetsWithDir(`nmap -iL /etc/passwd`, dir)
	if !got.Opaque {
		t.Fatal("out-of-workdir target list must fail closed")
	}
	// 缺失文件同样 fail-closed。
	got = ExtractFenceTargetsWithDir(`nmap -iL missing.txt`, dir)
	if !got.Opaque {
		t.Fatal("missing target list must fail closed")
	}
}

// TestFenceInterpreterScript 验证解释器脚本从工作目录读取；含网络调用时
// 既提取 URL 对象，也保留 Opaque（动态目标无法穷举）。
func TestFenceInterpreterScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "probe.py")
	if err := os.WriteFile(script, []byte("import requests\nrequests.get('https://api.example.com/x')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ExtractFenceTargetsWithDir(`python3 probe.py`, dir)
	if !got.Opaque {
		t.Fatal("network-capable script should stay opaque")
	}
	if !sameStrings(got.Domains, []string{"api.example.com"}) {
		t.Fatalf("script URL targets = %v", got.Domains)
	}

	got = ExtractFenceTargetsWithDir(`python3 missing.py`, dir)
	if !got.Opaque {
		t.Fatal("missing script must fail closed")
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
