// fence_corpus_test.go 提取语料回归(2026-10-30):审批里「命令的目标」必须
// 可信,这份语料钉住两类历史错误——
//   - 误报:位置参数里的裸单词(服务名/子命令/用户名/标签值)被提成域名,
//     nmap --exclude 的排除地址被列为目标;
//   - 漏报:mysqldump/impacket-*/crackmapexec/snmpwalk 不在出网命令表里
//     静默放行;管道喂扫描器(cat subs.txt | httpx)的 stdin 目标不可见。
package guard

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// normStrings 把空切片归一成 nil,让 reflect.DeepEqual 对「没有目标」的
// 两种表示(nil / 空切片)等价。
func normStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// TestFenceCorpusLoopVars 钉住循环变量/脚本路径的解析行为(2026-10-31:
// 用户实锤 `python3 "$f"` 被「无法读取脚本」整条转人工)。循环头词表可静态
// 解析时按候选展开;词表来自命令替换时维持 fail-closed;脚本路径含未解析
// 变量时,审批文案要说「含变量」而不是误导性的「仅允许工作目录内文件」。
func TestFenceCorpusLoopVars(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("clean.py", "print('local only')\n")
	write("probe.py", "import requests\nrequests.get('https://probe.example.com/health')\n")

	inspect := func(cmd string) Result {
		return Inspect("Bash", []byte(`{"command":`+jsonString(cmd)+`}`), dir)
	}

	// 循环跑本地脚本:词表展开到真实文件,干净脚本静默放行,联网脚本给出
	// 字面目标并标 Opaque(动态构造不可穷举)。
	if r := inspect(`for f in clean.py; do python3 "$f"; done`); r.Opaque || len(r.Domains) != 0 {
		t.Errorf("clean.py 循环: domains=%v opaque=%v, want 无目标且不转人工", r.Domains, r.Opaque)
	}
	if r := inspect(`for f in probe.py; do python3 "$f"; done`); !r.Opaque || len(r.Domains) != 1 || r.Domains[0] != "probe.example.com" {
		t.Errorf("probe.py 循环: domains=%v opaque=%v, want probe.example.com + Opaque", r.Domains, r.Opaque)
	}
	// glob 词表:*.py 展开为两个候选,目标取并集,联网候选令整体 Opaque。
	if r := inspect(`for f in *.py; do python3 "$f"; done`); !r.Opaque || len(r.Domains) != 1 || r.Domains[0] != "probe.example.com" {
		t.Errorf("glob 循环: domains=%v opaque=%v, want probe.example.com + Opaque", r.Domains, r.Opaque)
	}
	// 赋值变量脚本路径:代入后可读。
	if r := inspect(`s=probe.py; python3 "$s"`); !r.Opaque || len(r.Domains) != 1 || r.Domains[0] != "probe.example.com" {
		t.Errorf("赋值变量脚本: domains=%v opaque=%v", r.Domains, r.Opaque)
	}
	// 未解析变量路径:fail-closed,但文案必须说明是「含变量」,不再是
	// 「仅允许任务工作目录内文件」(那是权限语义,对动态路径是误导)。
	if r := inspect(`python3 "$f"`); !r.Opaque || !strings.Contains(r.Reason, "含变量") {
		t.Errorf("变量脚本路径: opaque=%v reason=%q, want Opaque 且文案说明含变量", r.Opaque, r.Reason)
	}
	// 循环目标是域名:逐候选展开求并集,不再因 $h 转 Opaque。
	if r := inspect(`for h in a.example.com b.example.com; do curl -s "http://$h/" -o /dev/null; done`); r.Opaque ||
		!reflect.DeepEqual(r.Domains, []string{"a.example.com", "b.example.com"}) {
		t.Errorf("域名循环: domains=%v opaque=%v", r.Domains, r.Opaque)
	}
	// 词表来自命令替换:不可解析,维持动态占位符 fail-closed。
	if r := inspect(`for u in $(cat urls.txt); do curl -s "$u"; done`); !r.Opaque {
		t.Errorf("命令替换词表: opaque=%v, want true", r.Opaque)
	}
	// while-read 循环:变量来自输入流,静态不可知 → fail-closed。
	if r := inspect(`while read u; do curl -s "$u"; done < urls.txt`); !r.Opaque {
		t.Errorf("while-read: opaque=%v, want true", r.Opaque)
	}
	// 嵌套 for:内层头带 do 前缀(`do for b in ...`),两层绑定都要登记,
	// 目标取笛卡尔积里的全部主机。
	if r := inspect(`for a in 1 2; do for b in x.example.com y.example.com; do curl -s "http://$b/$a" -o /dev/null; done; done`); r.Opaque ||
		!reflect.DeepEqual(r.Domains, []string{"x.example.com", "y.example.com"}) {
		t.Errorf("嵌套 for: domains=%v opaque=%v", r.Domains, r.Opaque)
	}
}

// TestSubstituteVarsBoundary 变量代入按标识符边界:绑定 f 不得误吃 $foo
// (旧 ReplaceAll 实现的真实风险);未绑定变量原样保留。
func TestSubstituteVarsBoundary(t *testing.T) {
	vars := map[string]string{"f": "1.2.3.4"}
	for _, tc := range []struct{ in, want string }{
		{"$f", "1.2.3.4"},
		{"${f}", "1.2.3.4"},
		{"$foo", "$foo"},
		{"${foo}", "${foo}"},
		{"$f$foo", "1.2.3.4$foo"},
		{"scan_$f.py", "scan_1.2.3.4.py"},
		{"$f}", "1.2.3.4}"},
		{"a$ $f", "a$ 1.2.3.4"},
		{"$1 $@ $?", "$1 $@ $?"},
	} {
		if got := substituteVars(tc.in, vars); got != tc.want {
			t.Errorf("substituteVars(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFenceCorpusExtraction(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		domains []string
		ips     []string
		opaque  bool
	}{
		// ---- 误报:位置参数裸单词不是目标 ----
		{"hydra 服务名", `hydra -L users.txt -P pass.txt 10.10.10.10 ssh`,
			nil, []string{"10.10.10.10"}, false},
		{"hydra 用户名与表单", `hydra -l admin -P pass.txt target.example.com http-post-form "/login:user=^USER^&pass=^PASS^:failed"`,
			[]string{"target.example.com"}, nil, false},
		{"amass 子命令", `amass enum -d target.example.com`,
			[]string{"target.example.com"}, nil, false},
		{"psql 用户名", `psql -h 10.10.10.10 -U postgres -c 'select version()'`,
			nil, []string{"10.10.10.10"}, false},
		{"redis-cli 子命令", `redis-cli -h 10.10.10.10 -p 6379 keys '*'`,
			nil, []string{"10.10.10.10"}, false},
		{"gobuster 子命令", `gobuster dir -u http://target.example.com -w words.txt -x php`,
			[]string{"target.example.com"}, nil, false},
		{"nuclei 标签与级别", `nuclei -u https://target.example.com -tags cve -severity high`,
			[]string{"target.example.com"}, nil, false},
		{"searchsploit 本地检索", `searchsploit apache 2.4.49`, nil, nil, false},
		{"nmap 排除地址不是目标", `nmap --exclude 10.10.10.99 10.10.10.0/24 -p 443`,
			nil, []string{"10.10.10.0"}, false},
		{"mysql 库名不是目标", `mysql -h 10.10.10.10 -u root -p'pass' northstar_prod -e 'show databases'`,
			nil, []string{"10.10.10.10"}, false},

		// ---- 漏报:出网命令表补齐 ----
		{"mysqldump", `mysqldump -h 203.0.113.10 -uroot northstar_prod > /tmp/dump.sql`,
			nil, []string{"203.0.113.10"}, false},
		{"impacket 前缀族", `impacket-secretsdump corp.local/svc_deploy:pass@10.10.10.10 -just-dc -dc-ip 10.10.10.250`,
			nil, []string{"10.10.10.10", "10.10.10.250"}, false},
		{"crackmapexec 协议位", `crackmapexec smb 10.10.10.0/24 -u user -p pass --sam`,
			nil, []string{"10.10.10.0"}, false},
		{"snmpwalk", `snmpwalk -v2c -c public 10.10.10.10`, nil, []string{"10.10.10.10"}, false},
		{"ssh 单段主机名带用户", `ssh root@gitlab-intranet`, []string{"gitlab-intranet"}, nil, false},

		// ---- 漏报:管道喂扫描器,目标来自 stdin → fail-closed ----
		{"管道喂 httpx", `cat subs.txt | httpx -silent -title`, nil, nil, true},
		// echo 的字面 IP 由 Opaque 兜底扫描收进结果(审批可见),但对象不可
		// 静态穷举 → 仍 Opaque。
		{"echo 管道 nc", `echo 49.51.48.17 | nc`, nil, []string{"49.51.48.17"}, true},
		// curl 目标显式;httpx 探测的是响应体里的任意主机 → 仍 Opaque。
		{"管道但上游目标显式", `curl -s http://target.example.com/list | httpx -silent`,
			[]string{"target.example.com"}, nil, true},

		// ---- 基线:正常形态不受影响 ----
		{"dig 类型与变量", `d="target.example.com"; dig +short "$d" CNAME; dig TXT x.origin.asn.cymru.com +short`,
			[]string{"target.example.com", "x.origin.asn.cymru.com"}, nil, false},
		{"curl 单段 URL", `curl -s http://intranet/api/health`, []string{"intranet"}, nil, false},
		{"nmap 常规", `nmap -sV --version-intensity 5 10.10.10.10 -p 80,443`,
			nil, []string{"10.10.10.10"}, false},
		{"ffuf 常规", `ffuf -u http://target.example.com/FUZZ -w /usr/share/wordlists/dir.txt -mc 200`,
			[]string{"target.example.com"}, nil, false},
		{"curl 头与输出", `curl -sS https://target.example.com/api -H 'Host: api.target.example.com' -o out.json`,
			[]string{"target.example.com"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Inspect("Bash", []byte(`{"command":`+jsonString(tc.cmd)+`}`), "")
			if !reflect.DeepEqual(normStrings(got.Domains), normStrings(tc.domains)) {
				t.Errorf("domains = %v, want %v", got.Domains, tc.domains)
			}
			if !reflect.DeepEqual(normStrings(got.IPs), normStrings(tc.ips)) {
				t.Errorf("ips = %v, want %v", got.IPs, tc.ips)
			}
			if got.Opaque != tc.opaque {
				t.Errorf("opaque = %v, want %v (reason: %s)", got.Opaque, tc.opaque, got.Reason)
			}
		})
	}
}
