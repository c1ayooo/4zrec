package guard

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestExtractFenceTargets 覆盖资产围栏目标提取的核心形态:URL host、裸 IP、
// 裸域名、CIDR 网段内的 IP,以及必须排除的误报(文件名、版本号、回环地址)。
func TestExtractFenceTargets(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		domains []string
		ips     []string
	}{
		{
			name:    "nmap 裸域名",
			cmd:     `nmap -sV --open sub.example.com`,
			domains: []string{"sub.example.com"},
		},
		{
			name:    "curl URL 与端口",
			cmd:     `curl -s https://api.example.com:8443/health`,
			domains: []string{"api.example.com"},
		},
		{
			name:    "多目标混合",
			cmd:     `nmap 10.0.0.1 10.0.0.2 web.example.com`,
			domains: []string{"web.example.com"},
			ips:     []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name: "CIDR 网段提取其中的网络地址",
			cmd:  `nmap -p 80 192.168.10.0/24`,
			ips:  []string{"192.168.10.0"},
		},
		{
			name: "冒号端口形态",
			cmd:  `nc -zv 10.1.2.3 443`,
			ips:  []string{"10.1.2.3"},
		},
		{
			name: "文件名不当作域名",
			cmd:  `python3 report.py && cat output.txt && tar czf backup.tar.gz ./data`,
		},
		{
			name: "版本号不当作 IP",
			cmd:  `nginx version 1.2.3 updated 2.4.13`,
		},
		{
			name: "回环地址排除",
			cmd:  `curl http://127.0.0.1:8080/debug && curl http://localhost/x`,
		},
		{
			// 2026-10-15 误报:渗透脚本把 shell 变量拼进 URL(循环/函数参数拼路径),
			// 提取器把 $p 一起当域名,授权内的 www.woniucx.com 反倒要审批。
			name:    "URL 带 shell 变量尾巴剥到合法主机",
			cmd:     `for p in /a /b; do curl -s "http://www.woniucx.com$p"; done`,
			domains: []string{"www.woniucx.com"},
		},
		{
			name:    "heredoc 探针函数的 $2 参数拼接",
			cmd:     `probe(){ r=$(curl -s -m 15 -X "$1" "https://woniuxy.com$2" -w "%{http_code}"); }`,
			domains: []string{"woniuxy.com"},
		},
		{
			name: "URL host 整段是变量则丢弃",
			cmd:  `curl "http://$host/path" && curl "http://x.${port}a/x"`,
		},
		{
			// 2026-10-15 误报原始形态:路径列表是独立的双引号串(URL 剔除不到),
			// 接口参数里的邮箱(?to=a@b.com)不是连接目标,@ 后段被裸 token
			// 扫描误当主机。
			name:    "邮箱查询参数不当作目标",
			cmd:     `for p in "/partner-back/download" "/partner-back/demo/mail/sendMessageWithAttachment?to=a@b.com"; do curl -s "http://www.woniucx.com$p"; done`,
			domains: []string{"www.woniucx.com"},
		},
		{
			name:    "JSON 载荷里的邮箱参数不当作目标",
			cmd:     `curl -d '{"to":"a@b.com","from":"x@y.org"}' "https://woniuxy.com/api/send"`,
			domains: []string{"woniuxy.com"},
		},
		{
			// 新口径:凭据参数(-u user@host)不是连接目标,只提取 URL 主机。
			name:    "凭据参数内的主机不当作目标",
			cmd:     `curl -u admin@evil.com http://api.example.com/`,
			domains: []string{"api.example.com"},
		},
		{
			name: "路径里的点分串不算目标",
			cmd:  `./run.sh --config ./conf/app.prod.yaml`,
		},
		{
			name:    "URL 内 path 不产生域名",
			cmd:     `wget https://example.com/a/b/c.d`,
			domains: []string{"example.com"},
		},
		{
			name:    "管道与重定向中的目标",
			cmd:     `dig +short sub.example.com | tee out.txt; curl http://10.9.8.7`,
			domains: []string{"sub.example.com"},
			ips:     []string{"10.9.8.7"},
		},
		{
			name: "Python 代码标识符不当作域名",
			cmd:  `python3 -c "import re,os,json; print(re.findall(r'[0-9]+', os.popen('echo hi').read())); json.loads('{}')"; pip install requests==2.31.0`,
		},
		{
			name:    "公共 DNS 解析器直接排除,真正目标照常提取",
			cmd:     `dig @8.8.8.8 +short sub.example.com; nslookup x.com 114.114.114.114`,
			domains: []string{"sub.example.com", "x.com"},
		},
		{
			// 用户实测形态:dig 的记录类型/类(CNAME/TXT/NS/IN)曾被当成域名送审。
			name:    "dig 查询类型与类不当作目标",
			cmd:     `d="target.example.com"; dig +short "$d" CNAME; dig TXT x.origin.asn.cymru.com +short; dig IN NS example.com`,
			domains: []string{"example.com", "target.example.com", "x.origin.asn.cymru.com"},
		},
		{
			// 用户实测形态:openssl x509 -ext subjectAltName 的子命令/扩展名/证书路径曾被当成目标。
			name:    "openssl 只取连接类旗标的值",
			cmd:     `openssl x509 -ext subjectAltName -noout -text -in cert.pem; openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null`,
			domains: []string{"api.example.com"},
		},
		{
			name:    "单引号载荷(代码/数据)里的裸 token 不是目标",
			cmd:     `dig +short sub.example.com | awk '{print $1}' && python3 -c 'x="other.evil.com"; print(len(x))'`,
			domains: []string{"sub.example.com"},
		},
		{
			// 2026-10-18 新口径:解释器代码里的 URL 是真实命令对象，提取出来送审；
			// 代码含网络调用时仍标记 Opaque（动态拼接的目标无法穷举）。
			name:    "python -c 代码里的 URL 按对象提取",
			cmd:     `python3 -c 'import requests; requests.get("https://api.evil.com/x")'`,
			domains: []string{"api.evil.com"},
		},
		{
			name:    "双引号包裹的真实目标仍识别",
			cmd:     `nmap -p 80 "sub.example.com"`,
			domains: []string{"sub.example.com"},
		},
		{
			name:    "POST 载荷里的裸域名不算目标,请求 URL 才算",
			cmd:     `curl -s -X POST -d '{"host":"inner.example"}' https://api.example.com/v1`,
			domains: []string{"api.example.com"},
		},
		{
			// 任务156实测形态:heredoc 里的 python 代码,m.group 撞内网伪 TLD。
			name: "heredoc python 载荷里的代码标识符不当作目标",
			cmd: `python3 - <<'EOF'
import re
for m in re.finditer(r'<script>(.*?)</script>', html, re.S):
    t=m.group(1)
    if 'version' in t: print(t)
EOF`,
		},
		{
			// 新口径:grep/cat/jq 等数据加工命令与 heredoc 一律跳过。
			name: "grep 参数与 heredoc 内容都不扫描",
			cmd: `grep -o sub.example.com index.html; python3 - <<'EOF'
x=m.group(1)
EOF`,
		},
		{
			name: "直接对公共解析器本身操作也不进围栏",
			cmd:  `curl -m 3 http://1.1.1.1/ && ping -c1 223.5.5.5`,
		},
		{
			name:    "内网伪 TLD 主机名仍识别",
			cmd:     `nmap -p 22 app.corp.local dc01.prod web.internal`,
			domains: []string{"app.corp.local", "dc01.prod", "web.internal"},
		},

		// ---- 对抗性用例(红队方向:必须提取到 / 必须拦住)。与上面的误报
		// 排除用例对偶——2026-10-16 围栏加固引入,每个用例对应一个实测过的
		// 绕过形态,改动提取器前先跑这里。----

		{
			// <<< here-string 曾被 reHeredocStart 从第二个 < 起误当 heredoc
			// 起点,未闭合分支再吞掉全部剩余文本 → 目标隐身。
			name:    "here-string(<<<)不是 heredoc 起点,后续目标照常提取",
			cmd:     `cat <<<EOF; nmap sub.evil.com`,
			domains: []string{"sub.evil.com"},
		},
		{
			// 未闭合 heredoc 曾把余下全部文本当载荷剔除;实际 <<EOF 后同行的
			// 命令是真实会执行的(分号分隔)。
			name:    "未闭合 heredoc 只抹标记,同行后续命令目标照常提取",
			cmd:     `cat <<EOF; nmap sub.evil.com`,
			domains: []string{"sub.evil.com"},
		},
		{
			// 单引号文本里的字面 <<EOF 曾被当 heredoc 起点 → 未闭合 → 吞全部。
			name:    "引号内的字面 <<TAG 不启动 heredoc,后续目标照常提取",
			cmd:     `echo 'see <<EOF docs'; nmap sub.evil.com`,
			domains: []string{"sub.evil.com"},
		},
		{
			// 反引号与 $() 运行时等价,此前只有反引号段被整段剔除。
			name:    "反引号命令替换段不再剔除,其中目标照常提取",
			cmd:     "ping -c1 `dig +short sub.evil.com`",
			domains: []string{"sub.evil.com"},
		},
		{
			// 整数形 IP(inet_aton):16909060 = 1.2.3.4。
			name: "整数形 IP 变体归一化提取",
			cmd:  `curl -s 16909060`,
			ips:  []string{"1.2.3.4"},
		},
		{
			// 十六进制形:0xC0A80001 = 192.168.0.1。
			name: "十六进制 IP 变体归一化提取",
			cmd:  `curl -s 0xC0A80001`,
			ips:  []string{"192.168.0.1"},
		},
		{
			// 前导零八进制段:0330 = 216。
			name: "八进制段 IP 变体归一化提取",
			cmd:  `curl -s 0330.0.0.1`,
			ips:  []string{"216.0.0.1"},
		},
		{
			// 末段前导零:10.0.0.01 → 10.0.0.1(validFenceIPv4 拒绝前导零,
			// 由变体分支接住)。
			name: "末段前导零 IP 归一化提取",
			cmd:  `curl -s 10.0.0.01`,
			ips:  []string{"10.0.0.1"},
		},
		{
			// 八进制环回(0177.0.0.1 = 127.0.0.1)与点分环环回同待遇:排除。
			name: "归一化后是回环地址则排除(与点分形态一致)",
			cmd:  `curl -s 0177.0.0.1`,
		},
		{
			// 版本号碎片(纯十进制三段)不判 IP 变体——防误报回归护栏。
			name: "纯十进制三段仍不判 IP 变体(版本号形态)",
			cmd:  `nginx version 1.2.3 updated 2.4.13 build 10.20.30`,
		},

		// ---- 2026-10-17 实盘误报回归:任务 165 的围栏审批把授权目标
		// (aiface.fanyunedu.com)和一个幽灵 IP(0.0.0.126)一起列出来,
		// 用户以为授权失效。下面是每个误报的原始形态。----

		{
			// SQLi payload 里的字节常量 0x7e 曾被 inet_aton 归一化成
			// 0.0.0.126,整条已授权命令被拖进审批。
			name:    "SQLi 载荷的 0x7e 字节常量不当作单段 IP",
			cmd:     `curl -G --data-urlencode "goodsTitle=bb' AND extractvalue(1,concat(0x7e,version()))-- -" https://aiface.fanyunedu.com/partner-back`,
			domains: []string{"aiface.fanyunedu.com"},
		},
		{
			name: "十六进制字节常量 0x27/0x20 不当作 IP",
			cmd:  `python3 -c "print(bytes([0x27,0x20]))"`,
		},
		{
			// 内联 python 的双引号段是代码:m.group 撞 .group 真 gTLD。
			name: "内联解释器代码参数里的 m.group 不当作域名",
			cmd:  `python3 -c "import re; h=open('x').read(); m=re.search(r'a',h); print(m.group(1))"`,
		},
		{
			// 文档/heredoc 里的占位符 host 不是目标(URL 分支此前不做校验)。
			name: "heredoc 文档里的 http://host 占位符不当作域名",
			cmd: `cat > n.txt <<'EOF'
target: http://host:8080/api
EOF`,
		},
		{
			// 单段真实内网主机名仍要拦(不能因为"没有点"就放行)。
			name:    "URL 里的单段内网主机名仍按目标处理",
			cmd:     `curl -s http://jira/rest/api && curl -s http://x/a`,
			domains: []string{"jira"},
		},
		{
			// URL 路径/裸字符串里的版本目录曾被 IPv4 正则当目标。
			name:    "路径片段里的版本号不当作 IP",
			cmd:     `for p in "/rainloop/v/1.10.0.103/" "/index.php/"; do curl -s -o /dev/null "http://smtp.woniuxy.com:8000$p"; done`,
			domains: []string{"smtp.woniuxy.com"},
		},
		{
			// .sh 在文件扩展名黑名单里;URL 分支现在与裸 token 同口径。
			name: `公共 CT 日志服务 crt.sh 不当作目标`,
			cmd:  `curl -s "https://crt.sh/?q=%25.fanyunedu.com&output=json"`,
		},
		{
			// 8 位十六进制单段仍是合法 IP 形态(0xC0A80001 用例的对偶护栏)。
			name: `8 位十六进制 IP 仍归一化提取`,
			cmd:  `curl -s 0x0A000001`,
			ips:  []string{"10.0.0.1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractFenceTargets(tc.cmd)
			if got.Domains == nil {
				got.Domains = []string{}
			}
			if got.IPs == nil {
				got.IPs = []string{}
			}
			if tc.ips == nil {
				tc.ips = []string{}
			}
			if tc.domains == nil {
				tc.domains = []string{}
			}
			if !reflect.DeepEqual(got.Domains, tc.domains) {
				t.Errorf("domains = %v, want %v", got.Domains, tc.domains)
			}
			if !reflect.DeepEqual(got.IPs, tc.ips) {
				t.Errorf("ips = %v, want %v", got.IPs, tc.ips)
			}
		})
	}
}

// TestFenceCommandTextOnlyKnownTools 保证非出网类工具不参与围栏。
func TestFenceCommandTextOnlyKnownTools(t *testing.T) {
	if got := fenceCommandText("Read", []byte(`{"path":"/etc/hosts"}`)); got != "" {
		t.Errorf("Read 不应参与围栏, got %q", got)
	}
	if got := fenceCommandText("Bash", []byte(`{"command":"nmap x.example.com"}`)); got != "nmap x.example.com" {
		t.Errorf("Bash command 提取错误: %q", got)
	}
}

// TestValidFenceDomain 边界:数字 TLD 拒绝、单字符标签拒绝、合法 ID 风格 token 拒绝、
// 代码标识符尾缀(不在 TLD 白名单)拒绝。
func TestValidFenceDomain(t *testing.T) {
	bad := []string{
		"python3.11", "a.b", "-bad.com", "example.com-", "host..com", "1.2.3.4", "x",
		// 代码标识符:尾缀不在 TLD 白名单,全部拒绝(用户实测 re.findall 误报的回归)
		"re.findall", "os.path", "os.path.join", "json.dumps", "sys.argv", "str.format",
	}
	for _, s := range bad {
		if validFenceDomain(s) {
			t.Errorf("%q 不应判定为域名", s)
		}
	}
	good := []string{
		"example.com", "sub.example.com", "a-b.example.co", "xn--fiqs8s.example",
		// 内网伪 TLD 与保留后缀
		"dc01.prod", "app.corp.local", "xawl.edu.cn",
	}
	for _, s := range good {
		if !validFenceDomain(s) {
			t.Errorf("%q 应判定为域名", s)
		}
	}
}

// TestFenceNoTruncationBeforeJudgment 截断只影响展示,判定用完整列表
// (2026-10-16 围栏加固回归):"提取阶段截到 32 条"曾经让排序靠后的未授权
// 目标同时躲过黑名单匹配与审批文案——批准者被蒙在鼓里。
func TestFenceNoTruncationBeforeJudgment(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("nmap")
	for i := 0; i < 34; i++ {
		fmt.Fprintf(&sb, " t%02d.example.com", i)
	}
	got := ExtractFenceTargets(sb.String())
	if len(got.Domains) != 34 {
		t.Fatalf("提取应保留全部 34 个目标(判定/黑名单/登记用),得到 %d", len(got.Domains))
	}
	// 排序后垫底的 t33 必须在场——按字典序排,它正是旧截断实现丢掉的那批。
	found := false
	for _, d := range got.Domains {
		if d == "t33.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("排序垫底的目标(t33.example.com)被丢弃——判定列表不得截断")
	}
	// 展示层才截断,并带总数标注。
	dl := got.displayList()
	if !strings.Contains(dl, "等 34 个目标") {
		t.Fatalf("展示层应截断并标注总数: %q", dl)
	}
	if strings.Contains(dl, "t33.example.com") || strings.Contains(dl, "t32.example.com") {
		t.Fatal("展示层截断后不应逐条列出第 32 名之外的目标")
	}
}

// TestInetAtonIP 归一化核心:四段/三段/两段/单段、八进制与十六进制段、
// 越界拒绝。可疑 IP 变体的判定正确性依赖这里。
func TestInetAtonIP(t *testing.T) {
	cases := map[string]string{
		"16909060":   "1.2.3.4",     // 整数形
		"0xC0A80001": "192.168.0.1", // 十六进制单段
		"0x7f.1":     "127.0.0.1",   // 混合段
		"0330.0.0.1": "216.0.0.1",   // 八进制首段
		"1.2.3":      "1.2.0.3",     // 三段(末段占两字节)
		"1.2.3.4":    "1.2.3.4",     // 标准四段
		"10.0.0.01":  "10.0.0.1",    // 末段前导零
		// 越界/非法 → 空串
		"256.1.1.1":    "",
		"1.2.3.4.5":    "",
		"999999999999": "",
		"1.2.65536":    "",
		"":             "",
	}
	for in, want := range cases {
		if got := inetAtonIP(in); got != want {
			t.Errorf("inetAtonIP(%q) = %q, want %q", in, got, want)
		}
	}
}
