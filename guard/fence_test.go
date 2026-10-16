package guard

import (
	"reflect"
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
			name: "多目标混合",
			cmd:  `nmap 10.0.0.1 10.0.0.2 web.example.com`,
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
			name:    "回环地址排除",
			cmd:     `curl http://127.0.0.1:8080/debug && curl http://localhost/x`,
			domains: []string{"localhost"}, // localhost 是域名形态,回环 IP 被排除
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
			// user@host 形态的凭据/登录名不在参数位,保留提取(宁误报勿漏拦)。
			name:    "user@host 凭据保留主机提取",
			cmd:     `curl -u admin@evil.com http://api.example.com/`,
			domains: []string{"api.example.com", "evil.com"},
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
			name: "管道与重定向中的目标",
			cmd:  `dig +short sub.example.com | tee out.txt; curl http://10.9.8.7`,
			domains: []string{"sub.example.com"},
			ips:    []string{"10.9.8.7"},
		},
		{
			name: "Python 代码标识符不当作域名",
			cmd:  `python3 -c "import re,os,json; print(re.findall(r'[0-9]+', os.popen('echo hi').read())); json.loads('{}')"; pip install requests==2.31.0`,
		},
		{
			name: "公共 DNS 解析器直接排除,真正目标照常提取",
			cmd:  `dig @8.8.8.8 +short sub.example.com; nslookup x.com 114.114.114.114`,
			domains: []string{"sub.example.com", "x.com"},
		},
		{
			name: "单引号载荷(代码/数据)里的裸 token 不是目标",
			cmd:  `dig +short sub.example.com | awk '{print $1}' && python3 -c 'x="other.evil.com"; print(len(x))'`,
			domains: []string{"sub.example.com"},
		},
		{
			name: "引号内带 scheme 的 URL 仍是目标(代码里的真实请求)",
			cmd:  `python3 -c 'import requests; requests.get("https://api.evil.com/x")'`,
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
			name:    "heredoc 之外的命令参数区目标照常识别",
			cmd:     `grep -o sub.example.com index.html; python3 - <<'EOF'
x=m.group(1)
EOF`,
			domains: []string{"sub.example.com"},
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
