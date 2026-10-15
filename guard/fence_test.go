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
