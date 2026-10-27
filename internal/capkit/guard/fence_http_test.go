package guard

import (
	"encoding/json"
	"testing"
)

// TestExtractHTTPProbeTargets 围栏对象 = http_probe 的请求 URL 对象:
// url / requests[].url / template×matrix|range;proxy、headers、body、
// extract、save_to_file 一律不产生目标;host 位含运行时回填变量时 Opaque。
func TestExtractHTTPProbeTargets(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		domains []string
		ips     []string
		opaque  bool
	}{
		{
			name:    "单发 url",
			input:   `{"url":"http://api.example.com/x","method":"GET"}`,
			domains: []string{"api.example.com"},
		},
		{
			name: "proxy 不是测试目标",
			input: `{"url":"https://target.example.com/login","proxy":"http://evil-proxy.io:8080",` +
				`"headers":{"Host":"spoof.example.com","Referer":"http://referrer.example.net/"},` +
				`"body":"{\"callback\":\"http://cb.example.org/ok\"}"}`,
			domains: []string{"target.example.com"},
		},
		{
			name: "批量 requests 逐项提取",
			input: `{"requests":[{"url":"http://a.example.com/1"},{"url":"http://10.1.2.3:8080/x"},` +
				`{"url":"https://b.example.com/2","headers":{"Authorization":"Bearer x"}}]}`,
			domains: []string{"a.example.com", "b.example.com"},
			ips:     []string{"10.1.2.3"},
		},
		{
			name:    "template + matrix 代入后提取",
			input:   `{"template":{"url":"http://{sub}.example.com/p"},"matrix":[{"sub":"a"},{"sub":"b"}]}`,
			domains: []string{"a.example.com", "b.example.com"},
		},
		{
			name:    "template + range 代入后提取",
			input:   `{"template":{"url":"http://target.example.com/id/{id}"},"range":{"var":"id","from":1,"to":3}}`,
			domains: []string{"target.example.com"},
		},
		{
			name:    "matrix 变量落在 host 位 → 代入后提取",
			input:   `{"template":{"url":"http://{host}.example.com/p"},"matrix":[{"host":"a"}]}`,
			domains: []string{"a.example.com"},
		},
		{
			name:    "串行链 extract 回填变量在 host 位 → Opaque(已识别目标保留)",
			input:   `{"requests":[{"url":"http://login.example.com/api","extract":{"token":{"from":"body"}}},{"url":"http://{token}.example.com/x"}]}`,
			domains: []string{"login.example.com"},
			opaque:  true,
		},
		{
			name:    "变量只在路径位 → 提取 host 不 Opaque",
			input:   `{"url":"http://target.example.com/api?next={token}"}`,
			domains: []string{"target.example.com"},
		},
		{
			name:  "IPv6 与端口",
			input: `{"url":"http://[2001:db8::1]:8080/x"}`,
			ips:   []string{"2001:db8::1"},
		},
		{
			name:  "非法 JSON → 无目标(工具自身报错)",
			input: `not-json`,
		},
		{
			name:  "无 URL 字段 → 无目标",
			input: `{"method":"GET"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractHTTPProbeTargets([]byte(tc.input))
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

// TestFenceToolTargetsHTTPProbe 保证 http_probe 经统一入口拿到结构化目标,
// 而 WebFetch/Bash 维持各自口径。
func TestFenceToolTargetsHTTPProbe(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"url":    "http://probe.example.com/",
		"proxy":  "socks5://127.0.0.1:1080",
		"header": map[string]string{"X": "y"},
	})
	got := fenceToolTargets("http_probe", raw, "")
	if got.Opaque || !sameStrings(got.Domains, []string{"probe.example.com"}) {
		t.Fatalf("http_probe targets = %+v", got)
	}

	got = fenceToolTargets("WebFetch", []byte(`{"url":"https://fetch.example.com/x"}`), "")
	if !sameStrings(got.Domains, []string{"fetch.example.com"}) {
		t.Fatalf("WebFetch targets = %+v", got)
	}

	got = fenceToolTargets("Bash", []byte(`{"command":"curl -s http://bash.example.com"}`), "")
	if !sameStrings(got.Domains, []string{"bash.example.com"}) {
		t.Fatalf("Bash targets = %+v", got)
	}

	got = fenceToolTargets("Read", []byte(`{"path":"/etc/hosts"}`), "")
	if !got.empty() || got.Opaque {
		t.Fatalf("Read 应不参与围栏: %+v", got)
	}
}
