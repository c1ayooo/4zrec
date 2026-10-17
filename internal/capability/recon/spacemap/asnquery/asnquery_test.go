package asnquery

import (
	"strings"
	"testing"
)

func TestQueryFor(t *testing.T) {
	cases := []struct {
		engine string
		kind   KeyKind
		value  string
		want   string
		ok     bool
	}{
		{"quake", KindASN, "AS15169", `asn:"AS15169"`, true},
		{"fofa", KindASN, "AS15169", `asn="AS15169"`, true},
		{"fofa", KindCIDR, "15169.0.0.0/8", `net="15169.0.0.0/8"`, true},
		{"fofa", KindOrg, "Google Inc.", `org="Google Inc."`, true},
		{"zoomeye", KindASN, "AS15169", "asn=AS15169", true},
		{"hunter", KindASN, "AS15169", `ip.asn="AS15169"`, true},
		{"hunter", KindASN, "15169", `ip.asn="AS15169"`, true}, // 纯数字自动补 AS 前缀
		{"shodan", KindASN, "AS15169", "", false},              // shodan 无直接 ASN 语法
		{"shodan", KindOrg, "Google", "", false},
		{"unknown-engine", KindASN, "AS1", "", false},
	}
	for _, c := range cases {
		got, ok := QueryFor(c.engine, c.kind, c.value)
		if ok != c.ok || got != c.want {
			t.Errorf("QueryFor(%s, %s, %s) = (%q, %v), want (%q, %v)",
				c.engine, c.kind, c.value, got, ok, c.want, c.ok)
		}
	}
}

func TestSupportedEngines(t *testing.T) {
	got := strings.Join(SupportedEngines(), ",")
	for _, want := range []string{"quake", "fofa", "zoomeye", "hunter"} {
		if !strings.Contains(got, want) {
			t.Errorf("SupportedEngines 缺少 %s: %s", want, got)
		}
	}
	if strings.Contains(got, "shodan") {
		t.Errorf("shodan 不应在支持列表: %s", got)
	}
}

func TestHostsFromRow(t *testing.T) {
	row := map[string]interface{}{
		"ip": "8.8.8.8, 8.8.4.4; 1.1.1.1",
	}
	hosts := HostsFromRow("fofa", row)
	if len(hosts) != 3 {
		t.Fatalf("应提取 3 个 IP: %v", hosts)
	}
}

func TestDomainsFromRow(t *testing.T) {
	row := map[string]interface{}{
		"host": "https://www.example.com:443/path",
	}
	domains := DomainsFromRow("fofa", row)
	if len(domains) != 1 || domains[0] != "www.example.com" {
		t.Fatalf("域名归一化失败: %v", domains)
	}
}
