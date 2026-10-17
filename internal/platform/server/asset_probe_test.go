package server

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// TestOwnershipHints 归属线索:证书 SAN/PTR 命中项目授权域,或与资产同根域。
func TestOwnershipHints(t *testing.T) {
	rules := []db.ProjectScope{{ID: 1, Kind: "domain", Domain: "huya.com"}}
	asset := &db.Asset{Type: "ip", IP: "203.0.113.10"}
	hints := ownershipHints(asset, rules,
		[]string{"ec2-203-0-113-10.compute.amazonaws.com"},
		[]string{"www.huya.com", "cdn.huya.com"})
	joined := strings.Join(hints, " | ")
	if !strings.Contains(joined, "证书 SAN 含授权域 huya.com") {
		t.Fatalf("证书 SAN 命中授权域应产生线索: %v", hints)
	}
	if strings.Contains(joined, "PTR") {
		t.Fatalf("不相关的 PTR 不应产生归属线索: %v", hints)
	}

	// 同根域线索(资产自身 root_domain)。
	asset2 := &db.Asset{Type: "subdomain", Domain: "api.huya.com", RootDomain: "huya.com"}
	hints2 := ownershipHints(asset2, nil, []string{"cdn.huya.com"}, nil)
	if !strings.Contains(strings.Join(hints2, " | "), "PTR cdn.huya.com 与资产同根域") {
		t.Fatalf("同根域 PTR 应产生线索: %v", hints2)
	}
}

// TestAssetProbeHost 主机/scheme/端口提取。
func TestAssetProbeHost(t *testing.T) {
	cases := []struct {
		a      db.Asset
		host   string
		scheme string
		port   int
	}{
		{db.Asset{IP: "1.2.3.4"}, "1.2.3.4", "", 0},
		{db.Asset{Domain: "sub.example.com"}, "sub.example.com", "", 0},
		{db.Asset{URL: "https://api.example.com:8443/x"}, "api.example.com", "https", 8443},
		{db.Asset{URL: "http://example.com/"}, "example.com", "http", 80},
	}
	for _, tc := range cases {
		host, scheme, port := assetProbeHost(&tc.a)
		if host != tc.host || scheme != tc.scheme || port != tc.port {
			t.Errorf("assetProbeHost(%+v) = %q %q %d", tc.a, host, scheme, port)
		}
	}
}
