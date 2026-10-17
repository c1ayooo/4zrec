package server

import "testing"

// TestIsNoiseSpacemapIP 公共测绘导入的噪音过滤:公共 DNS/基础设施、私网/回环、
// 组播/链路本地、保留/文档/基准网段必须丢弃;真实公网目标保留。
func TestIsNoiseSpacemapIP(t *testing.T) {
	noise := []string{
		"1.1.1.1", "8.8.8.8", "114.114.114.114", "223.5.5.5",
		"2001:4860:4860::8888", "2606:4700:4700::1111",
		"127.0.0.1", "::1", "0.0.0.0", "10.1.2.3", "172.16.0.1", "192.168.1.1",
		"169.254.1.1", "224.0.0.1", "192.0.2.10", "198.51.100.7", "203.0.113.9",
		"198.18.0.1", "240.0.0.1", "255.255.255.255",
	}
	for _, ip := range noise {
		if !isNoiseSpacemapIP(ip) {
			t.Errorf("%s 应判定为噪音", ip)
		}
	}
	real := []string{"47.98.195.217", "23.145.232.82", "101.47.12.205", "www.huya.com"}
	for _, ip := range real {
		if isNoiseSpacemapIP(ip) {
			t.Errorf("%s 不应判定为噪音", ip)
		}
	}
	// 域名(非 IP)永不按 IP 噪音处理。
	if isNoiseSpacemapIP("example.com") {
		t.Error("域名不应被 IP 噪音过滤器命中")
	}
}
