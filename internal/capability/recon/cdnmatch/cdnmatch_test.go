package cdnmatch

import "testing"

func TestClassifyByCNAMESuffix(t *testing.T) {
	cases := []struct {
		cname    string
		wantType string
		wantName string
	}{
		{"example.com.cdn.cloudflare.net", "cdn", "Cloudflare"},
		{"d111111abcdef8.cloudfront.net", "cdn", "CloudFront"},
		{"www.example.com.edgekey.net", "cdn", "Akamai"},
		{"example.com.aliyunwaf.com", "waf", "阿里云 WAF"},
		{"example.com.w.kunlungr.com", "cdn", "阿里云 CDN"},
		{"example.amazonaws.com", "cloud", "AWS"},
	}
	for _, c := range cases {
		got := Classify(c.cname, nil)
		if got.EdgeType != c.wantType || got.EdgeName != c.wantName {
			t.Fatalf("Classify(%q) = %+v, want %s/%s", c.cname, got, c.wantType, c.wantName)
		}
	}
}

func TestClassifyByIP(t *testing.T) {
	// 104.16.132.229 在 Cloudflare 段
	got := Classify("", []string{"104.16.132.229"})
	if got.EdgeType != "cdn" || got.EdgeName != "Cloudflare" {
		t.Fatalf("Cloudflare IP 段未命中: %+v", got)
	}
	// 普通公网 IP 不命中
	if got := Classify("", []string{"114.114.114.114"}); got.EdgeType != "" {
		t.Fatalf("普通 IP 不应命中: %+v", got)
	}
}

func TestClassifyLocal(t *testing.T) {
	if got := Classify("", nil); got.EdgeType != "" {
		t.Fatalf("空输入应返回零值: %+v", got)
	}
	if got := Classify("www.example.com", []string{"93.184.216.34"}); got.EdgeType != "" {
		t.Fatalf("无 CDN 特征应返回零值: %+v", got)
	}
}

func TestClassifyCNAMEWinsOverIP(t *testing.T) {
	// CNAME 品牌后缀优先于 IP 段（同为 Cloudflare 时只看类型一致性）
	got := Classify("example.com.edgekey.net", []string{"104.16.132.229"})
	if got.EdgeName != "Akamai" {
		t.Fatalf("CNAME 应优先: %+v", got)
	}
}
