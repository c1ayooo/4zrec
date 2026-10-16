package takeover

import "testing"

func TestMatchFingerprint(t *testing.T) {
	cases := []struct {
		cname string
		want  string // 期望 Service；空 = 不命中
	}{
		{"shop.example.com.github.io", "github_pages"},
		{"user.github.io", "github_pages"},
		{"app-strong-fox.herokuapp.com", "heroku"},
		{"bucket.s3.amazonaws.com", "aws_s3"},
		{"data.blob.core.windows.net", "azure_blob"},
		{"site.gitee.io", "gitee_pages"},
		{"www.example.com", ""},
		{"docs.google.com", ""},
		{"", ""},
	}
	for _, c := range cases {
		fp := MatchFingerprint(c.cname)
		if c.want == "" {
			if fp != nil {
				t.Fatalf("MatchFingerprint(%q) 不应命中, got %s", c.cname, fp.Service)
			}
			continue
		}
		if fp == nil {
			t.Fatalf("MatchFingerprint(%q) 应命中 %s", c.cname, c.want)
		}
		if fp.Service != c.want {
			t.Fatalf("MatchFingerprint(%q) = %s, want %s", c.cname, fp.Service, c.want)
		}
	}
}

func TestDetectNXDomainClass(t *testing.T) {
	f := Detect(Candidate{Subdomain: "old.example.com", CNAME: "gone.blob.core.windows.net", TargetNXDomain: true})
	if f == nil {
		t.Fatal("悬挂 CNAME + NXDomain 类指纹应命中")
	}
	if f.Service != "azure_blob" {
		t.Fatalf("服务判定: %s", f.Service)
	}
	// 目标还活着（无 NXDOMAIN 证据）时不得按 NXDomain 类误报
	if f := Detect(Candidate{Subdomain: "old.example.com", CNAME: "gone.blob.core.windows.net"}); f != nil {
		t.Fatal("无目标侧证据时 NXDomain 类指纹不应告警")
	}
}

func TestDetectBodyClass(t *testing.T) {
	f := Detect(Candidate{
		Subdomain: "docs.example.com", CNAME: "org.github.io",
		TargetStatus: 404, TargetBody: "<html>... There isn't a GitHub Pages site here. ...</html>",
	})
	if f == nil {
		t.Fatal("GitHub Pages 特征页应命中")
	}
	if f.Service != "github_pages" {
		t.Fatalf("服务判定: %s", f.Service)
	}
	// 指纹命中但 body 无特征：不告警
	if f := Detect(Candidate{Subdomain: "docs.example.com", CNAME: "org.github.io", TargetStatus: 200, TargetBody: "<html>正常页面</html>"}); f != nil {
		t.Fatal("正常页面不应告警")
	}
	// 指纹命中但完全没有目标侧观测：不告警（证据不足宁可漏报）
	if f := Detect(Candidate{Subdomain: "docs.example.com", CNAME: "org.github.io"}); f != nil {
		t.Fatal("无观测不应告警")
	}
}

func TestDetectUnrelated(t *testing.T) {
	if f := Detect(Candidate{Subdomain: "a.example.com", CNAME: "b.example.com", TargetNXDomain: true}); f != nil {
		t.Fatal("CNAME 不在指纹表不应命中")
	}
}
