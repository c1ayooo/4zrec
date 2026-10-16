package score

import "testing"

func TestComputeEmpty(t *testing.T) {
	value, level, factors := Compute(Input{})
	if value != 0 || level != "p4" || len(factors) != 0 {
		t.Fatalf("空输入应为 0 分 p4 零因子: got %d %s %v", value, level, factors)
	}
}

func TestComputeHighRiskPort(t *testing.T) {
	value, level, factors := Compute(Input{OpenPorts: []int{3389, 80}, HTTPSeen: true})
	if value == 0 {
		t.Fatal("RDP 暴露应计分")
	}
	found := false
	for _, f := range factors {
		if f.Factor == "exposure" && f.Points >= 18 {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少 exposure 因子或分值不足: %+v", factors)
	}
	if level == "" {
		t.Fatal("级别不能为空")
	}
}

func TestComputeCriticalVuln(t *testing.T) {
	value, _, factors := Compute(Input{VulnSeverity: 5, VulnCount: 2})
	// vuln 25 + business(有漏洞观测→影子资产 +3) = 28
	if value != 28 {
		t.Fatalf("critical 漏洞应得 28 分: got %d", value)
	}
	vulnPts := 0
	for _, f := range factors {
		if f.Factor == "vuln" {
			vulnPts = f.Points
		}
	}
	if vulnPts != 25 {
		t.Fatalf("vuln 因子应为 25: %+v", factors)
	}
}

func TestComputeBusinessAndShadow(t *testing.T) {
	// 核心(7) + 影子(3) = 10（维度预算封顶）
	value, _, _ := Compute(Input{Criticality: "核心", HasOwner: false})
	if value != 10 {
		t.Fatalf("核心+影子应得 10 分: got %d", value)
	}
	// 无任何观测的空输入不因影子凭空得分
	empty, _, factors := Compute(Input{})
	if empty != 0 || len(factors) != 0 {
		t.Fatalf("空输入应为 0 分: got %d %+v", empty, factors)
	}
}

func TestComputeWildcardHalving(t *testing.T) {
	base := Input{OpenPorts: []int{3389}, VulnSeverity: 5, VulnCount: 1}
	cleanScore, _, _ := Compute(base)
	wildcardScore, _, factors := Compute(func() Input {
		in := base
		in.IsWildcard = true
		return in
	}())
	if wildcardScore > (cleanScore+1)/2 {
		t.Fatalf("泛解析命中应减半: clean=%d wildcard=%d", cleanScore, wildcardScore)
	}
	hasAdjust := false
	for _, f := range factors {
		if f.Factor == "wildcard" && f.Points < 0 {
			hasAdjust = true
		}
	}
	if !hasAdjust {
		t.Fatalf("缺少 wildcard 调节因子: %+v", factors)
	}
}

func TestComputeTLSDims(t *testing.T) {
	value, _, factors := Compute(Input{CertExpired: true, CertSelfSigned: true, HasOwner: true})
	if value != 10 {
		t.Fatalf("过期+自签应得 10 分: got %d", value)
	}
	found := false
	for _, f := range factors {
		if f.Factor == "tls" {
			found = true
		}
	}
	if !found {
		t.Fatal("缺少 tls 因子")
	}
}

func TestComputeHygiene(t *testing.T) {
	value, _, _ := Compute(Input{
		HTTPSeen:               true,
		HTTPStatus:             200,
		HasOwner:               true,
		MissingSecurityHeaders: []string{"strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options"},
		DirectoryListing:       true,
		DefaultPage:            true,
	})
	// 目录列表 8 + 头缺失 4（cap）+ 默认页 2 = 14 → cap 10
	if value > 10 {
		t.Fatalf("Web 卫生维度应封顶 10: got %d", value)
	}
}

func TestLevelBoundaries(t *testing.T) {
	cases := map[int]string{
		0: "p4", 14: "p4", 15: "p3", 39: "p3", 40: "p2", 59: "p2",
		60: "p1", 79: "p1", 80: "p0", 100: "p0",
	}
	for score, want := range cases {
		if got := Level(score); got != want {
			t.Fatalf("Level(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestServiceRiskCap(t *testing.T) {
	// jenkins(16) + weblogic(16) + 多产品 +4 = 36 → cap 20
	value, _, factors := Compute(Input{Server: "Jenkins WebLogic", HTTPSeen: true})
	if value > 20+25 { // service 20 + exposure 上限 25
		t.Fatalf("评分异常: %d", value)
	}
	servicePts := 0
	for _, f := range factors {
		if f.Factor == "service" {
			servicePts = f.Points
		}
	}
	if servicePts != 20 {
		t.Fatalf("service 维度应封顶 20: got %d", servicePts)
	}
}

func TestAdminConsoleFactor(t *testing.T) {
	// 强标记:管理后台标题直接计分
	s, _, factors := Compute(Input{Title: "XX 运维管理后台", HTTPSeen: true, OpenPorts: []int{443}})
	found := false
	for _, f := range factors {
		if f.Factor == "admin_console" && f.Points > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("管理后台标题应命中 admin_console 因子, got factors=%v", factors)
	}
	_ = s

	// 弱标记单独出现不计(防营销页 login 误报)
	_, _, factors = Compute(Input{Title: "Login to shop", HTTPSeen: true})
	for _, f := range factors {
		if f.Factor == "admin_console" {
			t.Fatalf("弱标记单独不应计分: %v", f)
		}
	}

	// 上限 12
	_, _, factors = Compute(Input{Title: "管理后台 控制台 dashboard console admin login", HTTPSeen: true})
	for _, f := range factors {
		if f.Factor == "admin_console" && f.Points > 12 {
			t.Fatalf("admin_console 应封顶 12, got %d", f.Points)
		}
	}
}

func TestRiskyProductDictAdminConsoles(t *testing.T) {
	for _, kw := range []string{"dolphinscheduler", "apisix", "kubernetes-dashboard", "xxl-job"} {
		pts, hits := serviceRiskPoints(Input{Fingerprints: []string{kw}})
		if pts < 8 || len(hits) == 0 {
			t.Fatalf("%s 应命中高风险产品字典(≥8pt), got pts=%d hits=%v", kw, pts, hits)
		}
	}
}

func TestSuccessSignalPriorFactor(t *testing.T) {
	// 命中两族（admin-console 6 + debug-endpoint 6 = 12 → 封顶 10）
	s, _, factors := Compute(Input{Paths: []string{"/admin/login", "/actuator/env"}})
	found := false
	for _, f := range factors {
		if f.Factor == "success_signal" {
			found = true
			if f.Points != 10 {
				t.Fatalf("success_signal 应封顶 10, got %d", f.Points)
			}
		}
	}
	if !found {
		t.Fatalf("路径族命中应产生 success_signal 因子, factors=%v", factors)
	}
	if s < 10 {
		t.Fatalf("总分应含先验分, got %d", s)
	}

	// 无命中不产生因子、不加分
	s2, _, factors2 := Compute(Input{Paths: []string{"/index.html", "/static/app.js"}})
	for _, f := range factors2 {
		if f.Factor == "success_signal" {
			t.Fatalf("无命中不应产生因子: %v", f)
		}
	}
	if s2 != 0 {
		t.Fatalf("纯路径无其他观测不应得分, got %d", s2)
	}

	// 空/nil 路径安全
	_, _, factors3 := Compute(Input{})
	for _, f := range factors3 {
		if f.Factor == "success_signal" {
			t.Fatalf("nil 路径不应产生因子: %v", f)
		}
	}
}
