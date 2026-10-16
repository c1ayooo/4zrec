package certquery

import (
	"reflect"
	"testing"
)

func TestOrgQuerySyntaxPerEngine(t *testing.T) {
	cases := []struct {
		engine string
		want   string
		mode   MatchMode
	}{
		{"fofa", `cert.subject.org="Oracle Corporation"`, MatchExact},
		{"hunter", `cert.subject="Oracle Corporation"`, MatchExact},
		{"shodan", `ssl.cert.subject.O:"Oracle Corporation"`, MatchExact},
		{"quake", `cert:"Oracle Corporation"`, MatchContent},
		{"zoomeye", `ssl="Oracle Corporation"`, MatchContent},
	}
	for _, c := range cases {
		cap := Get(c.engine)
		if cap == nil || cap.OrgQuery == nil {
			t.Fatalf("%s 未注册或无 OrgQuery", c.engine)
		}
		if cap.MatchMode != c.mode {
			t.Errorf("%s MatchMode = %s; want %s", c.engine, cap.MatchMode, c.mode)
		}
		got, ok := QueryFor(c.engine, "Oracle Corporation")
		if !ok || got != c.want {
			t.Errorf("QueryFor(%s) = %q,%v; want %q,true", c.engine, got, ok, c.want)
		}
	}
	// 未知引擎
	if _, ok := QueryFor("censys", "Oracle Corporation"); ok {
		t.Error("未知引擎应不支持")
	}
}

func TestEngineSets(t *testing.T) {
	if got := SupportedEngines(); !reflect.DeepEqual(got, []string{"fofa", "hunter", "shodan", "quake", "zoomeye"}) {
		t.Errorf("SupportedEngines = %v（精确引擎应在前）", got)
	}
	if got := ExactEngines(); !reflect.DeepEqual(got, []string{"fofa", "hunter", "shodan"}) {
		t.Errorf("ExactEngines = %v", got)
	}
	if got := AllEngines(); !reflect.DeepEqual(got, []string{"fofa", "hunter", "shodan", "quake", "zoomeye"}) {
		t.Errorf("AllEngines = %v", got)
	}
}

func TestNormalizeOrg(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"  Oracle   Corporation ", "Oracle Corporation"}, // 折叠连续空白
		{"Oracle Corporation", "Oracle Corporation"},
		{"腾讯云计算（北京）有限责任公司", "腾讯云计算（北京）有限责任公司"},
		{"", ""},
		{"  ", ""},
		{"ab", ""}, // 过短（<3 rune）
		{"某某", ""}, // 中文同样过短
	}
	for _, c := range cases {
		if got := NormalizeOrg(c.raw); got != c.want {
			t.Errorf("NormalizeOrg(%q) = %q; want %q", c.raw, got, c.want)
		}
	}
}

func TestGenericOrgBlacklist(t *testing.T) {
	for _, org := range []string{
		"Cloudflare, Inc.", "cloudflare inc", "Google LLC", "google inc.",
		"Microsoft Corporation", "Amazon", "Amazon.com, Inc.", "Cisco", "Cisco Systems, Inc.",
		"F5 Networks, Inc.", "Fortinet, Inc.", "Siemens", "Synology Inc.",
	} {
		if !GenericOrg(org) {
			t.Errorf("GenericOrg(%q) = false; 应命中黑名单（大小写不敏感）", org)
		}
	}
	for _, org := range []string{
		"Oracle Corporation", "腾讯云计算（北京）有限责任公司", "Xiamen Superior Industry Co., Ltd.",
	} {
		if GenericOrg(org) {
			t.Errorf("GenericOrg(%q) = true; 正常主体不应误拦", org)
		}
	}
	// 未归一的输入（多空白）也应命中
	if !GenericOrg("  Cisco   Systems, Inc. ") {
		t.Error("多空白输入应先归一再比对")
	}
}

func TestCapabilitySummaryShape(t *testing.T) {
	summary := CapabilitySummary()
	if len(summary) != 5 {
		t.Fatalf("CapabilitySummary 引擎数 = %d; want 5", len(summary))
	}
	for _, item := range summary {
		engine, _ := item["engine"].(string)
		org, ok := item["org"].(string)
		if !ok || org == "" {
			t.Errorf("%s 缺 org 能力描述", engine)
		}
		mode, ok := item["match_mode"].(string)
		if !ok || mode == "" {
			t.Errorf("%s 缺 match_mode", engine)
		}
	}
}
