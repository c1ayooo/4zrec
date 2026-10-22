package vulnintel

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// pocFixture 是一条"情报里给了入口和判定特征"的情报 —— 只有这种才允许出 PoC。
func pocFixture() db.EnrichedVulnIntel {
	return db.EnrichedVulnIntel{
		VulnIntel: db.VulnIntel{
			ID:          77,
			Title:       "diem 项目 dmDataLoad.php 默认密码漏洞（CVE-2026-112030）",
			Description: "dmCorePlugin/lib/data/dmDataLoad.php 使用默认口令，攻击者可用 admin/admin 登录 cn_admin.php 管理页。",
			Severity:    "高危",
			CVE:         "CVE-2026-112030",
			Tags:        `["diem"]`,
		},
	}
}

// TestBuildPoCScriptFromSpec 验证要素齐备时产出的是**可运行**脚本:带真实入口、
// 真实参数、真实判定,而不是只有格式的空壳。
func TestBuildPoCScriptFromSpec(t *testing.T) {
	v := pocFixture()
	corpus := intelCorpus(v, nil)
	spec := pocSpec{
		Constructible: true,
		Method:        "POST",
		Path:          "/cn_admin.php",
		Params:        []pocParam{{Name: "user", Value: "admin"}, {Name: "pass", Value: "admin"}},
		Marker:        "dmDataLoad.php",
		MatchStatus:   200,
		Evidence:      "默认口令登录成功后进入管理页",
	}
	code, _, err := buildPoCScript(v, corpus, spec)
	if err != nil {
		t.Fatalf("buildPoCScript: %v", err)
	}
	for _, want := range []string{
		`PATH = "/cn_admin.php"`,
		`PARAMS = {"user": "admin", "pass": "admin"}`,
		`EXPECT_WORDS = ["dmDataLoad.php"]`,
		"EXPECT_STATUS = 200",
		"requests.post(",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("脚本缺少 %q:\n%s", want, code)
		}
	}
	if err := ValidatePoCScript(code); err != nil {
		t.Fatalf("自检未通过: %v", err)
	}
}

// TestBuildPoCScriptRejectsUngroundedPath 是这次修复的核心:模型编出来的入口
// 路径跑不通,必须拒绝而不是产出一个看着像样的脚本。
func TestBuildPoCScriptRejectsUngroundedPath(t *testing.T) {
	v := pocFixture()
	corpus := intelCorpus(v, nil)
	spec := pocSpec{
		Constructible: true,
		Method:        "GET",
		Path:          "/api/v2/internal/debug",
		Params:        []pocParam{{Name: "cmd", Value: "id"}},
		Marker:        "root:",
	}
	if _, _, err := buildPoCScript(v, corpus, spec); err == nil {
		t.Fatal("情报里没有出处的入口路径应被拒绝")
	}
}

// TestBuildPoCScriptRejectsNoJudgement 没有判定依据的请求验证不了任何漏洞。
func TestBuildPoCScriptRejectsNoJudgement(t *testing.T) {
	v := pocFixture()
	corpus := intelCorpus(v, nil)
	spec := pocSpec{
		Constructible: true,
		Method:        "GET",
		Path:          "/cn_admin.php",
		Params:        []pocParam{{Name: "a", Value: "1"}},
	}
	if _, _, err := buildPoCScript(v, corpus, spec); err == nil {
		t.Fatal("既无响应特征也无状态码时应拒绝")
	}
}

// TestBuildPoCScriptNotConstructible 要素不全时不留脚本,只留原因。
func TestBuildPoCScriptNotConstructible(t *testing.T) {
	v := pocFixture()
	spec := pocSpec{Constructible: false, Reason: "情报未给出插件入口与参数名"}
	code, note, err := buildPoCScript(v, intelCorpus(v, nil), spec)
	if err == nil || code != "" {
		t.Fatalf("不可构造时不应产出脚本: code=%q err=%v", code, err)
	}
	if note == "" {
		t.Fatal("应给出不可构造的原因")
	}
}

// TestPathGrounded 入口接地的判定:整段命中或文件名命中。
func TestPathGrounded(t *testing.T) {
	corpus := intelCorpus(pocFixture(), nil)
	if !pathGrounded(corpus, "/cn_admin.php") {
		t.Fatal("情报里出现的路径应判为接地")
	}
	if pathGrounded(corpus, "/totally/made/up.php") {
		t.Fatal("情报里没有的路径不应判为接地")
	}
}
