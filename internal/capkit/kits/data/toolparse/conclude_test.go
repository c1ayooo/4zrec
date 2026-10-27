package toolparse

import (
	"strings"
	"testing"
)

func TestParseConcludeOutputFencedJSON(t *testing.T) {
	text := "以下是收尾回执：\n```json\n" +
		`{"facts": [{"fact_key": "finding/tomcat-manager-exposed", "summary": "Tomcat 管理台暴露于 :8080", "body": "GET /manager/html 返回 401，默认凭据未验证", "confidence": "confirmed", "links": [{"from": "target/host-10.0.0.5", "type": "discovered_on"}]}], "residual": "凭据爆破未做完"}` +
		"\n```"
	env, err := ParseConcludeOutput(text)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(env.Facts) != 1 {
		t.Fatalf("facts 数量 = %d, 期望 1", len(env.Facts))
	}
	f := env.Facts[0]
	if f.Category != "finding" {
		t.Fatalf("category 应由 fact_key 前缀推导为 finding, 实得 %q", f.Category)
	}
	if f.Confidence != "confirmed" || len(f.Links) != 1 {
		t.Fatalf("confidence/links 丢失: %+v", f)
	}
	if env.Residual != "凭据爆破未做完" {
		t.Fatalf("residual 丢失: %q", env.Residual)
	}
}

func TestParseConcludeOutputBareObjectWithProse(t *testing.T) {
	text := "好的，系统注入的收尾指令收到。本轮增量如下 " +
		`{"facts": [{"fact_key": "auth/weak-password-admin", "summary": "admin 弱口令", "body": "admin/admin 登录成功（待复核）"}], "residual": ""}`
	env, err := ParseConcludeOutput(text)
	if err != nil {
		t.Fatalf("整段含散文时应能提取顶层对象: %v", err)
	}
	if len(env.Facts) != 1 {
		t.Fatalf("facts 数量 = %d, 期望 1", len(env.Facts))
	}
	if env.Facts[0].Confidence != "tentative" {
		t.Fatalf("confidence 缺省应补 tentative, 实得 %q", env.Facts[0].Confidence)
	}
	if env.Facts[0].Category != "auth" {
		t.Fatalf("category 推导失败: %q", env.Facts[0].Category)
	}
}

func TestParseConcludeOutputDropsInvalidKeepsValid(t *testing.T) {
	text := `{"facts": [
		{"fact_key": "无效键无斜杠", "summary": "x", "body": "x"},
		{"fact_key": "nosuch/xxx", "summary": "x", "body": "x"},
		{"fact_key": "infra/redis-open", "summary": "Redis 未授权", "body": "无密码可 PING"},
		{"fact_key": "finding/self-link", "summary": "x", "body": "x", "links": [{"from": "finding/self-link", "type": "discovered_on"}]}
	]}`
	env, err := ParseConcludeOutput(text)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(env.Facts) != 2 {
		t.Fatalf("应丢弃非法 category 与非法键，保留 2 条, 实得 %d", len(env.Facts))
	}
	if env.Facts[0].FactKey != "infra/redis-open" {
		t.Fatalf("首条应为合法事实, 实得 %q", env.Facts[0].FactKey)
	}
	if len(env.Facts[1].Links) != 0 {
		t.Fatalf("自指边应被 NormalizeFact 丢弃, 实得 %v", env.Facts[1].Links)
	}
}

func TestParseConcludeOutputEmptyFactsIsHonestAnswer(t *testing.T) {
	env, err := ParseConcludeOutput(`{"facts": [], "residual": "扫描刚开始就断了"}`)
	if err != nil {
		t.Fatalf("空 facts 是合法诚实回执: %v", err)
	}
	if len(env.Facts) != 0 || env.Residual != "扫描刚开始就断了" {
		t.Fatalf("空信封解析异常: %+v", env)
	}
}

func TestParseConcludeOutputCapsFactCount(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"facts": [`)
	for i := 0; i < ConcludeMaxFacts+10; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"fact_key": "infra/host-` + string(rune('a'+i%26)) + `-0", "summary": "s", "body": "b"}`)
	}
	b.WriteString(`]}`)
	env, err := ParseConcludeOutput(b.String())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(env.Facts) != ConcludeMaxFacts {
		t.Fatalf("应截断到 %d 条, 实得 %d", ConcludeMaxFacts, len(env.Facts))
	}
}

func TestParseConcludeOutputRejectsNonEnvelope(t *testing.T) {
	cases := []string{
		"",
		"没有 JSON 的纯文本总结。",
		`{"summary": "这不是信封"}`,
		`{"facts": [}`,
		"```json\n{\"unrelated\": true}\n```",
	}
	for _, c := range cases {
		if _, err := ParseConcludeOutput(c); err == nil {
			t.Fatalf("非信封输入应报错（fail-closed）: %q", c)
		}
	}
}

func TestParseConcludeOutputBracesInsideStrings(t *testing.T) {
	text := `前提说明 {"note": "body 里可能带 {花括号}"} 然后 {"facts": [{"fact_key": "chain/proxy-to-intranet", "summary": "s", "body": "b"}]}`
	env, err := ParseConcludeOutput(text)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 第一个顶层对象不含 "facts" 字段应被跳过，取到第二个
	if len(env.Facts) != 1 || env.Facts[0].FactKey != "chain/proxy-to-intranet" {
		t.Fatalf("应取含 facts 的对象: %+v", env)
	}
}

func TestConcludeFencedBlocksUnclosed(t *testing.T) {
	out := concludeFencedBlocks("```json\n{\"facts\": []")
	if len(out) != 1 {
		t.Fatalf("未闭合围栏按已有内容收: %v", out)
	}
}
