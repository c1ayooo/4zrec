package vulnintel

import (
	"testing"
)

func TestExtractJSONObject(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain json",
			in:   `{"title_zh":"x"}`,
			want: `{"title_zh":"x"}`,
		},
		{
			name: "fenced json",
			in:   "```json\n{\"a\":1}\n```",
			want: `{"a":1}`,
		},
		{
			name: "with prose around",
			in:   `好的，结果如下：{"a":1} 以上。`,
			want: `{"a":1}`,
		},
		{
			// PoC 代码里满是花括号与引号,必须靠字符串态跳过,否则会提前收尾。
			name: "braces inside string value",
			in:   `{"poc":{"code":"def f():\n    return {\"k\": '}'}\n"}}`,
			want: `{"poc":{"code":"def f():\n    return {\"k\": '}'}\n"}}`,
		},
		{
			name: "escaped quote inside string",
			in:   `{"a":"he said \"}\" ok"}`,
			want: `{"a":"he said \"}\" ok"}`,
		},
		{
			name: "no object",
			in:   `没有 JSON`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractJSONObject(tc.in); got != tc.want {
				t.Fatalf("extractJSONObject() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUnmarshalLooseAnalysis(t *testing.T) {
	// 典型模型输出:代码块包裹 + PoC 里的花括号与转义。
	raw := "```json\n" + `{
  "title_zh": "某某系统远程代码执行漏洞",
  "description_zh": "该漏洞允许未授权攻击者执行任意代码。",
  "principle": "参数未经校验即传入 eval。",
  "attack_scope": "1.0 至 1.4 版本",
  "poc_spec": {"constructible": true, "method": "GET", "path": "/api/x", "params": [{"name": "a", "value": "{"}], "marker": "syntax error", "match_status": 500}
}` + "\n```"
	var out intelAnalysisOut
	if err := unmarshalLoose(raw, &out); err != nil {
		t.Fatalf("unmarshalLoose: %v", err)
	}
	if out.TitleZh == "" || out.Principle == "" || out.AttackScope == "" {
		t.Fatalf("字段缺失: %+v", out)
	}
	if out.PocSpec == nil || !out.PocSpec.Constructible {
		t.Fatalf("验证要素未解析: %+v", out.PocSpec)
	}
	if out.PocSpec.Path != "/api/x" || len(out.PocSpec.Params) != 1 {
		t.Fatalf("验证要素字段缺失: %+v", out.PocSpec)
	}
}

func TestUnmarshalLooseRejectsGarbage(t *testing.T) {
	var out intelAnalysisOut
	if err := unmarshalLoose("模型拒绝回答", &out); err == nil {
		t.Fatal("期望报错,实际通过")
	}
}

func TestNeedsLocalization(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"english long", "Apache Struts2 remote code execution via OGNL injection", true},
		{"chinese long", "Apache Struts2 远程代码执行漏洞，攻击者可构造 OGNL 表达式", false},
		{"mixed mostly chinese", "某系统存在反序列化漏洞 deserialization issue in Java", false},
		{"too short", "CVE-2024-1234", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsLocalization(tc.in); got != tc.want {
				t.Fatalf("needsLocalization(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestJoinJSONList(t *testing.T) {
	got := joinJSONList(`["rce","xss"]`, `["npm/foo","rce"]`)
	if got != "rce, xss, npm/foo" {
		t.Fatalf("joinJSONList = %q", got)
	}
	if got := joinJSONList("not json", ""); got != "" {
		t.Fatalf("非法输入应返回空,得到 %q", got)
	}
}

func TestHasUpstreamPoc(t *testing.T) {
	if hasUpstreamPoc("[]") {
		t.Fatal("空数组不应判定为有上游 PoC")
	}
	if hasUpstreamPoc("") {
		t.Fatal("空串不应判定为有上游 PoC")
	}
	if !hasUpstreamPoc(`[{"full_name":"a/b","url":"https://x","stars":1}]`) {
		t.Fatal("非空数组应判定为有上游 PoC")
	}
}
