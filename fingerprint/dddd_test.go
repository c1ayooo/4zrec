package fingerprint

import (
	"strings"
	"testing"
)

func TestDdddPreescape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"无反斜杠原样返回", `server="nginx" && title="后台管理"`, `server="nginx" && title="后台管理"`},
		// 正则转义翻倍：tokenizer 还原后值中仍是 \b
		{"正则词边界", `body~="\b(shpss_[a-f0-9]{32})\b"`, `body~="\\b(shpss_[a-f0-9]{32})\\b"`},
		{"点号转义", `body~="a\.b"`, `body~="a\\.b"`},
		// 引号转义是 tokenizer 原生语法，保持单反斜杠
		{"引号转义保留", `body="id=\"serverinfo\"> PowerEdge R420"`, `body="id=\"serverinfo\"> PowerEdge R420"`},
		// 混合：同一表达式两类转义并存
		{"混合转义", `body~="\b secret \" key \."`, `body~="\\b secret \" key \\."`},
	}
	for _, c := range cases {
		if got := ddddPreescape(c.in); got != c.want {
			t.Fatalf("%s: ddddPreescape(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestParseDdddFinger(t *testing.T) {
	yamlData := []byte(`Nginx:
  - 'server="nginx"'
极限OA:
  - 'title="极限OA"'
  - 'body="seeyon"'
BadRule:
  - 'unknownfield="x"'
EmptyRule: []
RegexEscape:
  - 'body~="\b(shpss_[a-fA-F0-9]{32})\b"'
`)
	rules, stats, err := ParseDdddFinger(yamlData)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("应 3 条规则(极限OA 两条表达式合并), got %d", len(rules))
	}
	byName := map[string]Rule{}
	for _, r := range rules {
		byName[r.Name] = r
	}

	// 中文产品名 + 多表达式 (e1) || (e2) 合并
	oa, ok := byName["极限OA"]
	if !ok {
		t.Fatalf("中文产品名规则缺失: %v", byName)
	}
	if oa.Expression != `(title="极限OA") || (body="seeyon")` {
		t.Fatalf("多表达式应 (e1) || (e2) 合并: %s", oa.Expression)
	}
	if oa.Source != SourceDddd || oa.Category != SourceDddd || !oa.Enabled {
		t.Fatalf("来源/类别/启用态异常: %+v", oa)
	}

	// 非法字段表达式跳过并计数，不阻断整体（BadRule 同时计入 patterns 与
	// technologies 两项跳过，语义与 wappalyzer 翻译器一致；EmptyRule 计 technologies）
	if stats.PatternsSkipped != 1 || stats.TechnologiesSkipped != 2 {
		t.Fatalf("跳过统计异常: %+v", stats)
	}
	if len(stats.SkipSamples) != 1 || !strings.Contains(stats.SkipSamples[0], "BadRule") {
		t.Fatalf("跳过样本应含 BadRule: %v", stats.SkipSamples)
	}

	// \b 词边界穿过 tokenizer 后仍是正则词边界（而非字母 b）
	re, ok := byName["RegexEscape"]
	if !ok {
		t.Fatalf("正则转义规则缺失")
	}
	if !strings.Contains(re.Expression, `\b`) {
		t.Fatalf("\\b 转义应原样保留在表达式中: %s", re.Expression)
	}
	parsed, err := ParseExpression(re.Expression)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Eval(&Observation{Body: "token shpss_0123456789abcdefABCDEF0123456789 end"}) {
		t.Fatalf("词边界应命中空格分隔的密钥")
	}
	if parsed.Eval(&Observation{Body: "xshpss_0123456789abcdefABCDEF0123456789y"}) {
		t.Fatalf("词边界不应命中被字母包裹的串")
	}
}

// TestParseDdddFingerRealSnapshot 解析真实出厂快照（snapshots/dddd-finger.yaml）：
// 全量 7800+ 条应几乎全部可翻译（语料字段均在 knownFields 内），任一规则表达式
// 都能过 ParseExpression。
func TestParseDdddFingerRealSnapshot(t *testing.T) {
	if len(ddddSnapshotYAML) == 0 {
		t.Fatal("内置快照为空")
	}
	rules, stats, err := ParseDdddFinger(ddddSnapshotYAML)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TechnologiesTotal < 7000 {
		t.Fatalf("快照产品数异常: %d", stats.TechnologiesTotal)
	}
	if len(rules) < 7000 {
		t.Fatalf("可翻译规则数异常: %d (skipped=%d)", len(rules), stats.TechnologiesSkipped)
	}
	if stats.TechnologiesSkipped+stats.PatternsSkipped > 20 {
		t.Fatalf("跳过过多，疑似翻译器缺陷: %+v 样本=%v", stats, stats.SkipSamples)
	}
	byName := map[string]bool{}
	for _, r := range rules {
		byName[r.Name] = true
		if r.Source != SourceDddd {
			t.Fatalf("来源应为 dddd: %+v", r)
		}
	}
	for _, want := range []string{"Nginx", "MacOS"} {
		if !byName[want] {
			t.Fatalf("已知产品 %s 应在快照中", want)
		}
	}
}
