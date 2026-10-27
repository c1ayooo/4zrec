package payload

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestVariantsRender 各语言 × 各变体可渲染，模板 ID 反映变体。
func TestVariantsRender(t *testing.T) {
	for _, st := range []ShellType{ShellPHP, ShellASP, ShellASPX, ShellJSP} {
		for _, v := range []Variant{VariantPlain, VariantLite, VariantEnc} {
			if v == VariantEnc && st != ShellPHP {
				continue // enc 仅 PHP 支持
			}
			p, err := Generate(Options{ShellType: st, Password: "pw123", Variant: v})
			if err != nil {
				t.Fatalf("%s/%s: %v", st, v, err)
			}
			if p.Variant != v {
				t.Errorf("%s/%s: payload.Variant = %s", st, v, p.Variant)
			}
			if p.TemplateID == "" {
				t.Errorf("%s/%s: templateID 为空", st, v)
			}
			if v != VariantPlain && !strings.Contains(p.TemplateID, string(v)) {
				t.Errorf("%s/%s: templateID 未标变体: %s", st, v, p.TemplateID)
			}
		}
	}
}

// TestVariantLiteNoStructuralSignature lite 变量随机化：两次生成的变量名不同（打散固定特征）。
func TestVariantLiteNoStructuralSignature(t *testing.T) {
	p1, err := Generate(Options{ShellType: ShellPHP, Password: "abc", Variant: VariantLite})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Generate(Options{ShellType: ShellPHP, Password: "abc", Variant: VariantLite})
	if err != nil {
		t.Fatal(err)
	}
	if string(p1.Content) == string(p2.Content) {
		t.Error("两次 lite 生成内容不应完全一致（随机化失效）")
	}
	// 密码必须保留（行为等价：仍按 pass 参数校验）
	if !strings.Contains(string(p1.Content), "abc") {
		t.Error("lite 模板丢失密码校验")
	}
}

// TestVariantEncHidesDangerousLiterals enc 变体核心性质：
// eval/system/base64_decode/passthru/shell_exec 及密码、命令参数名不得以明文出现。
func TestVariantEncHidesDangerousLiterals(t *testing.T) {
	p, err := Generate(Options{ShellType: ShellPHP, Password: "s3cret_pw", CmdParam: "cm9", Variant: VariantEnc})
	if err != nil {
		t.Fatal(err)
	}
	content := string(p.Content)
	for _, lit := range []string{"eval", "system", "base64_decode", "passthru", "shell_exec", "s3cret_pw", "cm9", "$_REQUEST"} {
		if strings.Contains(content, lit) {
			t.Errorf("enc 模板泄露明文 %q", lit)
		}
	}
	// 解码链自洽：取出 strrev(base64) 的载荷，反解回 inner，应含密码校验与 system 分发
	b64Start := strings.Index(content, "'") + 1
	b64End := strings.Index(content[b64Start:], "'")
	if b64End < 0 {
		t.Fatal("enc 模板缺载荷")
	}
	raw, derr := base64.StdEncoding.DecodeString(content[b64Start : b64Start+b64End])
	if derr != nil {
		t.Fatalf("载荷 base64 解码失败: %v", derr)
	}
	inner := reverseString(string(raw))
	if !strings.Contains(inner, "s3cret_pw") || !strings.Contains(inner, "system") {
		t.Error("解码后的执行体不含密码校验/命令执行（链路断裂）")
	}
}

// TestVariantLiteJSPBalance jsp lite 模板 scriptlet 花括号/引号完整性（历史 bug：数组初始化多一层花括号）。
func TestVariantLiteJSPBalance(t *testing.T) {
	p, err := Generate(Options{ShellType: ShellJSP, Password: "x1", Variant: VariantLite})
	if err != nil {
		t.Fatal(err)
	}
	c := string(p.Content)
	if strings.Count(c, "{") != strings.Count(c, "}") {
		t.Error("jsp lite 花括号不配对")
	}
	if strings.Contains(c, "{{{") {
		t.Error("jsp lite 数组初始化存在三层花括号")
	}
}

// TestVariantASPLiteClosing asp lite 结束标签连续（%%> 转义回归）。
func TestVariantASPLiteClosing(t *testing.T) {
	p, err := Generate(Options{ShellType: ShellASP, Password: "x1", Variant: VariantLite})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(p.Content), "%>") || strings.Contains(string(p.Content), "%\n>") {
		t.Error("asp lite 结束标签异常")
	}
}

// TestNormalizeVariant 空值默认 plain，未知值报错。
func TestNormalizeVariant(t *testing.T) {
	if v, _ := NormalizeVariant(""); v != VariantPlain {
		t.Errorf("空值应默认 plain, got %s", v)
	}
	if v, _ := NormalizeVariant(" LITE "); v != VariantLite {
		t.Errorf("NormalizeVariant(lite) = %s", v)
	}
	if _, err := NormalizeVariant("magic"); err == nil {
		t.Error("未知变体应报错")
	}
}
