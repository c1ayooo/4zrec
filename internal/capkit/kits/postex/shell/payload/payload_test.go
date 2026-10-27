package payload

import (
	"strings"
	"testing"
)

func TestGenerateAllShellTypes(t *testing.T) {
	for _, st := range []ShellType{ShellPHP, ShellASP, ShellASPX, ShellJSP} {
		p, err := Generate(Options{ShellType: st, Password: "pw_123", Watermark: "dl-abc123"})
		if err != nil {
			t.Fatalf("%s: Generate: %v", st, err)
		}
		content := string(p.Content)
		if !strings.Contains(content, "pw_123") {
			t.Errorf("%s: 密码未嵌入模板", st)
		}
		if !strings.Contains(content, "dl-abc123") {
			t.Errorf("%s: 水印缺失", st)
		}
		if !strings.Contains(content, "'cmd'") && !strings.Contains(content, `"cmd"`) && !strings.Contains(content, `["cmd"]`) && !strings.Contains(content, `("cmd")`) {
			t.Errorf("%s: cmd 参数名未嵌入", st)
		}
		if len(p.SHA256) != 64 {
			t.Errorf("%s: sha256 长度 = %d", st, len(p.SHA256))
		}
		if p.Filename == "" || !strings.HasSuffix(p.Filename, shellExt(st)) {
			t.Errorf("%s: 文件名异常: %q", st, p.Filename)
		}
		if p.TemplateID == "" {
			t.Errorf("%s: templateID 为空", st)
		}
	}
}

func TestGenerateClosingTagContiguous(t *testing.T) {
	// 结束标签必须完整：%%> 转义后应为连续的 %>（历史 bug：被拆成跨行的 %\n>）
	expect := map[ShellType]string{
		ShellPHP:  "?>",
		ShellASP:  "%>",
		ShellASPX: "%>",
		ShellJSP:  "%>",
	}
	for st, tag := range expect {
		p, err := Generate(Options{ShellType: st, Password: "x1"})
		if err != nil {
			t.Fatalf("%s: %v", st, err)
		}
		if !strings.Contains(string(p.Content), tag) {
			t.Errorf("%s: 缺少连续结束标签 %q", st, tag)
		}
		if strings.Contains(string(p.Content), "%\n>") {
			t.Errorf("%s: 结束标签被拆行", st)
		}
	}
}

func TestGenerateRandomPasswordWhenEmpty(t *testing.T) {
	p1, err := Generate(Options{ShellType: ShellPHP})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	p2, err := Generate(Options{ShellType: ShellPHP})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(p1.Password) != passwordLength {
		t.Errorf("随机密码长度 = %d, 期望 %d", len(p1.Password), passwordLength)
	}
	if p1.Password == p2.Password {
		t.Error("两次生成的随机密码不应相同")
	}
	if p1.Password == p2.Password {
		t.Error("随机文件名不应相同")
	}
	if p1.Filename == p2.Filename {
		t.Error("随机文件名不应相同")
	}
}

func TestGeneratePasswordMismatchGuard(t *testing.T) {
	// 密码嵌入内容但接口层不回显内容给非授权方——这里只保证一致性
	p, err := Generate(Options{ShellType: ShellPHP, Password: "abc"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if p.Password != "abc" {
		t.Errorf("指定密码被改写: %q", p.Password)
	}
}

func TestGenerateUnknownShellType(t *testing.T) {
	if _, err := Generate(Options{ShellType: "python"}); err == nil {
		t.Fatal("未知语言应返回错误")
	}
}

func TestGenerateUnsafeLiteralRejected(t *testing.T) {
	if _, err := Generate(Options{ShellType: ShellPHP, Password: `a"b`}); err == nil {
		t.Fatal("含引号的密码应被拒绝")
	}
	if _, err := Generate(Options{ShellType: ShellPHP, CmdParam: "c;d"}); err == nil {
		t.Fatal("含分号的 cmdParam 应被拒绝")
	}
}

func TestNormalizeShellType(t *testing.T) {
	if st, err := NormalizeShellType(" PHP "); err != nil || st != ShellPHP {
		t.Errorf("NormalizeShellType(php) = %v, %v", st, err)
	}
	if _, err := NormalizeShellType(""); err == nil {
		t.Error("空语言应返回错误")
	}
}

func TestSanitizeWatermark(t *testing.T) {
	if got := sanitizeWatermark(`dl<script>"x"`); got != "dlscriptx" {
		t.Errorf("sanitizeWatermark = %q", got)
	}
	long := strings.Repeat("a", 100)
	if got := sanitizeWatermark(long); len(got) != 64 {
		t.Errorf("长水印未截断: %d", len(got))
	}
}
