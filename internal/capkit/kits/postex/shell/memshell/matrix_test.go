package memshell

import (
	"strings"
	"testing"
)

// 矩阵全覆盖：每个 kind 可生成、占位符全部替换、关键字段在位。
func TestGenerateMatrix(t *testing.T) {
	for _, kind := range allKinds {
		p, err := Generate(Options{Kind: kind, Password: "pw123456", FilterName: "wsFtest01", Watermark: "wm", Mapping: "/wsx"})
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		s := string(p.Content)
		for _, leftover := range []string{"{{WATERMARK}}", "{{PASSWORD}}", "{{FILTER_NAME}}", "{{MAPPING}}", "{{TRIGGER_PARAM}}"} {
			if strings.Contains(s, leftover) {
				t.Errorf("%s: 占位符 %s 未替换", kind, leftover)
			}
		}
		if !strings.Contains(s, "pw123456") {
			t.Errorf("%s: 密码未嵌入", kind)
		}
		switch kind {
		case KindTomcatFilter:
			if !strings.Contains(s, "javax.servlet") || strings.Contains(s, "jakarta.servlet") {
				t.Error("filter 应为 javax 命名空间")
			}
		case KindTomcatFilterJakarta:
			if !strings.Contains(s, "jakarta.servlet") {
				t.Error("jakarta filter 命名空间错误")
			}
		case KindTomcatValve:
			if !strings.Contains(s, "ValveBase") || !strings.Contains(s, "addValve") {
				t.Error("valve 模板缺注册逻辑")
			}
		case KindTomcatServlet:
			if !strings.Contains(s, "StandardWrapper") || !strings.Contains(s, `"/wsx"`) {
				t.Error("servlet 模板缺 wrapper/映射")
			}
		case KindSpringController:
			if !strings.Contains(s, "registerSingleton") || !strings.Contains(s, "registerHandler") {
				t.Error("spring 模板缺 bean/映射注册")
			}
		case KindAspxHttpModule:
			if !strings.Contains(s, "RegisterModule") || !strings.Contains(s, "IHttpModule") {
				t.Error("aspx 模板缺 HttpModule 注册")
			}
		case KindPhpUserIni:
			if p.ExtraFiles[".user.ini"] != "auto_prepend_file=wsFtest01\n" {
				t.Errorf("php-user-ini .user.ini 内容 = %q", p.ExtraFiles[".user.ini"])
			}
			if !p.Triggerless {
				t.Error("php-user-ini 应为 Triggerless")
			}
		}
	}
}

func TestKindsListAndNormalize(t *testing.T) {
	if len(Kinds()) != 7 {
		t.Errorf("kind 数 = %d", len(Kinds()))
	}
	for _, k := range Kinds() {
		if _, err := NormalizeKind(k); err != nil {
			t.Errorf("NormalizeKind(%s) 报错: %v", k, err)
		}
	}
	if got, _ := NormalizeKind(""); got != KindTomcatFilter {
		t.Error("空 kind 默认 tomcat-filter")
	}
	if _, err := NormalizeKind("nope"); err == nil {
		t.Error("未知 kind 应报错")
	}
	if !SupportsRemover(KindTomcatFilter) || SupportsRemover(KindTomcatValve) {
		t.Error("SupportsRemover 应仅 Filter 型")
	}
}

func TestGenerateMappingValidation(t *testing.T) {
	p, err := Generate(Options{Kind: KindTomcatServlet, Password: "pw123456", Mapping: "wsabc"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Mapping != "/wsabc" {
		t.Errorf("mapping 自动补前缀 = %q", p.Mapping)
	}
	if _, err = Generate(Options{Kind: KindSpringController, Password: "pw;drop"}); err == nil {
		t.Error("密码非法字符应报错")
	}
}
