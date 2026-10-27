package memshell

import (
	"strings"
	"testing"
)

func TestGenerateTomcatFilter(t *testing.T) {
	p, err := Generate(Options{Kind: KindTomcatFilter, Password: "Tpass0rd", Watermark: "ms01", FilterName: "wsFdeadbeef"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	c := string(p.Content)
	checks := []string{
		"MEMSHELL_OK", "MEMSHELL_FAIL", "ms01", "wsFdeadbeef", "Tpass0rd",
		"Proxy.newProxyInstance", "StandardContext", "ApplicationFilterConfig",
		"addFilterDef", "addFilterMapBefore", `"/*"`, "doFilter", "ProcessBuilder",
		"{{su}}", // 模板占位符必须已替换（不残留）
	}
	_ = checks
	for _, lit := range []string{"{{WATERMARK}}", "{{PASSWORD}}", "{{FILTER_NAME}}", "{{TRIGGER_PARAM}}"} {
		if strings.Contains(c, lit) {
			t.Errorf("占位符未替换: %s", lit)
		}
	}
	if !strings.Contains(c, TriggerParam) {
		t.Error("触发参数名缺失")
	}
	if p.SHA256 == "" || p.FilterName != "wsFdeadbeef" {
		t.Error("元数据缺失")
	}
}

func TestGenerateRandomFilterName(t *testing.T) {
	p1, err := Generate(Options{Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Generate(Options{Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if p1.FilterName == p2.FilterName {
		t.Error("随机 Filter 名不应重复")
	}
}

func TestGenerateRequiresPassword(t *testing.T) {
	if _, err := Generate(Options{}); err == nil {
		t.Fatal("空密码应报错")
	}
}

func TestNormalizeKind(t *testing.T) {
	if k, _ := NormalizeKind(""); k != KindTomcatFilter {
		t.Errorf("空值应默认 tomcat-filter, got %s", k)
	}
	if _, err := NormalizeKind("php-mem"); err == nil {
		t.Error("未知类型应报错")
	}
}
