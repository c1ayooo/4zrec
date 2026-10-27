package memshell

import (
	"strings"
	"testing"
)

func TestGenerateRemover(t *testing.T) {
	p, err := GenerateRemover(KindTomcatFilter, "pw123456", "wsFabcdef01", "testwm")
	if err != nil {
		t.Fatal(err)
	}
	if p.TemplateID != "tomcat-filter-proxy-remover" || p.FilterName != "wsFabcdef01" {
		t.Errorf("template=%s filter=%s", p.TemplateID, p.FilterName)
	}
	s := string(p.Content)
	for _, want := range []string{
		"\"pw123456\"", "\"wsFabcdef01\"",
		"findFilterMaps", "removeFilterMap", "findFilterDefs", "removeFilterDef", "filterConfigs",
		"MEMSHELL_REMOVE_OK", "MEMSHELL_REMOVE_FAIL",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("卸载器缺少 %s", want)
		}
	}
	// 注入器与卸载器触发协议一致（同参数名）
	if !strings.Contains(s, "\""+TriggerParam+"\"") {
		t.Errorf("卸载器触发参数应为 %s", TriggerParam)
	}
}

func TestGenerateRemoverValidation(t *testing.T) {
	if _, err := GenerateRemover(KindTomcatFilter, "", "f", ""); err == nil {
		t.Error("空密码应报错")
	}
	if _, err := GenerateRemover(KindTomcatFilter, "pw", "", ""); err == nil {
		t.Error("空 filter_name 应报错")
	}
	if _, err := GenerateRemover(KindTomcatFilter, "pw;drop", "f", ""); err == nil {
		t.Error("密码含非法字符应报错")
	}
	if _, err := GenerateRemover("bogus-kind", "pw", "f", ""); err == nil {
		t.Error("未知类型应报错")
	}
}
