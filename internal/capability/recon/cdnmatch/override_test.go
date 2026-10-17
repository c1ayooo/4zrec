package cdnmatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// G6：覆盖文件加载——缺失静默跳过、覆盖内置、追加新条目、非法条目跳过不中断。
func TestLoadOverridesFile(t *testing.T) {
	dir := t.TempDir()

	// 文件缺失：内置表兜底
	if n, err := LoadOverridesFile(filepath.Join(dir, "missing.json")); n != 0 || err != nil {
		t.Fatalf("文件缺失应静默跳过: n=%d err=%v", n, err)
	}

	// 覆盖内置 cloudfront.net + 追加新条目 + 两条非法
	p := filepath.Join(dir, "cdn.json")
	content := `[
		{"suffix":"cloudfront.net","type":"waf","name":"CloudFront WAF"},
		{"suffix":"newcdn.example.net","type":"cdn","name":"示例新 CDN"},
		{"suffix":"","type":"cdn","name":"空后缀"},
		{"suffix":"bad.example","type":"bogus","name":"非法类型"}
	]`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := LoadOverridesFile(p)
	if err == nil || !strings.Contains(err.Error(), "2 条非法条目") {
		t.Fatalf("非法条目应有错误说明: n=%d err=%v", n, err)
	}
	if n != 2 {
		t.Fatalf("合法 2 条应生效: n=%d", n)
	}

	// Classify 生效
	if r := Classify("xyz.cloudfront.net", nil); r.EdgeType != "waf" {
		t.Fatalf("覆盖内置条目应生效: %+v", r)
	}
	if r := Classify("a.newcdn.example.net", nil); r.EdgeName != "示例新 CDN" {
		t.Fatalf("追加条目应生效: %+v", r)
	}

	// 恢复内置表（包级全局，避免影响其他测试）
	tableMu.Lock()
	suffixTable["cloudfront.net"] = Result{EdgeType: "cdn", EdgeName: "CloudFront"}
	delete(suffixTable, "newcdn.example.net")
	tableMu.Unlock()
}
