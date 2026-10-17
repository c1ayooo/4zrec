package server

import "testing"

// TestMergeSchemaPropsSyncsRequired required 必须跟随代码 schema:旧库残留的
// required(url) 要被清掉,否则 http_probe 批量模式(requests/template)会被
// schema 校验拒绝;代码新增的可选参数仍要合并进来。
func TestMergeSchemaPropsSyncsRequired(t *testing.T) {
	cur := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{"type": "string", "description": "user-edited"},
		},
		"required": []any{"url"},
	}
	code := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url":      map[string]any{"type": "string"},
			"requests": map[string]any{"type": "array"},
		},
	}
	got := mergeSchemaProps(cur, code)
	if _, ok := got["required"]; ok {
		t.Fatalf("代码不再要求 url 时 required 应被移除: %v", got["required"])
	}
	props, _ := got["properties"].(map[string]any)
	if _, ok := props["requests"]; !ok {
		t.Fatal("新增参数 requests 应被合并")
	}
	if d, _ := props["url"].(map[string]any)["description"].(string); d != "user-edited" {
		t.Fatalf("已有参数描述不应被覆盖: %q", d)
	}

	// 代码声明 required 时以代码为准。
	code2 := map[string]any{"type": "object", "required": []string{"targets"}}
	got2 := mergeSchemaProps(map[string]any{"type": "object", "required": []any{"url"}}, code2)
	reqs := schemaRequiredStrings(got2["required"])
	if len(reqs) != 1 || reqs[0] != "targets" {
		t.Fatalf("required 应以代码为准: %v", reqs)
	}
}
