package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestHTTPProbeBatchMatrix template+matrix 差分:两行变量代入,逐包摘要;
// requests 直用与上限校验。
func TestHTTPProbeBatchMatrix(t *testing.T) {
	// 直调展开层(免网络:验证归一/代入/上限语义)。
	var in httpProbeInput
	raw := `{
		"template": {"label": "user-{id}", "url": "http://h/api/user/{id}", "headers": {"X-Role": "{role}"}},
		"matrix": [{"id": "1", "role": "a"}, {"id": "2", "role": "b"}]
	}`
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	specs, errMsg := expandProbeSpecs(&in)
	if errMsg != "" || len(specs) != 2 {
		t.Fatalf("展开失败: %v %d", errMsg, len(specs))
	}
	if specs[0].URL != "http://h/api/user/1" || specs[0].Headers["X-Role"] != "a" || specs[1].URL != "http://h/api/user/2" {
		t.Fatalf("代入不符: %+v %+v", specs[0], specs[1])
	}
	if specs[0].Label != "user-1" || specs[1].Label != "user-2" {
		t.Fatalf("label 代入不符: %q %q", specs[0].Label, specs[1].Label)
	}

	// range 展开 + 上限 50。
	var in2 httpProbeInput
	raw2 := `{"template": {"url": "http://h/x?id={n}"}, "range": {"var": "n", "from": 1, "to": 100, "step": 1}}`
	_ = json.Unmarshal([]byte(raw2), &in2)
	specs2, _ := expandProbeSpecs(&in2)
	if len(specs2) != 50 {
		t.Fatalf("range 应封顶 50: %d", len(specs2))
	}

	// 便捷头合并:headers 显式优先。
	var in3 httpProbeInput
	raw3 := `{"url": "http://h/", "cookie": "s=1", "headers": {"Cookie": "explicit=2"}}`
	_ = json.Unmarshal([]byte(raw3), &in3)
	specs3, _ := expandProbeSpecs(&in3)
	if specs3[0].Headers["Cookie"] != "explicit=2" {
		t.Fatalf("显式 Cookie 应优先: %+v", specs3[0].Headers)
	}

	// requests 超限报错。
	var in4 httpProbeInput
	var many []map[string]any
	for i := 0; i < 51; i++ {
		many = append(many, map[string]any{"url": "http://h/x"})
	}
	b4, _ := json.Marshal(map[string]any{"requests": many})
	_ = json.Unmarshal(b4, &in4)
	if _, msg := expandProbeSpecs(&in4); !strings.Contains(msg, "上限 50") {
		t.Fatalf("超限应报错: %q", msg)
	}
	_ = context.Background()
}
