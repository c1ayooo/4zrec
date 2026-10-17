package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarkdownToBlocks(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "report_assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "report_assets", "proof.png"), []byte("png"), 0o644); err != nil {
		t.Fatal(err)
	}
	md := `# 标题

## 概述

第一段。

- 要点一
- 要点二

1. 步骤一
2. 步骤二

` + "```http\nGET / HTTP/1.1\n```" + `

| 项 | 值 |
|---|---|
| a | b |

> 引用结论

![截图](/api/report-assets/proof.png?v=1)

![外链](https://example.com/x.png)
`
	blocks := markdownToBlocks(md, dataDir)
	types := map[string]int{}
	for _, b := range blocks {
		types[b.Type]++
	}
	if types["heading"] != 1 { // the h1 title is skipped
		t.Fatalf("heading blocks = %d (%+v)", types["heading"], types)
	}
	if types["text"] != 2 || types["bullet"] != 2 || types["numbered"] != 2 ||
		types["code"] != 1 || types["table"] != 1 || types["quote"] != 1 ||
		types["image"] != 1 {
		t.Fatalf("block types = %+v", types)
	}
	for _, b := range blocks {
		if b.Type == "image" && b.Path == "" {
			t.Fatal("local image path not resolved")
		}
		if b.Type == "table" && len(b.Rows) != 2 {
			t.Fatalf("table rows = %d", len(b.Rows))
		}
	}
}
