package report

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

func TestBuildSRCMarkdown(t *testing.T) {
	f1 := &db.DBFinding{
		ID: 1, Name: "匿名读取财务桶", Severity: "critical", TaskDescription: "虎牙 SRC 项目",
		Report: `# 匿名读取财务桶

## 1. 漏洞描述&发现方式、漏洞利用及危害

### 1.1 漏洞描述

桶匿名可读。

### 1.2 发现方式

通过接口枚举发现匿名可读桶。

### 1.3 漏洞利用方式

直接 GET。

### 1.4 危害与受影响范围

财务数据泄露。

## 2. 漏洞的详细复现/证明过程

### 2.1 复现步骤

GET /hssp/?list-type=2

## 3. 测试源信息

| 测试账号 | 无 |
|---|---|

## 4. 修复方案

关闭匿名策略。
`,
	}
	f2 := &db.DBFinding{
		ID: 2, Name: "匿名写对象", Severity: "high", TaskDescription: "虎牙 SRC 项目",
		Report: `# 匿名写对象

## 1. 漏洞描述&发现方式、漏洞利用及危害

### 1.1 漏洞描述

public 桶可写。

## 2. 漏洞的详细复现/证明过程

### 2.1 复现步骤

PUT /public/x

## 3. 测试源信息

| 测试账号 | 无 |
|---|---|

## 4. 修复方案

关闭匿名写。
`,
	}
	out := BuildSRCMarkdown([]*db.DBFinding{f1, f2}, "虎牙 SRC 报告")
	for _, want := range []string{
		"# 虎牙 SRC 报告",
		"## 测试范围",
		"- 虎牙 SRC 项目",
		"## 一、漏洞描述、发现过程与危害",
		"### 1. 匿名读取财务桶（严重）",
		"### 2. 匿名写对象（高危）",
		"#### 1.1 漏洞描述",
		"## 二、复现过程",
		"## 三、测试源信息",
		"## 四、修复方案",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Count(out, "虎牙 SRC 项目") != 1 {
		t.Fatalf("scope should be deduped:\n%s", out)
	}
}

// TestBuildSRCMarkdownFallback 守住两个交付底线：报告为空时不能静默丢漏洞，
// 证据等级/处置状态/复测结论要出现在正文里。
func TestFixStatusMapping(t *testing.T) {
	for _, tc := range []struct {
		locale, status, want string
	}{
		{"zh-CN", "fixed", "已修复"},
		{"zh-CN", "resolved", "已处理"},
		{"zh-CN", "pending", "待修复"},
		{"en-US", "fixed", "Fixed"},
		{"en-US", "resolved", "Resolved"},
	} {
		if got := fixStatus(tc.locale, tc.status); got != tc.want {
			t.Fatalf("fixStatus(%q,%q) = %q, want %q", tc.locale, tc.status, got, tc.want)
		}
	}
}

func TestBuildSRCMarkdownFallback(t *testing.T) {
	f := &db.DBFinding{
		ID: 3, Name: "无报告但有证据", Severity: "medium",
		Summary: "摘要说明", Evidence: "GET /api/x 返回 200 与业务数据",
		Confidence: "partial", Status: "fixed", RetestVerdict: "fixed",
	}
	out := BuildSRCMarkdown([]*db.DBFinding{f}, "报告")
	for _, want := range []string{
		"摘要说明", "GET /api/x 返回 200", "证据等级：部分验证",
		"处置状态：已修复", "复测结论：已修复",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}

	empty := &db.DBFinding{ID: 4, Name: "完全空的漏洞", Severity: "low"}
	out = BuildSRCMarkdown([]*db.DBFinding{empty}, "报告")
	if !strings.Contains(out, "该漏洞未附详细报告与证据") {
		t.Fatalf("empty finding should stay visible:\n%s", out)
	}
}
