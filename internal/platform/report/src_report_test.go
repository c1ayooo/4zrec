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
