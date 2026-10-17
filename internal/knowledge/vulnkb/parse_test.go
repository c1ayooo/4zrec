package vulnkb

import (
	"strings"
	"testing"
)

// 两代真实样本:新版标签式与旧版行内式(截取自老 4zreco 漏洞库)。
const sampleLabeled = `# 英飞达影像存档与通讯PACS系统INFINITT_PACS任意文件上传漏洞

- **系统**：英飞达影像存档与通讯PACS系统INFINITT_PACS　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：` + "`\"INFINITT\"`" + `
- **请求**：` + "`POST /webservices/WebJobUpload.asmx HTTP/1.1`" + `

**Payload**
` + "```" + `xml
<soap:Envelope>jobUpload</soap:Envelope>
` + "```" + `
- **响应特征**：200 jobUploadResult
`

const sampleInline = `# 迅饶科技登录绕过漏洞

迅饶科技登录绕过 ｜ 其他 ｜ —
- **指纹**：` + "`server=\"SunFull-Webs\"`" + `
- **请求**：` + "`GET /index.html HTTP/1.1`" + `
- **响应特征**：200 用户管理
`

func TestParseLabeledFormat(t *testing.T) {
	e := Parse([]byte(sampleLabeled), "英飞达/INFINITT_PACS任意文件上传漏洞.md")
	if e.Title != "英飞达影像存档与通讯PACS系统INFINITT_PACS任意文件上传漏洞" {
		t.Fatalf("title=%q", e.Title)
	}
	if e.Product != "英飞达影像存档与通讯PACS系统INFINITT_PACS" {
		t.Fatalf("product=%q", e.Product)
	}
	if e.VulnType != "文件上传" {
		t.Fatalf("vuln_type=%q", e.VulnType)
	}
	if e.Fingerprint != `"INFINITT"` {
		t.Fatalf("fingerprint=%q", e.Fingerprint)
	}
	if e.RequestLine != "POST /webservices/WebJobUpload.asmx HTTP/1.1" {
		t.Fatalf("request=%q", e.RequestLine)
	}
	if e.Payload == "" || !contains(e.Payload, "jobUpload") {
		t.Fatalf("payload=%q", e.Payload)
	}
	if e.ResponseSig != "200 jobUploadResult" {
		t.Fatalf("response_sig=%q", e.ResponseSig)
	}
}

func TestParseInlineFormat(t *testing.T) {
	e := Parse([]byte(sampleInline), "迅饶科技登录绕过/迅饶科技登录绕过漏洞.md")
	if e.Product != "迅饶科技登录绕过" {
		t.Fatalf("product=%q", e.Product)
	}
	if e.VulnType != "其他" {
		t.Fatalf("vuln_type=%q", e.VulnType)
	}
	if e.Fingerprint != `server="SunFull-Webs"` {
		t.Fatalf("fingerprint=%q", e.Fingerprint)
	}
	if e.CVE != "" {
		t.Fatalf("cve should be empty, got %q", e.CVE)
	}
}

func TestParseCVEFallback(t *testing.T) {
	body := "# SpringCloud存在SpEL表达式注入漏洞(CVE-2025-41243)\n\n" +
		"- **系统**：SpringCloud　|　**类型**：SQL注入　|　**CVE**：—\n" +
		"- **指纹**：`app=\"vmware-SpringBoot-Framework\"`\n"
	e := Parse([]byte(body), "Spring/SpringCloud SpEL.md")
	if e.CVE != "CVE-2025-41243" {
		t.Fatalf("cve fallback=%q", e.CVE)
	}
	if e.Product != "SpringCloud" {
		t.Fatalf("product=%q", e.Product)
	}
}

func TestParseProductFallsBackToDir(t *testing.T) {
	e := Parse([]byte("# 只有标题\n\n没有元数据行\n"), "用友/某漏洞.md")
	if e.Product != "用友" {
		t.Fatalf("product fallback=%q", e.Product)
	}
	if e.Title != "只有标题" {
		t.Fatalf("title=%q", e.Title)
	}
}

func TestContentHashStable(t *testing.T) {
	a := Parse([]byte(sampleInline), "a/b.md")
	b := Parse([]byte(sampleInline), "a/c.md")
	if a.ContentHash != b.ContentHash {
		t.Fatal("same content must hash equal")
	}
	if a.ContentHash == "" {
		t.Fatal("hash empty")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
