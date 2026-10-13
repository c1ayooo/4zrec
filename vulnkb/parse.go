// Package vulnkb 把老 4zreco 项目沉淀的 1day 漏洞库(markdown)解析成结构化
// 记录并导入数据库。库内容为半结构化 md,存在两代格式:
//
//	新版(标签式):  - **系统**:X　|　**类型**:Y　|　**CVE**:Z
//	旧版(行内式):  X ｜ Y ｜ Z
//
// 共同字段以「- **指纹**:」等行标签承载,Payload 为标记行后的首个围栏代码块。
// 解析失败不报错、尽力而为——知识库的价值在覆盖面,个别畸形文件缺字段可用。
package vulnkb

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
)

var (
	// 新版元数据行里的三个标签(值以 | 或 ｜ 分隔,冒号全半角皆可)。
	reSysField  = regexp.MustCompile(`\*\*系统\*\*[：:]\s*([^|｜]*)`)
	reTypeField = regexp.MustCompile(`\*\*类型\*\*[：:]\s*([^|｜]*)`)
	reCVEField  = regexp.MustCompile(`\*\*CVE\*\*[：:]\s*(.*)`)
	// 行内字段标签:值可能裹反引号、可能多个反引号段以全角空格相连。
	reFingerprint = regexp.MustCompile(`(?m)^\s*-\s*\*\*指纹\*\*[：:]\s*(.+?)\s*$`)
	reRequest     = regexp.MustCompile(`(?m)^\s*-\s*\*\*请求\*\*[：:]\s*(.+?)\s*$`)
	reHeaders     = regexp.MustCompile(`(?m)^\s*-\s*\*\*关键头\*\*[：:]\s*(.+?)\s*$`)
	reResponseSig = regexp.MustCompile(`(?m)^\s*-\s*\*\*响应特征\*\*[：:]\s*(.+?)\s*$`)
	reExpected    = regexp.MustCompile(`(?m)^\s*-\s*\*\*预期\*\*[：:]\s*(.+?)\s*$`)
	// Payload:标记行(**Payload** / **请求体 / payload**)之后的第一个围栏块。
	rePayload = regexp.MustCompile("(?s)\\*\\*(?:请求体\\s*/\\s*payload|Payload|payload)\\*\\*[^`]*?```[a-zA-Z0-9]*\\n(.*?)```")
	reTitle   = regexp.MustCompile(`(?m)^#\s+(.+?)\s*$`)
	// CVE 兜底:字段缺失/为「—」时从正文里抽标准编号。
	reCVEAny = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
)

// cleanValue 去掉反引号与首尾空白(含全角空格),压掉内部换行。
func cleanValue(s string) string {
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.Trim(s, " \t　")
}

// Parse 把一篇漏洞 md 解析为库记录。product 回退用 md 所在目录名——库按
// 产品建目录,目录名即权威产品名(正文里的「系统」字段常有别名/简写)。
func Parse(raw []byte, sourcePath string) db.VulnKBEntry {
	e := db.VulnKBEntry{
		ContentHash: sha256Hex(raw),
		Body:        string(raw),
		SourcePath:  sourcePath,
	}
	if m := reTitle.FindSubmatch(raw); m != nil {
		e.Title = string(m[1])
	}
	if e.Title == "" {
		e.Title = strings.TrimSuffix(filepath.Base(sourcePath), ".md")
	}

	head := raw
	if idx := strings.Index(string(raw), "\n**Payload"); idx > 0 {
		head = raw[:idx]
	}

	// 新版元数据行。
	if m := reSysField.FindSubmatch(head); m != nil {
		e.Product = cleanValue(string(m[1]))
		if m := reTypeField.FindSubmatch(head); m != nil {
			e.VulnType = cleanValue(string(m[1]))
		}
		if m := reCVEField.FindSubmatch(head); m != nil {
			e.CVE = cleanValue(string(m[1]))
		}
	} else if product, vtype, cve := splitInlineMeta(string(head)); product != "" {
		// 旧版行内式:开头几行内一条「X ｜ Y ｜ Z」。
		e.Product, e.VulnType, e.CVE = product, vtype, cve
	}

	if m := reFingerprint.FindSubmatch(raw); m != nil {
		e.Fingerprint = cleanValue(string(m[1]))
	}
	if m := reRequest.FindSubmatch(raw); m != nil {
		e.RequestLine = cleanValue(string(m[1]))
	}
	if m := reHeaders.FindSubmatch(raw); m != nil {
		e.Headers = cleanValue(string(m[1]))
	}
	if m := reResponseSig.FindSubmatch(raw); m != nil {
		e.ResponseSig = cleanValue(string(m[1]))
	}
	if m := reExpected.FindSubmatch(raw); m != nil {
		e.Expected = cleanValue(string(m[1]))
	}
	if m := rePayload.FindSubmatch(raw); m != nil {
		e.Payload = strings.TrimRight(string(m[1]), "\n")
	}

	// 兜底与规范化。
	if e.Product == "" || e.Product == "—" {
		e.Product = filepath.Base(filepath.Dir(sourcePath))
	}
	if e.CVE == "" || e.CVE == "—" || !strings.HasPrefix(e.CVE, "CVE-") {
		if m := reCVEAny.FindString(e.Body); m != "" {
			e.CVE = m
		} else if strings.HasPrefix(e.CVE, "CVE-") {
			// 保留合法值
		} else {
			e.CVE = ""
		}
	}
	return e
}

// splitInlineMeta 在文件前几行里找旧版行内元数据「X ｜ Y ｜ Z」。要求不以
// -/#/` 开头(排除标签行、标题、代码)。
func splitInlineMeta(text string) (product, vtype, cve string) {
	for i, line := range strings.Split(text, "\n") {
		if i >= 10 {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "`") || strings.HasPrefix(line, "```") {
			continue
		}
		if !strings.ContainsAny(line, "|｜") {
			continue
		}
		parts := strings.FieldsFunc(line, func(r rune) bool { return r == '|' || r == '｜' })
		if len(parts) < 2 || len(parts) > 3 {
			continue
		}
		p0 := strings.TrimSpace(parts[0])
		if p0 == "" {
			continue
		}
		product = strings.Trim(p0, " \t　")
		vtype = strings.TrimSpace(parts[1])
		if len(parts) == 3 {
			cve = cleanValue(parts[2])
		}
		return
	}
	return "", "", ""
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ParseFile 读单篇 md。
func ParseFile(path string) (db.VulnKBEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return db.VulnKBEntry{}, err
	}
	return Parse(raw, filepath.ToSlash(path)), nil
}
