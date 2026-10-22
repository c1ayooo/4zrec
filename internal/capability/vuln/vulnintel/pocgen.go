// 情报 → 验证性 PoC(pocgen)。和 tplgen 同一思路:**确定性骨架优先**。模型只
// 提供可核验的请求要素(方法/入口路径/参数/响应特征),脚本由代码拼装。
//
// 为什么不让模型直接写整段代码:实测模型很擅长产出"看起来像 PoC"的 Python ——
// import requests、TARGET 占位、几个 if —— 但端点、参数、判定特征全是编的,
// 或者退化成对本机二进制的版本比对,拿去做验证一步都跑不通。把「写代码」换成
// 「填要素」以后,凡是填不出具体入口/特征的条目就老实报「无法构造」,不再产出
// 只有格式的脚本。
package vulnintel

import (
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// pocParam 是请求参数(名/值)。值可以是验证载荷,也可以是占位符。
type pocParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// pocSpec 是模型给出的验证要素。Constructible=false 时 Reason 说明为什么
// 情报不足以构造可运行的验证脚本。
type pocSpec struct {
	Constructible bool       `json:"constructible"`
	Reason        string     `json:"reason"`
	Method        string     `json:"method"`
	Path          string     `json:"path"`
	Params        []pocParam `json:"params"`
	BodyFormat    string     `json:"body_format"` // form | json
	Marker        string     `json:"marker"`      // 响应里用于判定成功的特征
	MatchStatus   int        `json:"match_status"`
	Evidence      string     `json:"evidence"` // 判定依据
}

// buildPoCScript 由验证要素拼装可运行的 Python 3 脚本。要求:
//   - 入口路径非空且能在情报正文里找到(接地),否则拒绝 —— 只有 "/" 的探测
//     验证不了任何漏洞;
//   - 至少有一个响应特征(marker)或明确的状态码,否则没有判定依据。
//
// 返回 (脚本, 备注, error)。备注写进 poc_note,用于说明参数是否模型推测。
func buildPoCScript(v db.EnrichedVulnIntel, corpus string, spec pocSpec) (string, string, error) {
	reason := strings.TrimSpace(spec.Reason)
	if !spec.Constructible {
		if reason == "" {
			reason = "情报未给出可触发漏洞的入口与参数"
		}
		return "", reason, fmt.Errorf("%s", reason)
	}

	path := strings.TrimSpace(spec.Path)
	if path == "" || path == "/" || !strings.HasPrefix(path, "/") {
		return "", "", fmt.Errorf("情报没有给出可验证的入口路径，无法构造可运行的 PoC")
	}
	if !pathGrounded(corpus, path) {
		return "", "", fmt.Errorf("入口路径 %s 在情报原文里找不到出处（模型推测的路径跑不通），未生成 PoC", path)
	}

	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method != "POST" {
		method = "GET"
	}

	params := make([]pocParam, 0, len(spec.Params))
	ungrounded := 0
	for _, p := range spec.Params {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		if !grounded(corpus, name) {
			ungrounded++
		}
		params = append(params, pocParam{Name: name, Value: strings.TrimSpace(p.Value)})
	}
	if len(params) == 0 {
		return "", "", fmt.Errorf("没有可发送的参数，无法构造验证请求")
	}

	marker := strings.TrimSpace(spec.Marker)
	if marker != "" && !grounded(corpus, marker) {
		return "", "", fmt.Errorf("响应特征 %q 在情报原文里找不到出处，未生成 PoC", marker)
	}
	if marker == "" && spec.MatchStatus == 0 {
		return "", "", fmt.Errorf("情报没有给出可判定的响应特征或状态码，未生成 PoC")
	}
	status := spec.MatchStatus
	if status < 100 || status > 599 {
		status = 0
	}

	var b strings.Builder
	b.WriteString("#!/usr/bin/env python3\n")
	b.WriteString("# -*- coding: utf-8 -*-\n")
	b.WriteString("# 4zrec 情报流水线自动生成 —— 验证性 PoC(仅发送无损探测请求)\n")
	fmt.Fprintf(&b, "# 目标产品：%s\n", firstNonEmpty(strings.TrimSpace(v.Title), v.CVE, "（未命名）"))
	if spec.Evidence != "" {
		fmt.Fprintf(&b, "# 判定依据：%s\n", strings.TrimSpace(spec.Evidence))
	}
	if ungrounded > 0 {
		fmt.Fprintf(&b, "# 注意：%d 个参数名在情报原文中没有出处，为模型推测，使用前请核对。\n", ungrounded)
	}
	b.WriteString("# 用法：python3 poc.py <base_url>    # 例如 http://192.168.1.10:8080\n")
	b.WriteString("import sys\n\nimport urllib3\nimport requests\n\n")
	b.WriteString("urllib3.disable_warnings()\n\n")
	b.WriteString("TARGET = \"http://127.0.0.1\"  # 未传参时的默认目标\n")
	fmt.Fprintf(&b, "PATH = %s\n", pyString(path))
	fmt.Fprintf(&b, "METHOD = %s\n", pyString(method))
	fmt.Fprintf(&b, "PARAMS = %s\n", pyDict(params))
	fmt.Fprintf(&b, "EXPECT_WORDS = %s\n", pyList(marker))
	if status > 0 {
		fmt.Fprintf(&b, "EXPECT_STATUS = %d\n", status)
	} else {
		b.WriteString("EXPECT_STATUS = 0  # 0 表示不校验状态码\n")
	}
	b.WriteString(`
def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else TARGET).rstrip("/")
    url = base + PATH
    try:
        if METHOD == "POST":
            resp = requests.post(url, data=PARAMS, timeout=15, verify=False, allow_redirects=False)
        else:
            resp = requests.get(url, params=PARAMS, timeout=15, verify=False, allow_redirects=False)
    except requests.RequestException as exc:
        print(f"[-] 请求失败: {exc}")
        return 2

    body = resp.text
    status_ok = EXPECT_STATUS == 0 or resp.status_code == EXPECT_STATUS
    hits = [w for w in EXPECT_WORDS if w.lower() in body.lower()]
    if status_ok and hits:
        print(f"[+] 疑似存在漏洞: HTTP {resp.status_code}, 命中特征 {hits}")
        print(f"[*] 响应片段: {body[:300]!r}")
        return 0
    print(f"[-] 未确认: HTTP {resp.status_code}, 命中特征 {hits or '无'}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
`)
	note := ""
	if ungrounded > 0 {
		note = fmt.Sprintf("%d 个参数名为模型推测，使用前请核对", ungrounded)
	}
	code := b.String()
	if err := ValidatePoCScript(code); err != nil {
		return "", "", fmt.Errorf("PoC 自检失败: %w", err)
	}
	return code, note, nil
}

// ValidatePoCScript 是骨架自检:确认脚本真的带着请求与判定逻辑(防止模板改动
// 后悄悄退化成空壳)。
func ValidatePoCScript(code string) error {
	if !strings.Contains(code, "requests.") {
		return fmt.Errorf("PoC 没有发起 HTTP 请求")
	}
	if !strings.Contains(code, "PATH = ") || !strings.Contains(code, "PARAMS = ") {
		return fmt.Errorf("PoC 缺少入口或参数")
	}
	if !strings.Contains(code, "EXPECT_WORDS") || !strings.Contains(code, "return 0") {
		return fmt.Errorf("PoC 缺少判定逻辑")
	}
	return nil
}

// pathGrounded 判断路径是否在情报原文里出现过:整段路径命中,或路径末段
// (文件名/最后一节)命中。
func pathGrounded(corpus, path string) bool {
	clean := strings.ToLower(strings.TrimSpace(path))
	if clean == "" {
		return false
	}
	if strings.Contains(corpus, clean) {
		return true
	}
	base := clean
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if len(base) < 4 {
		return false
	}
	return strings.Contains(corpus, base)
}

func pyString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func pyList(items ...string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		if strings.TrimSpace(it) == "" {
			continue
		}
		parts = append(parts, pyString(it))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func pyDict(params []pocParam) string {
	parts := make([]string, 0, len(params))
	for _, p := range params {
		parts = append(parts, pyString(p.Name)+": "+pyString(p.Value))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
