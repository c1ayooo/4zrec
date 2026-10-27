package poc

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// The PoC path is element-filling, not code generation. A model asked for a
// verification script reliably returns something that *reads* like a PoC —
// imports, a TARGET placeholder, an `if` — with the endpoint, the parameters
// and the success condition all invented. Nothing about that runs. So the model
// is only allowed to fill in verification elements (where to send the request,
// what to send, what a positive response looks like), and the script itself is
// assembled here from a fixed skeleton. An advisory whose elements cannot be
// filled or grounded yields "cannot construct", which is a usable answer;
// a script that only has the right shape is not.

// PoCParam is one request parameter. Value is usually a harmless probe value.
type PoCParam struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// PoCSpec is everything the model contributes to a PoC: the verification
// elements. Constructible false (with Reason) means the advisory does not say
// enough to build a request that proves anything.
type PoCSpec struct {
	Constructible bool       `json:"constructible"`
	Reason        string     `json:"reason,omitempty"`
	Method        string     `json:"method,omitempty"`
	Path          string     `json:"path,omitempty"`
	Params        []PoCParam `json:"params,omitempty"`
	BodyFormat    string     `json:"body_format,omitempty"` // form | json
	Marker        string     `json:"marker,omitempty"`      // response substring that indicates the issue
	MatchStatus   int        `json:"match_status,omitempty"`
	Evidence      string     `json:"evidence,omitempty"`
}

// PoC body formats.
const (
	bodyForm = "form"
	bodyJSON = "json"
)

// buildPoCScript assembles a runnable script from verification elements.
//
// It refuses rather than guesses in four cases, because each one produces a
// script that cannot distinguish a vulnerable target from any other:
//   - no entry path, or a bare "/" (proves nothing about this advisory);
//   - an entry path that does not occur in the advisory text (the model made it
//     up, so it will 404);
//   - no parameters at all (no request to send);
//   - neither a response marker nor an expected status (no verdict).
//
// Marker and path must be grounded in the advisory; parameter *names* only
// downgrade to a note, since a name can legitimately be the obvious one for a
// documented endpoint ("id", "file") without appearing verbatim.
//
// The returned note is meant for the operator, not the machine.
func buildPoCScript(in IntelInput, corpus string, spec PoCSpec) (code string, note string, err error) {
	if !spec.Constructible {
		reason := strings.TrimSpace(spec.Reason)
		if reason == "" {
			reason = "情报未给出可触发漏洞的入口与参数"
		}
		return "", "", fmt.Errorf("%s", reason)
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

	params := make([]PoCParam, 0, len(spec.Params))
	ungrounded := 0
	for _, p := range spec.Params {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		if !grounded(corpus, name) {
			ungrounded++
		}
		params = append(params, PoCParam{Name: name, Value: strings.TrimSpace(p.Value)})
	}
	if len(params) == 0 {
		return "", "", fmt.Errorf("没有可发送的参数，无法构造验证请求")
	}

	marker := strings.TrimSpace(spec.Marker)
	if marker != "" && !grounded(corpus, marker) {
		return "", "", fmt.Errorf("响应特征 %q 在情报原文里找不到出处，未生成 PoC", marker)
	}
	status := spec.MatchStatus
	if status < 100 || status > 599 {
		status = 0
	}
	if marker == "" && status == 0 {
		return "", "", fmt.Errorf("情报没有给出可判定的响应特征或状态码，未生成 PoC")
	}

	bodyFormat := bodyForm
	if strings.EqualFold(strings.TrimSpace(spec.BodyFormat), bodyJSON) {
		bodyFormat = bodyJSON
	}
	// A JSON body only exists for a method that has a body.
	if method != "POST" {
		bodyFormat = bodyForm
	}

	var b strings.Builder
	b.WriteString("#!/usr/bin/env python3\n")
	b.WriteString("# -*- coding: utf-8 -*-\n")
	b.WriteString("# capkit 情报流水线自动生成：漏洞验证脚本（只做无损探测，判断漏洞是否存在）\n")
	fmt.Fprintf(&b, "# 目标产品：%s\n", joinNonEmpty(" / ", in.Title, in.CVE, "（未命名）"))
	if ev := strings.TrimSpace(spec.Evidence); ev != "" {
		fmt.Fprintf(&b, "# 判定依据：%s\n", ev)
	}
	if ungrounded > 0 {
		fmt.Fprintf(&b, "# 注意：%d 个参数名在情报原文中没有出处，为模型推测，使用前请核对。\n", ungrounded)
	}
	b.WriteString("# 依赖：仅标准库（Python 3.7+）。用法：python3 poc.py <base_url>\n")
	b.WriteString("# " + strings.Repeat("-", 72) + "\n")
	b.WriteString(`import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

`)
	fmt.Fprintf(&b, "TARGET = %s          # 未传参时的默认目标\n", pyQuote("http://127.0.0.1"))
	fmt.Fprintf(&b, "PATH = %s\n", pyQuote(path))
	fmt.Fprintf(&b, "METHOD = %s\n", pyQuote(method))
	fmt.Fprintf(&b, "BODY_FORMAT = %s          # form | json\n", pyQuote(bodyFormat))
	fmt.Fprintf(&b, "PARAMS = %s\n", pyDictLiteral(params))
	fmt.Fprintf(&b, "EXPECT_WORDS = %s          # 全部命中才算确认\n", pyListLiteral(marker))
	if status > 0 {
		fmt.Fprintf(&b, "EXPECT_STATUS = %d\n", status)
	} else {
		b.WriteString("EXPECT_STATUS = 0          # 0 表示不校验状态码\n")
	}
	b.WriteString("TIMEOUT = 15\n")

	b.WriteString(`

def build_request(base, path, method, params, body_format):
    """装配一次探测请求；params 为空时退化为无参请求。"""
    if method == "POST":
        if body_format == "json":
            payload = json.dumps(params).encode("utf-8")
            content_type = "application/json"
        else:
            payload = urllib.parse.urlencode(params).encode("utf-8")
            content_type = "application/x-www-form-urlencoded"
        return urllib.request.Request(
            base + path, data=payload, method="POST", headers={"Content-Type": content_type}
        )
    query = urllib.parse.urlencode(params)
    url = base + path + ("?" + query if query else "")
    return urllib.request.Request(url, method="GET")


def probe(request):
    """发一次请求，返回 (status, body)；连接失败返回 (0, "")。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:
        print("[-] 请求失败（无法判定）: %s" % exc)
        return 0, ""


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else TARGET).rstrip("/")
    request = build_request(base, PATH, METHOD, PARAMS, BODY_FORMAT)
    status, body = probe(request)
    if status == 0:
        return 2

    lowered = body.lower()
    hits = [w for w in EXPECT_WORDS if w.lower() in lowered]
    status_ok = EXPECT_STATUS == 0 or status == EXPECT_STATUS
    words_ok = len(EXPECT_WORDS) == 0 or len(hits) == len(EXPECT_WORDS)
    if status_ok and words_ok:
        print("[+] 疑似存在漏洞: HTTP %d, 命中特征 %s" % (status, hits or "（仅按状态码判定）"))
        print("[*] 响应片段: %r" % body[:300])
        return 0
    print("[-] 未确认: HTTP %d, 命中特征 %s" % (status, hits or "无"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
`)

	code = b.String()
	if err := ValidatePoCScript(code); err != nil {
		return "", "", fmt.Errorf("PoC 自检失败: %w", err)
	}
	if ungrounded > 0 {
		note = fmt.Sprintf("%d 个参数名为模型推测，使用前请核对", ungrounded)
	}
	return code, note, nil
}

// ValidatePoCScript is the skeleton self-check. It guards the assembled script
// against a future edit to the skeleton silently degrading it into something
// that makes no request or renders no verdict.
func ValidatePoCScript(code string) error {
	switch {
	case !strings.Contains(code, "urllib.request.urlopen"):
		return fmt.Errorf("PoC 没有发起 HTTP 请求")
	case !strings.Contains(code, "PATH = ") || !strings.Contains(code, "PARAMS = "):
		return fmt.Errorf("PoC 缺少入口或参数")
	case !strings.Contains(code, "EXPECT_WORDS") || !strings.Contains(code, "return 0"):
		return fmt.Errorf("PoC 缺少判定逻辑")
	}
	return nil
}

// intelCorpus flattens everything the advisory says into one lowercase
// haystack. Grounding is a substring test against it, so the corpus must
// include every field the model is allowed to quote: the text of the advisory
// and — when the analysis step already ran — its write-up, which often states
// the entry point the raw advisory left implicit.
func intelCorpus(in IntelInput, extra ...string) string {
	parts := []string{
		in.Title, in.Description, in.Solutions, in.CVE,
		strings.Join(in.Tags, "\n"), strings.Join(in.Affected, "\n"),
	}
	parts = append(parts, extra...)
	return strings.ToLower(strings.Join(parts, "\n"))
}

// grounded reports whether any alphanumeric run of s (>=3 runes) occurs in the
// lowercase corpus. Token granularity, not whole-string: a parameter quoted as
// "filename" is grounded by an advisory that says "file name".
func grounded(corpus, s string) bool {
	for _, tok := range alnumRuns(s) {
		if strings.Contains(corpus, tok) {
			return true
		}
	}
	return false
}

// pathGrounded accepts the whole path, or its last segment when that segment
// is long enough to be specific. Advisories routinely document
// "/api/v2/upload" as `POST /upload`, and a bare "/" or "/api" is not evidence
// of anything.
func pathGrounded(corpus, path string) bool {
	clean := strings.ToLower(strings.TrimSpace(path))
	if clean == "" {
		return false
	}
	if strings.Contains(corpus, clean) {
		return true
	}
	seg := clean
	if i := strings.LastIndex(seg, "/"); i >= 0 {
		seg = seg[i+1:]
	}
	if len([]rune(seg)) < 4 {
		return false
	}
	return strings.Contains(corpus, seg)
}

// alnumRuns splits s into lowercase runs of letters and digits, dropping
// separators and anything shorter than 3 runes (too short to be evidence).
func alnumRuns(s string) []string {
	var (
		out []string
		cur []rune
	)
	flush := func() {
		if len(cur) >= 3 {
			out = append(out, strings.ToLower(string(cur)))
		}
		cur = cur[:0]
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur = append(cur, r)
			continue
		}
		flush()
	}
	flush()
	return out
}

// pyQuote renders a Python double-quoted string literal.
func pyQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

// pyListLiteral renders []string as a Python list; empty strings are dropped.
func pyListLiteral(items ...string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		if strings.TrimSpace(it) == "" {
			continue
		}
		parts = append(parts, pyQuote(it))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// pyDictLiteral renders the parameters as a Python dict literal.
func pyDictLiteral(params []PoCParam) string {
	parts := make([]string, 0, len(params))
	for _, p := range params {
		parts = append(parts, pyQuote(p.Name)+": "+pyQuote(p.Value))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// MarshalPoCSpec encodes a spec for handing back to a caller that wants to
// review or edit the elements before rebuilding the script.
func MarshalPoCSpec(spec PoCSpec) json.RawMessage {
	b, err := json.Marshal(spec)
	if err != nil {
		return nil
	}
	return b
}

// joinNonEmpty joins the non-blank parts, or returns the fallback.
func joinNonEmpty(sep string, parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, sep)
}
