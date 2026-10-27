package toolparse

import (
	"encoding/json"
	"net/url"
	"strings"
)

// dalfoxParser 解析 dalfox --format jsonl -o <tmpfile> 输出（JSONL 文件由挂钩层并入 stdout）。
// 事实映射（档案 §4.5）：XSS 命中（参数 + payload）→ finding/xss-<host>-<param>
// （tentative，命中实证待复核；exploits → target/<host>）。
type dalfoxParser struct{}

func (dalfoxParser) Tools() []string { return []string{"dalfox"} }

func (dalfoxParser) Match(tool string, argv []string) bool {
	return tool == "dalfox" && hasFlag(argv, "--format")
}

type dalfoxLine struct {
	Type     string `json:"type"`
	Href     string `json:"href"`
	Param    string `json:"param"`
	Payload  string `json:"payload"`
	Evidence string `json:"evidence"`
	CWE      string `json:"cwe"`
	Severity string `json:"severity"`
	Data     struct {
		CWE      string `json:"cwe"`
		Severity string `json:"severity"`
	} `json:"data"`
}

func (p dalfoxParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "dalfox", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	seen := map[string]bool{}
	issues := 0

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var l dalfoxLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		if l.Href == "" || l.Param == "" {
			continue
		}
		u, err := url.Parse(l.Href)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := Sluggify(u.Hostname())
		paramSlug := Sluggify(l.Param)
		key := "finding/xss-" + host + "-" + paramSlug
		if !seen[key] {
			seen[key] = true
			res.Facts = append(res.Facts, FactCandidate{
				FactKey:    key,
				Category:   "finding",
				Summary:    "XSS 命中 [" + l.Severity + "] " + l.Param + " @ " + l.Href,
				Body:       "URL: " + l.Href + "｜参数: " + l.Param + "｜Payload: " + l.Payload + "｜证据: " + l.Evidence + "｜CWE: " + l.CWE,
				Confidence: "tentative",
				Links:      []FactLink{{From: "target/" + host, Type: "exploits"}},
			})
		}
		issues++
	}
	res.Fields["issues"] = issues
	return res, nil
}
