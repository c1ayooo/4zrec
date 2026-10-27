package toolparse

import (
	"encoding/json"
	"sort"
	"strings"
)

// arjunParser 解析 arjun -oJ <tmpfile> 输出（JSON 对象文件由挂钩层并入 stdout）。
// 事实映射（档案 §4.5）：发现的参数清单 → infra/<host>-params（tentative，
// body 累积清单；part_of → target/<host>）。格式：{"<param>": ["GET","POST"], ...}。
type arjunParser struct{}

func (arjunParser) Tools() []string { return []string{"arjun"} }

func (arjunParser) Match(tool string, argv []string) bool {
	return tool == "arjun" && hasFlag(argv, "-oJ")
}

func (p arjunParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "arjun", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	target := targetFromPrefix(stdout)
	var found map[string][]string
	if err := json.Unmarshal([]byte(stripTargetPrefix(stdout)), &found); err != nil {
		res.OK = false
		res.Err = "arjun JSON 解析失败: " + err.Error()
		return res, nil
	}
	if len(found) == 0 {
		res.Fields["params"] = 0
		return res, nil
	}
	host := Sluggify(urlHostname(target))
	if host == "" {
		// 无目标 host（非 TargetAware 通道调用）：只报字段不落键（fail-closed）
		res.Fields["param_count"] = len(found)
		return res, nil
	}
	var b strings.Builder
	params := make([]string, 0, len(found))
	for k, methods := range found {
		params = append(params, k)
		b.WriteString(k)
		b.WriteString(" (")
		b.WriteString(strings.Join(methods, "/"))
		b.WriteString(")\n")
	}
	sort.Strings(params)
	res.Facts = append(res.Facts, FactCandidate{
		FactKey:    "infra/" + host + "-params",
		Category:   "infra",
		Summary:    "参数清单（arjun 发现）: " + strings.Join(params, ", ") + " @ " + target,
		Body:       b.String(),
		Confidence: "tentative",
		Links:      []FactLink{{From: "target/" + host, Type: "part_of"}},
	})
	res.Fields["params"] = params
	res.Fields["param_count"] = len(params)
	return res, nil
}

// NeedsTarget 实现 TargetAware：arjun 的结构化 JSON 不含目标 host。
func (arjunParser) NeedsTarget() bool { return true }

// targetFromPrefix 从 runner 并入的 "TARGET: <url>" 前缀读取目标 URL（无则 ""）。
func targetFromPrefix(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "TARGET:") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "TARGET:"))
		}
	}
	return ""
}

// stripTargetPrefix 移除 stdout 头部的 TARGET 前缀行（供整段 JSON/XML 解析器使用）。
func stripTargetPrefix(stdout string) string {
	var out []string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "TARGET:") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
