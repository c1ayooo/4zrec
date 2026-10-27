package toolparse

import (
	"regexp"
	"strings"
)

// sqlmapParser 解析 sqlmap --batch --output-dir=<tmpdir> 的人类判定行（§4.4-C：无机器可读输出）。
// 事实映射（档案 §4.5）：注入点 → finding/sqli-<host>-<param>（tentative，注入实证待复核；
// exploits → target/<host>）。
// 不解析 session.sqlite（§八-3：避免耦合第三方内部格式）。
type sqlmapParser struct{}

func (sqlmapParser) Tools() []string { return []string{"sqlmap"} }

func (sqlmapParser) Match(tool string, argv []string) bool {
	return tool == "sqlmap" && hasFlag(argv, "--output-dir")
}

var (
	sqlmapInjectableRe = regexp.MustCompile(`(?i)parameter '([^']+)' appears to be injectable`)
	sqlmapVulnerableRe = regexp.MustCompile(`(?i)parameter '([^']+)' is vulnerable`)
	sqlmapBlockRe      = regexp.MustCompile(`(?i)^Parameter: ([^\s]+) \(`)
	sqlmapDBMSRe       = regexp.MustCompile(`(?i)the back-end DBMS is ([A-Za-z0-9]+)`)
)

func (p sqlmapParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "sqlmap", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	host := Sluggify(urlHostname(targetFromPrefix(stdout)))
	seen := map[string]bool{}
	var dbms string

	for _, line := range strings.Split(stdout+"\n"+stderr, "\n") {
		line = strings.TrimSpace(line)
		if m := sqlmapDBMSRe.FindStringSubmatch(line); len(m) == 2 && dbms == "" {
			dbms = m[1]
		}
		var param string
		if m := sqlmapInjectableRe.FindStringSubmatch(line); len(m) == 2 {
			param = m[1]
		} else if m := sqlmapVulnerableRe.FindStringSubmatch(line); len(m) == 2 {
			param = m[1]
		} else if m := sqlmapBlockRe.FindStringSubmatch(line); len(m) == 2 {
			param = m[1]
		}
		if param == "" || host == "" {
			continue
		}
		key := "finding/sqli-" + host + "-" + Sluggify(param)
		if !seen[key] {
			seen[key] = true
			res.Facts = append(res.Facts, FactCandidate{
				FactKey:    key,
				Category:   "finding",
				Summary:    "SQL 注入点: " + param + " @ " + targetFromPrefix(stdout),
				Body:       "参数: " + param + "｜DBMS: " + dbms + "｜判定行: " + line,
				Confidence: "tentative",
				Links:      []FactLink{{From: "target/" + host, Type: "exploits"}},
			})
		}
	}
	res.Fields["injection_points"] = len(seen)
	res.Fields["dbms"] = dbms
	return res, nil
}

// NeedsTarget 实现 TargetAware：sqlmap 判定行不含目标 host（目标在 -u 参数里）。
func (sqlmapParser) NeedsTarget() bool { return true }
