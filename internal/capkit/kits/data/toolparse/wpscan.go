package toolparse

import (
	"encoding/json"
)

// wpscanParser 解析 wpscan -f json -o <tmpfile> 输出（JSON 文件由挂钩层并入 stdout）。
// 事实映射（档案 §4.5）：
//   - WordPress 版本 → infra/<host>-wordpress-<ver>（有实证即 confirmed；part_of → target/<host>）
//   - 插件/主题漏洞条目 → finding/<plugin-slug>-<host>（tentative；exploits → target/<host>）
type wpscanParser struct{}

func (wpscanParser) Tools() []string { return []string{"wpscan"} }

func (wpscanParser) Match(tool string, argv []string) bool {
	return tool == "wpscan" && hasFlag(argv, "-f")
}

type wpscanOut struct {
	Version *struct {
		Number string `json:"number"`
	} `json:"version"`
	MainTheme *struct {
		Slug string `json:"slug"`
	} `json:"main_theme"`
	Plugins map[string]struct {
		Version *struct {
			Number string `json:"number"`
		} `json:"version"`
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Title    string `json:"title"`
			Severity string `json:"severity"`
		} `json:"vulnerabilities"`
	} `json:"plugins"`
}

func (p wpscanParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "wpscan", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	target := targetFromPrefix(stdout)
	var out wpscanOut
	if err := json.Unmarshal([]byte(stripTargetPrefix(stdout)), &out); err != nil {
		res.OK = false
		res.Err = "wpscan JSON 解析失败: " + err.Error()
		return res, nil
	}
	host := Sluggify(urlHostname(target))
	infra := 0
	findings := 0
	if host == "" {
		// 非 TargetAware 通道：host 取不到，只报计数
		res.Fields["wordpress"] = false
		return res, nil
	}
	if out.Version != nil && out.Version.Number != "" {
		infra++
		res.Facts = append(res.Facts, FactCandidate{
			FactKey:    "infra/" + host + "-wordpress-" + Sluggify(out.Version.Number),
			Category:   "infra",
			Summary:    "WordPress 版本: " + out.Version.Number + " @ " + target,
			Body:       "版本: " + out.Version.Number,
			Confidence: "confirmed",
			Links:      []FactLink{{From: "target/" + host, Type: "part_of"}},
		})
	}
	for slug, plug := range out.Plugins {
		for _, v := range plug.Vulnerabilities {
			key := "finding/" + Sluggify(slug) + "-" + host
			res.Facts = append(res.Facts, FactCandidate{
				FactKey:    key,
				Category:   "finding",
				Summary:    "WordPress 插件漏洞 [" + v.Severity + "] " + v.Title + "（" + slug + "）@ " + target,
				Body:       "插件: " + slug + "｜漏洞: " + v.Title + "｜ID: " + v.ID,
				Confidence: "tentative",
				Links:      []FactLink{{From: "target/" + host, Type: "exploits"}},
			})
			findings++
		}
	}
	res.Fields["wordpress"] = out.Version != nil
	res.Fields["infra_facts"] = infra
	res.Fields["vuln_findings"] = findings
	return res, nil
}

// NeedsTarget 实现 TargetAware：wpscan -f json 的 target 在请求参数里，文件内容不含 host。
func (wpscanParser) NeedsTarget() bool { return true }
