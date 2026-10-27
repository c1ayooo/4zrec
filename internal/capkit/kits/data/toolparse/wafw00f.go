package toolparse

import (
	"encoding/json"
)

// wafw00fParser 解析 wafw00f -f json -o <tmpfile> 输出（JSON 数组文件由挂钩层并入 stdout）。
// 事实映射（档案 §4.5）：WAF 是否 + 厂商指纹 → infra/<host>-waf-<vendor>（tentative，
// WAF/CDN 识别有误报面，待复核；part_of → target/<host>）。
type wafw00fParser struct{}

func (wafw00fParser) Tools() []string { return []string{"wafw00f"} }

func (wafw00fParser) Match(tool string, argv []string) bool {
	return tool == "wafw00f" && hasFlag(argv, "-f")
}

type wafw00fEntry struct {
	URL          string `json:"url"`
	Detected     bool   `json:"detected"`
	Firewall     string `json:"firewall"`
	Manufacturer string `json:"manufacturer"`
}

func (p wafw00fParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "wafw00f", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	var entries []wafw00fEntry
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		res.OK = false
		res.Err = "wafw00f JSON 解析失败: " + err.Error()
		return res, nil
	}
	seen := map[string]bool{}
	noWAF := 0

	for _, e := range entries {
		host := Sluggify(urlHostname(e.URL))
		if host == "" {
			continue
		}
		if !e.Detected || e.Firewall == "" || e.Firewall == "None" {
			noWAF++
			continue
		}
		vendor := Sluggify(e.Firewall)
		key := "infra/" + host + "-waf-" + vendor
		if !seen[key] {
			seen[key] = true
			res.Facts = append(res.Facts, FactCandidate{
				FactKey:    key,
				Category:   "infra",
				Summary:    "WAF 指纹: " + e.Firewall + "（" + e.Manufacturer + "） @ " + e.URL,
				Body:       "URL: " + e.URL + "｜WAF: " + e.Firewall + "｜厂商: " + e.Manufacturer,
				Confidence: "tentative",
				Links:      []FactLink{{From: "target/" + host, Type: "part_of"}},
			})
		}
	}
	res.Fields["waf_detected"] = len(seen)
	res.Fields["targets"] = len(entries)
	res.Fields["no_waf"] = noWAF
	return res, nil
}
