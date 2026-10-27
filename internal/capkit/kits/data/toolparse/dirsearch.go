package toolparse

import (
	"encoding/json"
	"net/url"
	"strings"
)

// dirsearchParser 解析 dirsearch -O json -o <tmpfile> 输出（JSON 文件由挂钩层并入 stdout）。
// 事实映射（档案 §4.5）：目录/文件命中 → finding/<host>-<path-slug>（tentative，
// discovered_on → target/<host>）。dirsearch 已过滤状态码，输出 results 即命中。
type dirsearchParser struct{}

func (dirsearchParser) Tools() []string { return []string{"dirsearch"} }

func (dirsearchParser) Match(tool string, argv []string) bool {
	return tool == "dirsearch" && hasFlag(argv, "-O")
}

type dirsearchOut struct {
	Info    map[string]any `json:"info"`
	Results []struct {
		URL      string `json:"url"`
		Status   int    `json:"status"`
		Length   int    `json:"contentLength"`
		Type     string `json:"contentType"`
		Redirect string `json:"redirect"`
	} `json:"results"`
}

func (p dirsearchParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "dirsearch", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	if strings.TrimSpace(stripTargetPrefix(stdout)) == "" {
		return res, nil // 空输入：OK=true 零事实
	}
	var out dirsearchOut
	if err := json.Unmarshal([]byte(stripTargetPrefix(stdout)), &out); err != nil {
		res.OK = false
		res.Err = "dirsearch JSON 解析失败: " + err.Error()
		return res, nil
	}
	keys := map[string]bool{}
	keyBodies := map[string][]string{}

	for _, r := range out.Results {
		u, err := url.Parse(r.URL)
		if err != nil || u.Hostname() == "" || r.URL == "" {
			continue
		}
		// target/* 键口径统一为无端口 hostname
		host := Sluggify(u.Hostname())
		path := urlPathSlug(r.URL)
		key := "finding/" + host + "-" + path
		if !keys[key] {
			keys[key] = true
			res.Facts = append(res.Facts, FactCandidate{
				FactKey:    key,
				Category:   "finding",
				Summary:    "目录/文件命中: " + r.URL,
				Body:       "URL: " + r.URL + "｜Status: " + statusText(r.Status) + "｜Length: " + intText(r.Length),
				Confidence: "tentative",
				Links:      []FactLink{{From: "target/" + host, Type: "discovered_on"}},
			})
		}
		keyBodies[key] = append(keyBodies[key], r.URL)
	}

	for key, urls := range keyBodies {
		appendFactBody(res, key, "Evidence URLs:\n"+strings.Join(urls, "\n"))
	}
	res.Fields["hits"] = len(keys)
	return res, nil
}
