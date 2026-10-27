package toolparse

import (
	"encoding/json"
	"net/url"
	"strings"
)

// ffufParser 解析 ffuf -json 输出（NDJSON 到 stdout，见 tools/ffuf.yaml）。
// 事实映射（档案 §4.5）：暴露路径 → finding/<host>-<path-slug>（tentative，
// discovered_on → target/<host>）。ffuf 已按 -mc 过滤，输出行即命中。
type ffufParser struct{}

func (ffufParser) Tools() []string { return []string{"ffuf"} }

func (ffufParser) Match(tool string, argv []string) bool {
	return tool == "ffuf" && hasFlag(argv, "-json")
}

type ffufLine struct {
	Input    map[string]string `json:"input"`
	Position int               `json:"position"`
	Status   int               `json:"status"`
	Length   int               `json:"length"`
	Words    int               `json:"words"`
	Lines    int               `json:"lines"`
	URL      string            `json:"url"`
	Host     string            `json:"host"`
	Redirect string            `json:"redirectlocation"`
}

func (p ffufParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "ffuf", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	keys := map[string]bool{}
	keyBodies := map[string][]string{}

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var l ffufLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		host := strings.TrimSpace(l.Host)
		if host == "" {
			if u, err := url.Parse(l.URL); err == nil && u.Hostname() != "" {
				host = u.Hostname()
			}
		}
		// target/* 键口径统一为无端口 hostname（ffuf -json 的 host 字段是 host:port，需剥离）
		if u, err := url.Parse(l.URL); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		}
		host = Sluggify(host)
		if host == "" || l.URL == "" {
			continue
		}
		path := urlPathSlug(l.URL)
		key := "finding/" + host + "-" + path
		if !keys[key] {
			keys[key] = true
			res.Facts = append(res.Facts, FactCandidate{
				FactKey:    key,
				Category:   "finding",
				Summary:    "暴露路径/文件: " + l.URL,
				Body:       "URL: " + l.URL + "｜Status: " + statusText(l.Status) + "｜Length: " + intText(l.Length) + "｜Words: " + intText(l.Words),
				Confidence: "tentative",
				Links:      []FactLink{{From: "target/" + host, Type: "discovered_on"}},
			})
		}
		keyBodies[key] = append(keyBodies[key], l.URL)
	}

	for key, urls := range keyBodies {
		appendFactBody(res, key, "Evidence URLs:\n"+strings.Join(urls, "\n"))
	}
	res.Fields["hits"] = len(keys)
	return res, nil
}

// urlPathSlug 从 URL 提取路径并转 fact_key slug 段（/admin/index.html → admin-index-html）。
func urlPathSlug(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	p := strings.Trim(u.Path, "/")
	if p == "" {
		return "root"
	}
	p = strings.ReplaceAll(p, "/", "-")
	return Sluggify(p)
}
