package toolparse

import (
	"encoding/xml"
	"strings"
)

// niktoParser 解析 nikto -Format xml -o <tmpfile> 输出（XML 文件由挂钩层并入 stdout）。
// 事实映射（档案 §4.5）：服务器配置类条目 → finding/<host>-<item-slug>（tentative，
// discovered_on → target/<host>）。nikto 输出只有 htm/nbe/xml 三种格式（无 JSON，§4.4-B）。
type niktoParser struct{}

func (niktoParser) Tools() []string { return []string{"nikto"} }

func (niktoParser) Match(tool string, argv []string) bool {
	return tool == "nikto" && hasFlag(argv, "-Format")
}

type niktoScan struct {
	XMLName   xml.Name `xml:"niktoscan"`
	ScanInfos []struct {
		Target string      `xml:"target,attr"`
		Port   string      `xml:"port,attr"`
		Items  []niktoItem `xml:"item"`
	} `xml:"scaninfo"`
}

type niktoItem struct {
	ID       string `xml:"id,attr"`
	Method   string `xml:"method,attr"`
	OSVDB    string `xml:"osvdb,attr"`
	Desc     string `xml:"description"`
	URI      string `xml:"uri"`
	Namelink string `xml:"namelink"`
}

func (p niktoParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "nikto", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	var scan niktoScan
	if err := xml.Unmarshal([]byte(stdout), &scan); err != nil {
		res.OK = false
		res.Err = "nikto XML 解析失败: " + err.Error()
		return res, nil
	}
	seen := map[string]bool{}
	items := 0

	for _, si := range scan.ScanInfos {
		host := Sluggify(urlHostname(si.Target))
		if host == "" {
			continue
		}
		for _, it := range si.Items {
			items++
			slug := Sluggify(it.URI)
			if slug == "" {
				slug = "item"
			}
			key := "finding/" + host + "-" + slug
			if it.ID != "" {
				key += "-id" + it.ID
			}
			if !seen[key] {
				seen[key] = true
				desc := strings.TrimSpace(it.Desc)
				res.Facts = append(res.Facts, FactCandidate{
					FactKey:    key,
					Category:   "finding",
					Summary:    "nikto 配置类问题: " + strings.TrimSpace(it.URI) + " @ " + si.Target,
					Body:       "条目: " + it.ID + "｜方法: " + it.Method + "｜描述: " + desc,
					Confidence: "tentative",
					Links:      []FactLink{{From: "target/" + host, Type: "discovered_on"}},
				})
			}
		}
	}
	res.Fields["items"] = items
	return res, nil
}
