package toolparse

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// katanaParser 解析 katana -jsonl 输出（-or -ob 裁掉原始报文与 body 控体积）。
// 事实映射（档案 §4.5）：爬取 URL 汇入 target/<host> 的 body 累积（不单独立键，防键爆炸）。
type katanaParser struct{}

func (katanaParser) Tools() []string { return []string{"katana"} }

func (katanaParser) Match(tool string, argv []string) bool {
	return tool == "katana" && hasFlag(argv, "-jsonl")
}

type katanaLine struct {
	Request struct {
		Method   string `json:"method"`
		Endpoint string `json:"endpoint"` // 完整 URL
	} `json:"request"`
	Response struct {
		StatusCode    int `json:"status_code"`
		ContentLength int `json:"content_length"`
	} `json:"response"`
}

func (p katanaParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "katana", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	hostSeen := map[string]bool{}
	hostBodies := map[string][]string{}
	urlSeen := map[string]bool{}

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var l katanaLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		u, err := url.Parse(l.Request.Endpoint)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if urlSeen[l.Request.Endpoint] {
			continue
		}
		urlSeen[l.Request.Endpoint] = true
		// target/* 键口径统一为无端口 hostname（与 httpx 同键覆盖；端口在 URL/body 里）
		host := Sluggify(u.Hostname())
		if host == "" {
			continue
		}
		if !hostSeen[host] {
			hostSeen[host] = true
			res.Facts = append(res.Facts, FactCandidate{
				FactKey:    "target/" + host,
				Category:   "target",
				Summary:    "存活 Web 服务（katana 爬取确认）: " + u.Scheme + "://" + u.Host,
				Body:       "Method: " + l.Request.Method + "｜Status: " + statusText(l.Response.StatusCode),
				Confidence: "confirmed",
			})
		}
		hostBodies[host] = append(hostBodies[host], l.Request.Endpoint)
	}

	for host, urls := range hostBodies {
		appendFactBody(res, "target/"+host, "Crawled URLs:\n"+strings.Join(urls, "\n"))
	}
	res.Fields["urls"] = len(urlSeen)
	res.Fields["hosts"] = len(hostSeen)
	return res, nil
}

// intText 整数转字符串（字段展示用）。
func intText(n int) string {
	return strconv.Itoa(n)
}
