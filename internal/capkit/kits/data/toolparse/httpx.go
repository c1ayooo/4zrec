package toolparse

import (
	"encoding/json"
	"strconv"
	"strings"
)

// httpxParser 解析 httpx -json -silent 输出（每行一个 JSON 对象，见 tools/httpx.yaml）。
// 事实映射（档案 §4.5）：存活 URL → target/<host>（confirmed）；技术栈 → infra/<host>-<tech>
// （tentative，part_of → target/<host>）。
type httpxParser struct{}

func (httpxParser) Tools() []string { return []string{"httpx"} }

func (httpxParser) Match(tool string, argv []string) bool {
	return tool == "httpx" && hasFlag(argv, "-json")
}

type httpxLine struct {
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	HostIP        string   `json:"host_ip"`
	Port          string   `json:"port"`
	Scheme        string   `json:"scheme"`
	Title         string   `json:"title"`
	Status        int      `json:"status_code"`
	WebServer     string   `json:"webserver"`
	Tech          []string `json:"tech"`
	ContentType   string   `json:"content_type"`
	ContentLength int      `json:"content_length"`
	Failed        bool     `json:"failed"`
}

func (p httpxParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "httpx", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	seenHost := map[string]bool{} // 同 host 只落一条 target（多行累积 body）
	hostBody := map[string][]string{}
	techKeys := map[string]bool{} // infra/<host>-<tech> 去重
	infraBody := map[string][]string{}

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var l httpxLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue // 单行畸形跳过，不整批失败（fail-closed 只对"整体不可解析"生效）
		}
		if l.Failed || l.Host == "" {
			continue
		}
		host := Sluggify(l.Host)
		if host == "" {
			continue
		}
		if !seenHost[host] {
			seenHost[host] = true
			// 存活判定：有 URL 且未 failed。状态码 0（-status-code 关闭）不阻断存活判定。
			res.Facts = append(res.Facts, FactCandidate{
				FactKey:    "target/" + host,
				Category:   "target",
				Summary:    "存活 Web 服务: " + l.URL,
				Body:       "URL: " + l.URL + "｜Status: " + statusText(l.Status) + "｜Title: " + l.Title,
				Confidence: "confirmed",
			})
		}
		hostBody[host] = append(hostBody[host],
			"URL: "+l.URL+"｜Status: "+statusText(l.Status)+"｜Title: "+l.Title+"｜Server: "+l.WebServer+"｜IP: "+l.HostIP)
		// 技术栈 → infra/<host>-<tech>
		for _, t := range l.Tech {
			tech := strings.TrimSpace(t)
			if tech == "" {
				continue
			}
			key := "infra/" + host + "-" + Sluggify(tech)
			if !techKeys[key] {
				techKeys[key] = true
				res.Facts = append(res.Facts, FactCandidate{
					FactKey:    key,
					Category:   "infra",
					Summary:    "技术栈/中间件: " + tech + " @ " + l.Host,
					Body:       "URL: " + l.URL + "｜组件: " + tech,
					Confidence: "tentative",
					Links:      []FactLink{{From: "target/" + host, Type: "part_of"}},
				})
			}
			infraBody[key] = append(infraBody[key], l.URL)
		}
	}

	// body 累积（同键覆盖时保留历史证据，落库层按时间戳分隔追加）
	for host, entries := range hostBody {
		appendFactBody(res, "target/"+host, strings.Join(entries, "\n"))
	}
	for key, urls := range infraBody {
		appendFactBody(res, key, "Evidence URLs:\n"+strings.Join(urls, "\n"))
	}

	res.Fields["hosts"] = len(seenHost)
	res.Fields["infra_tech"] = len(techKeys)
	if len(res.Facts) == 0 && stdout != "" {
		// 有输出但零存活（全 failed 或格式不符）→ 判定为可解析但无事实，不算失败
		res.OK = true
	}
	return res, nil
}

// appendFactBody 给已有候选追加 body 段（解析器侧累积证据，落库层再做时间戳分隔）。
func appendFactBody(res *Result, factKey, extra string) {
	if extra == "" {
		return
	}
	for i := range res.Facts {
		if res.Facts[i].FactKey == factKey {
			if !strings.Contains(res.Facts[i].Body, extra) {
				res.Facts[i].Body += "\n" + extra
			}
			return
		}
	}
}

// statusText 状态码转展示文本（0 = 未采集）。
func statusText(code int) string {
	if code == 0 {
		return "N/A"
	}
	return strconv.Itoa(code)
}
