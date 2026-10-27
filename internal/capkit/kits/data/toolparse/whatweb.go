package toolparse

import (
	"encoding/xml"
	"strings"
)

// whatwebParser 解析 whatweb --log-xml=<tmpfile> 输出（XML 文件由挂钩层并入 stdout）。
// 事实映射（档案 §4.5）：指纹键值对 → infra/<host>-<tech>（tentative，part_of → target/<host>）。
type whatwebParser struct{}

func (whatwebParser) Tools() []string { return []string{"whatweb"} }

func (whatwebParser) Match(tool string, argv []string) bool {
	return tool == "whatweb" && hasFlag(argv, "--log-xml")
}

type whatwebLog struct {
	XMLName xml.Name `xml:"log"`
	Targets []struct {
		URI     string `xml:"uri"`
		Status  string `xml:"http-status"`
		Plugins []struct {
			Name    string `xml:"name"`
			Version string `xml:"version"`
			String  string `xml:"string"`
		} `xml:"plugin"`
	} `xml:"target"`
}

func (p whatwebParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "whatweb", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	var log whatwebLog
	if err := xml.Unmarshal([]byte(stripTargetPrefix(stdout)), &log); err != nil {
		res.OK = false
		res.Err = "whatweb XML 解析失败: " + err.Error()
		return res, nil
	}
	// fail-closed：非 whatweb XML（根元素非 log）判不可解析
	if log.XMLName.Local != "log" && strings.TrimSpace(stripTargetPrefix(stdout)) != "" {
		res.OK = false
		res.Err = "whatweb XML 根元素非 <log>"
		return res, nil
	}
	seen := map[string]bool{}
	hostBodies := map[string][]string{}

	for _, t := range log.Targets {
		u := strings.TrimSpace(t.URI)
		if u == "" {
			continue
		}
		host := Sluggify(urlHostname(u))
		if host == "" {
			continue
		}
		var descs []string
		for _, pl := range t.Plugins {
			name := strings.TrimSpace(pl.Name)
			if name == "" {
				continue
			}
			techSlug := Sluggify(name)
			key := "infra/" + host + "-" + techSlug
			if !seen[key] {
				seen[key] = true
				summary := "指纹: " + name + " @ " + u
				if pl.Version != "" {
					summary += " v" + pl.Version
				}
				res.Facts = append(res.Facts, FactCandidate{
					FactKey:    key,
					Category:   "infra",
					Summary:    summary,
					Body:       "组件: " + name + "｜版本: " + pl.Version + "｜详情: " + pl.String,
					Confidence: "tentative",
					Links:      []FactLink{{From: "target/" + host, Type: "part_of"}},
				})
			}
			descs = append(descs, name)
		}
		hostBodies[host] = append(hostBodies[host], "whatweb 指纹: "+strings.Join(descs, ", "))
	}

	for host, entries := range hostBodies {
		appendFactBody(res, "target/"+host, strings.Join(entries, "\n"))
	}
	res.Fields["fingerprints"] = len(seen)
	res.Fields["targets"] = len(log.Targets)
	return res, nil
}

// urlHostname 从 URL 提取 hostname（无端口；target/* 与 finding 的 host 段口径统一，
// 仅 infra 端口型键保留端口，见 nmap.go 的 <ip>:<port> 键）。
func urlHostname(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		// 剥端口（IPv6 简化为取冒号前；本项目目标均为 IPv4/域名）
		if host := s[:i]; host != "" {
			s = host
		}
	}
	return s
}
