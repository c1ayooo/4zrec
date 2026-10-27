package toolparse

import (
	"encoding/xml"
	"strings"
)

// nmapParser 解析 nmap -oX - 输出（XML 直出 stdout，见 tools/nmap.yaml）。
// 事实映射（档案 §4.5）：
//   - 存活主机 → target/<ip>（confirmed，TCP 连通即实证）
//   - 开放端口+服务 → infra/<ip>:<port>-<service>（confirmed 有版本 / tentative 仅端口；
//     -sV 有版本信息时 confirmed）；只取 state=open
//   - 边：target/<ip> --contains--> infra/<ip>:<port>-<service>
type nmapParser struct{}

func (nmapParser) Tools() []string { return []string{"nmap"} }

func (nmapParser) Match(tool string, argv []string) bool {
	return tool == "nmap" && hasFlag(argv, "-oX")
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Address []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []nmapPort `xml:"ports>port"`
	OS    []struct {
		Name string `xml:"name,attr"`
	} `xml:"os>osmatch"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	} `xml:"service"`
}

func (p nmapParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "nmap", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	if strings.TrimSpace(stdout) == "" {
		return res, nil // 空输入：OK=true 零事实
	}
	var run nmapRun
	if err := xml.Unmarshal([]byte(stdout), &run); err != nil {
		// 非 XML（或 XML 头前混入文本）：fail-closed，判不可解析
		res.OK = false
		res.Err = "nmap XML 解析失败: " + err.Error()
		return res, nil
	}
	seenTarget := map[string]bool{}
	seenInfra := map[string]bool{}
	hostBodies := map[string][]string{}

	for _, h := range run.Hosts {
		ip := ""
		for _, a := range h.Address {
			if a.AddrType == "ipv4" && a.Addr != "" {
				ip = a.Addr
				break
			}
		}
		if ip == "" {
			continue
		}
		hostname := ""
		if len(h.Hostnames) > 0 {
			hostname = h.Hostnames[0].Name
		}
		targetKey := "target/" + Sluggify(ip)
		if h.Status.State == "up" && !seenTarget[targetKey] {
			seenTarget[targetKey] = true
			summary := "存活主机: " + ip
			if hostname != "" {
				summary += "（" + hostname + "）"
			}
			res.Facts = append(res.Facts, FactCandidate{
				FactKey:    targetKey,
				Category:   "target",
				Summary:    summary,
				Body:       "IP: " + ip + "｜State: up",
				Confidence: "confirmed",
			})
		}
		openPorts := 0
		var openDescs []string
		for _, pt := range h.Ports {
			if pt.State.State != "open" || pt.PortID == "" {
				continue
			}
			openPorts++
			svc := pt.Service.Name
			if svc == "" {
				svc = "unknown"
			}
			svcSlug := Sluggify(svc)
			key := "infra/" + Sluggify(ip) + ":" + pt.PortID + "-" + svcSlug
			hasVersion := pt.Service.Product != "" || pt.Service.Version != ""
			conf := "tentative"
			if hasVersion {
				conf = "confirmed"
			}
			desc := pt.Protocol + "/" + pt.PortID + " " + svc
			if pt.Service.Product != "" {
				desc += " " + pt.Service.Product
			}
			if pt.Service.Version != "" {
				desc += " " + pt.Service.Version
			}
			if !seenInfra[key] {
				seenInfra[key] = true
				res.Facts = append(res.Facts, FactCandidate{
					FactKey:    key,
					Category:   "infra",
					Summary:    "开放端口+服务: " + desc + " @ " + ip,
					Body:       "端口: " + pt.PortID + "/" + pt.Protocol + "｜服务: " + svc + "｜版本: " + pt.Service.Product + " " + pt.Service.Version,
					Confidence: conf,
					Links:      []FactLink{{From: targetKey, Type: "contains"}},
				})
			}
			openDescs = append(openDescs, desc)
		}
		hostBodies[targetKey] = append(hostBodies[targetKey],
			"开放端口: "+strings.Join(openDescs, ", ")+"｜共 "+intText(openPorts)+" 个")
	}

	for key, entries := range hostBodies {
		appendFactBody(res, key, strings.Join(entries, "\n"))
	}
	res.Fields["hosts"] = len(seenTarget)
	res.Fields["open_ports"] = len(seenInfra)
	return res, nil
}
