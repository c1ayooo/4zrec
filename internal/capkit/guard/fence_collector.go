package guard

import (
	"net"
	"net/url"
	"sort"
	"strings"
)

// fenceCollector 是提取目标的公共收集器：旧的字面提取和新加的“命令对象”
// 解析共用同一套 host/URL/CIDR/变量归一化逻辑，避免两条路径口径漂移。
type fenceCollector struct {
	t    fenceTargets
	seen map[string]bool
	vars map[string]string
}

func newFenceCollector(vars map[string]string) *fenceCollector {
	if vars == nil {
		vars = map[string]string{}
	}
	return &fenceCollector{seen: map[string]bool{}, vars: vars}
}

func (c *fenceCollector) addDomain(d string) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if d != "" && !c.seen["d:"+d] {
		c.seen["d:"+d] = true
		c.t.Domains = append(c.t.Domains, d)
	}
}

func (c *fenceCollector) addIP(ip string) {
	if ip == "" || publicInfraIPs[ip] {
		return
	}
	if !c.seen["i:"+ip] {
		c.seen["i:"+ip] = true
		c.t.IPs = append(c.t.IPs, ip)
	}
}

func (c *fenceCollector) addHost(raw string) {
	raw = strings.Trim(substituteVars(strings.TrimSpace(raw), c.vars), `"'`)
	if raw == "" {
		return
	}
	// 变量/引号尾巴截断（http://host$p → host；残缺则丢弃）
	if i := strings.IndexAny(raw, "$`{}"); i >= 0 {
		raw = strings.TrimSuffix(raw[:i], "/")
		if strings.HasSuffix(raw, ".") || raw == "" {
			return
		}
	}
	// URL 形态
	if strings.Contains(raw, "://") || strings.HasPrefix(raw, "//") {
		u := raw
		if strings.HasPrefix(u, "//") {
			u = "http:" + u
		}
		if parsed, err := url.Parse(u); err == nil && parsed.Hostname() != "" {
			c.addHost(parsed.Hostname())
		}
		return
	}
	// 裸 IPv6（可带方括号）：在 host:port 解析前接住，避免被冒号拆分。
	if strings.Contains(raw, ":") {
		if ip := net.ParseIP(strings.Trim(raw, "[]")); ip != nil && ip.To4() == nil {
			if !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() {
				c.addIP(ip.String())
			}
			return
		}
	}
	// 无点 token：可疑 IP 变体（整数/十六进制）→IP；单段主机名（http://jira/）→域名。
	if !strings.Contains(raw, ".") && !strings.Contains(raw, ":") {
		if suspiciousIPVariant(raw) {
			addIPVariant(raw, c.addIP)
		} else if len(raw) > 1 && isSimpleHostLabel(raw) && !nonTargetSingleLabelHosts[strings.ToLower(raw)] {
			c.addDomain(raw)
		}
		return
	}
	// host:port / user@host(:port) / host:port:...
	raw = strings.TrimPrefix(raw, "@")
	if i := strings.Index(raw, "@"); i >= 0 {
		raw = raw[i+1:]
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	} else if i := strings.LastIndexByte(raw, ':'); i > 0 && allDigits(raw[i+1:]) {
		raw = raw[:i]
	}
	raw = strings.Trim(raw, "[]")
	if raw == "" {
		return
	}
	if ip := net.ParseIP(raw); ip != nil {
		if ip.To4() != nil {
			if validFenceIPv4(ip.String()) {
				c.addIP(ip.String())
			}
		} else if !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() {
			c.addIP(ip.String())
		}
		return
	}
	if validFenceIPv4(raw) {
		c.addIP(raw)
		return
	}
	// 可疑 IP 变体（整数/八进制/十六进制）
	if suspiciousIPVariant(raw) {
		addIPVariant(raw, c.addIP)
		return
	}
	// CIDR
	if _, ipnet, err := net.ParseCIDR(raw); err == nil {
		if ipnet.IP.To4() != nil {
			c.addIP(ipnet.IP.String())
		} else if !ipnet.IP.IsLoopback() && !ipnet.IP.IsUnspecified() && !ipnet.IP.IsLinkLocalUnicast() && !ipnet.IP.IsMulticast() {
			c.addIP(ipnet.IP.String())
		}
		return
	}
	if validFenceDomain(raw) {
		c.addDomain(raw)
		return
	}
}

func (c *fenceCollector) merge(other fenceTargets) {
	for _, d := range other.Domains {
		c.addDomain(d)
	}
	for _, ip := range other.IPs {
		c.addIP(ip)
	}
	if other.Opaque {
		c.t.Opaque = true
		if c.t.Reason == "" {
			c.t.Reason = other.Reason
		}
	}
}

func (c *fenceCollector) result() fenceTargets {
	sort.Strings(c.t.Domains)
	sort.Strings(c.t.IPs)
	return c.t
}
