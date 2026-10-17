// fence_extract.go 命令感知的目标提取(2026-10-17 重构,用户口径):不再扫描全
// 命令文本,只解析**实际发起连接的部分**——
//   - curl/wget 的 URL/位置参数、--resolve host、-x 代理跳过;
//   - nc/ncat 的 host/port、ssh/scp/sftp 的 host、ping/dig/host/nslookup 的目标、
//     nmap/masscan/nikto/nuclei/httpx/sqlmap/hydra/redis-cli/psql/mysql/mongo/
//     smbclient/telnet/ftp/whois/openssl 等的目标位置参数;
//   - /dev/tcp|udp/<host>/<port> 重定向(含 $var 变量代入);
//   - $(...) 与反引号命令替换:递归解析其中的子命令。
//
// 其余命令(grep/cat/jq/awk/sed/echo/head/tail/sort/uniq/python/node/... 数据加工
// 与脚本执行)一律跳过——样本分析不再因正文里的域名/IP 卡审批。heredoc 体先剔除。
package guard

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// connectionCommands 会发起网络连接的命令(参数才可能是围栏目标)。
var connectionCommands = map[string]bool{
	"curl": true, "wget": true, "wget2": true, "nc": true, "ncat": true, "netcat": true,
	"ssh": true, "scp": true, "sftp": true, "rsync": true,
	"ping": true, "ping6": true, "dig": true, "host": true, "nslookup": true, "whois": true,
	"nmap": true, "masscan": true, "zmap": true, "nikto": true, "nuclei": true,
	"httpx": true, "httprobe": true, "ffuf": true, "gobuster": true, "dirb": true,
	"sqlmap": true, "hydra": true, "medusa": true, "smbclient": true, "smbmap": true,
	"redis-cli": true, "psql": true, "mysql": true, "mongo": true, "mongosh": true,
	"telnet": true, "ftp": true, "http": true, "httpie": true, "socat": true,
	"openssl": true, "msfconsole": true, "searchsploit": true,
}

// valueFlags 各命令中"取一个值"的旗标:其后的 token 是值不是位置参数。
// 只收录会吃掉目标样 token 的常见旗标(-H/-d/-u/... 值里出现域名的场景)。
var valueFlags = map[string]bool{
	"-H": true, "--header": true, "-d": true, "--data": true, "--data-raw": true,
	"--data-binary": true, "--data-urlencode": true, "-X": true, "--request": true,
	"-u": true, "--user": true, "-A": true, "--user-agent": true, "-e": true, "--referer": true,
	"-b": true, "--cookie": true, "-c": true, "--cookie-jar": true, "-o": true, "--output": true,
	"-F": true, "--form": true, "-T": true, "--upload-file": true, "-x": true, "--proxy": true,
	"-w": true, "--write-out": true, "-m": true, "--max-time": true, "--connect-timeout": true,
	"--retry": true, "-E": true, "--cert": true, "-K": true, "--config": true, "--time": true,
	"-p": true, "-W": true, "-R": true,
	"-D": true, "--script": true, "-oN": true, "-oX": true, "-oG": true, "-oA": true, "-iL": true,
	"--wordlist": true, "-w5": true, "--url": false, // --url 值按 URL 解析(特殊处理)
}

// urlValueFlags 值需按 URL 解析的旗标。
var urlValueFlags = map[string]bool{"--url": true, "-u2": true}

// dnsRecordTypes / dnsClasses 是 dig/host/nslookup 的查询类型与类,不是目标。
// `dig +short $d CNAME`、`dig TXT x.origin.asn.cymru.com` 里的类型 token
// 曾被当成域名送审,导致每次正常 DNS 查询都误触围栏。
var dnsRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "AFSDB": true, "ANY": true, "AXFR": true, "CAA": true,
	"CDNSKEY": true, "CDS": true, "CERT": true, "CNAME": true, "DHCID": true, "DLV": true,
	"DNAME": true, "DNSKEY": true, "DS": true, "EUI48": true, "EUI64": true, "HINFO": true,
	"HIP": true, "HTTPS": true, "IPSECKEY": true, "IXFR": true, "KEY": true, "KX": true,
	"LOC": true, "MAILA": true, "MAILB": true, "MX": true, "NAPTR": true, "NS": true,
	"NSEC": true, "NSEC3": true, "NSEC3PARAM": true, "NULL": true, "OPENPGPKEY": true,
	"OPT": true, "PTR": true, "RRSIG": true, "SIG": true, "SMIMEA": true, "SOA": true,
	"SRV": true, "SSHFP": true, "SVCB": true, "TA": true, "TKEY": true, "TLSA": true,
	"TSIG": true, "TXT": true, "URI": true, "ZONEMD": true,
}

var dnsClasses = map[string]bool{"IN": true, "CH": true, "HS": true, "NONE": true}

// isDNSTypeOrClass 判定 dig/host/nslookup 的查询类型/类 token。
func isDNSTypeOrClass(tok string) bool {
	t := strings.ToUpper(strings.TrimSpace(tok))
	if t == "" {
		return false
	}
	if dnsRecordTypes[t] || dnsClasses[t] {
		return true
	}
	// RFC 3597 的 TYPE1234 形式。
	if strings.HasPrefix(t, "TYPE") && len(t) > 4 {
		for _, c := range t[4:] {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// scanOpenSSLArgs openssl 只从显式连接类旗标取值。子命令(x509/req/...)与
// `-ext subjectAltName`、证书文件路径都不是目标——此前它们被当作位置参数
// 送审,正常解析证书反而卡审批。
func scanOpenSSLArgs(rest []string, addHost func(string)) {
	for k := 0; k < len(rest); k++ {
		switch strings.ToLower(rest[k]) {
		case "-connect", "-host", "-proxy", "-servername", "-verify_hostname", "-verify_ip":
			if k+1 < len(rest) {
				k++
				addHost(rest[k])
			}
		}
	}
}


// reDevTCP /dev/tcp|udp/host/port 重定向。
var reDevTCP = regexp.MustCompile(`(?i)/dev/(?:tcp|udp)/([^/\s]+)/([0-9]{1,5})`)

// reAssign 变量赋值(VAR=value),用于 $var 代入。
var reAssign = regexp.MustCompile(`(?:^|[\s;|&(])([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;|&)]+)`)

// ExtractFenceTargets 从工具输入文本提取围栏目标(命令感知)。
func ExtractFenceTargets(text string) fenceTargets {
	var t fenceTargets
	seen := map[string]bool{}
	addDomain := func(d string) {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && !seen["d:"+d] {
			seen["d:"+d] = true
			t.Domains = append(t.Domains, d)
		}
	}
	addIP := func(ip string) {
		if ip == "" || publicInfraIPs[ip] {
			return
		}
		if !seen["i:"+ip] {
			seen["i:"+ip] = true
			t.IPs = append(t.IPs, ip)
		}
	}
	vars := collectVars(text)
	subst := func(s string) string { return substituteVars(s, vars) }
	var addHost func(string)
	addHost = func(raw string) { // 单个 host(可含端口/凭据/方括号)归类
		raw = strings.Trim(subst(strings.TrimSpace(raw)), `"'`)
		if raw == "" {
			return
		}
		// 变量/引号尾巴截断(http://host$p → host;残缺则丢弃)
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
				addHost(parsed.Hostname())
			}
			return
		}
		// 无点 token:可疑 IP 变体(整数/十六进制)→IP;单段主机名(http://jira/)→域名。
		if !strings.Contains(raw, ".") && !strings.Contains(raw, ":") {
			if suspiciousIPVariant(raw) {
				addIPVariant(raw, addIP)
			} else if len(raw) > 1 && isSimpleHostLabel(raw) && !nonTargetSingleLabelHosts[strings.ToLower(raw)] {
				addDomain(raw)
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
			if ip.To4() != nil && validFenceIPv4(ip.String()) {
				addIP(ip.String())
			}
			return
		}
		if validFenceIPv4(raw) {
			addIP(raw)
			return
		}
		// 可疑 IP 变体(整数/八进制/十六进制)
		if suspiciousIPVariant(raw) {
			addIPVariant(raw, addIP)
			return
		}
		// CIDR
		if _, ipnet, err := net.ParseCIDR(raw); err == nil {
			if ipnet.IP.To4() != nil {
				addIP(ipnet.IP.String())
			}
			return
		}
		if validFenceDomain(raw) {
			addDomain(raw)
			return
		}
	}

	stripped := stripHeredocs(text)
	// /dev/tcp 与 /dev/udp 重定向(含变量)。
	for _, m := range reDevTCP.FindAllStringSubmatch(stripped, -1) {
		addHost(m[1])
	}
	// $(...) 与反引号命令替换:递归解析内部子命令(深度≤2)。
	recurseSubstitutions(stripped, 0, func(inner string) {
		sub := ExtractFenceTargetsDepth(inner, 1)
		for _, d := range sub.Domains {
			addDomain(d)
		}
		for _, ip := range sub.IPs {
			addIP(ip)
		}
	})
	// 纯 URL 输入(WebFetch 等工具直接给 URL,无命令前缀)。
	trimmed := strings.TrimSpace(stripped)
	if strings.Contains(trimmed, "://") && !strings.ContainsAny(trimmed, " \n;|&") {
		addHost(trimmed)
	}
	// 简单命令逐段解析。
	for _, seg := range splitCommands(stripped) {
		scanCommandSegment(seg, addHost, addDomain, addIP, vars)
	}
	sort.Strings(t.Domains)
	sort.Strings(t.IPs)
	return t
}

// ExtractFenceTargetsDepth 供子命令替换递归使用(深度守卫)。
func ExtractFenceTargetsDepth(text string, depth int) fenceTargets {
	if depth > 2 {
		return fenceTargets{}
	}
	return ExtractFenceTargets(text)
}

// scanCommandSegment 解析单个简单命令段。
func scanCommandSegment(seg string, addHost func(string), addDomain func(string), addIP func(string), vars map[string]string) {
	args := tokenize(seg)
	if len(args) == 0 {
		return
	}
	// 跳过前置变量赋值与 shell 关键字(for/do/then/else/! 等)。
	shellKeywords := map[string]bool{"do": true, "then": true, "else": true, "!": true,
		"time": true, "sudo": true, "env": true, "command": true, "nohup": true, "nice": true, "{": true}
	i := 0
	for i < len(args) {
		if strings.Contains(args[i], "=") && !strings.HasPrefix(args[i], "-") {
			i++
			continue
		}
		if shellKeywords[strings.ToLower(args[i])] {
			i++
			continue
		}
		break
	}
	if i >= len(args) {
		return
	}
	cmd := strings.ToLower(args[i])
	if j := strings.LastIndexByte(cmd, '/'); j >= 0 {
		cmd = cmd[j+1:]
	}
	if !connectionCommands[cmd] {
		return
	}
	rest := args[i+1:]
	if cmd == "openssl" {
		scanOpenSSLArgs(rest, addHost)
		return
	}
	// dig/host/nslookup 的位置参数里混着查询类型与类(CNAME/TXT/IN...),
	// 它们不是目标;真正的主机名仍按位置参数提取。
	dnsQuery := cmd == "dig" || cmd == "host" || cmd == "nslookup"
	for k := 0; k < len(rest); k++ {
		tok := rest[k]
		if tok == "" {
			continue
		}
		if dnsQuery {
			switch {
			case tok == "-t" || tok == "-c" || tok == "-q" || tok == "-f" || tok == "-p" || tok == "-W":
				k++ // 旗标值(查询类型/类/文件名/端口/超时)
			case strings.HasPrefix(tok, "@"), strings.HasPrefix(tok, "+"), strings.HasPrefix(tok, "-"):
				// 解析器地址与 dig 的 +short 等选项
			case isDNSTypeOrClass(tok):
				// 查询类型/类
			default:
				addHost(tok)
			}
			continue
		}
		// --resolve host:port:addr → 取 host
		if tok == "--resolve" {
			if k+1 < len(rest) {
				k++
				spec := rest[k]
				if j := strings.IndexByte(spec, ':'); j > 0 {
					addHost(spec[:j])
				} else {
					addHost(spec)
				}
			}
			continue
		}
		if urlValueFlags[tok] {
			if k+1 < len(rest) {
				k++
				addHost(rest[k])
			}
			continue
		}
		if valueFlags[tok] {
			k++ // 值跳过(头/体/输出/超时等)
			continue
		}
		if strings.HasPrefix(tok, "@") {
			continue // 解析器地址(dig @8.8.8.8 等)不是测试目标
		}
		if strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "+") {
			continue // 旗标与 dig 的 +short 等选项
		}
		// 位置参数:host/URL/CIDR/域名。
		addHost(tok)
	}
}

// splitCommands 按 ; && || | & 换行 切简单命令(引号与 $( )/反引号内不切)。
func splitCommands(text string) []string {
	var out []string
	var cur strings.Builder
	inS, inD, inBT := false, false, false
	depth := 0
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case inS:
			cur.WriteByte(c)
			if c == '\'' {
				inS = false
			}
			continue
		case inD:
			cur.WriteByte(c)
			if c == '"' && (i == 0 || text[i-1] != '\\') {
				inD = false
			}
			continue
		case inBT:
			cur.WriteByte(c)
			if c == '`' {
				inBT = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
			cur.WriteByte(c)
		case '"':
			inD = true
			cur.WriteByte(c)
		case '`':
			inBT = true
			cur.WriteByte(c)
		case '$':
			if i+1 < len(text) && text[i+1] == '(' {
				depth++
				cur.WriteString("$(")
				i++
				continue
			}
			cur.WriteByte(c)
		case ')':
			if depth > 0 {
				depth--
			}
			cur.WriteByte(c)
		case '(', ' ', '\t':
			cur.WriteByte(c)
		case '\n', ';', '&', '|':
			// $( ) 内不切
			if depth > 0 {
				cur.WriteByte(c)
				continue
			}
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// tokenize 引号感知分词(去引号;反引号/$( ) 块整体作为一个 token)。
func tokenize(seg string) []string {
	var out []string
	var cur strings.Builder
	inS, inD, inBT := false, false, false
	depth := 0
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
				continue
			}
			cur.WriteByte(c)
			continue
		case inD:
			if c == '"' && (i == 0 || seg[i-1] != '\\') {
				inD = false
				continue
			}
			cur.WriteByte(c)
			continue
		case inBT:
			cur.WriteByte(c)
			if c == '`' {
				inBT = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
		case '"':
			inD = true
		case '`':
			inBT = true
			cur.WriteByte(c)
		case '$':
			if i+1 < len(seg) && seg[i+1] == '(' {
				depth++
				cur.WriteString("$(")
				i++
				continue
			}
			cur.WriteByte(c)
		case ')':
			if depth > 0 {
				depth--
			}
			cur.WriteByte(c)
		case ' ', '\t':
			if depth > 0 {
				cur.WriteByte(c)
				continue
			}
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// collectVars 收集命令中的变量赋值(用于 $var 代入)。
func collectVars(text string) map[string]string {
	out := map[string]string{}
	for _, m := range reAssign.FindAllStringSubmatch(text, -1) {
		v := strings.Trim(m[2], `"'`)
		out[m[1]] = v
	}
	return out
}

// substituteVars 把 $VAR / ${VAR} 代入。
func substituteVars(s string, vars map[string]string) string {
	if len(vars) == 0 || !strings.Contains(s, "$") {
		return s
	}
	for name, val := range vars {
		s = strings.ReplaceAll(s, "${"+name+"}", val)
		s = strings.ReplaceAll(s, "$"+name, val)
	}
	return s
}

// recurseSubstitutions 提取 $(...) 与反引号内容并回调(简单配对扫描)。
func recurseSubstitutions(text string, depth int, fn func(string)) {
	if depth > 1 {
		return
	}
	for i := 0; i < len(text); i++ {
		if text[i] == '$' && i+1 < len(text) && text[i+1] == '(' {
			lvl := 1
			j := i + 2
			for ; j < len(text); j++ {
				if text[j] == '(' {
					lvl++
				}
				if text[j] == ')' {
					lvl--
					if lvl == 0 {
						break
					}
				}
			}
			if j < len(text) {
				fn(text[i+2 : j])
			}
			i = j
			continue
		}
		if text[i] == '`' {
			j := strings.IndexByte(text[i+1:], '`')
			if j >= 0 {
				fn(text[i+1 : i+1+j])
				i = i + 1 + j
			}
		}
	}
}

// addIPVariant 把可疑 IP 变体归一化后计入;归一化失败按原 token fail-closed。
func addIPVariant(tok string, addIP func(string)) {
	if ip := net.ParseIP(inetAtonIP(tok)); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return
		}
		addIP(ip.String())
		return
	}
	addIP(tok)
}

// isSimpleHostLabel 单段主机名:非空、非纯数字、仅 [a-z0-9-]。
func isSimpleHostLabel(s string) bool {
	if s == "" {
		return false
	}
	allDigit := true
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
		if c < '0' || c > '9' {
			allDigit = false
		}
	}
	return !allDigit
}
