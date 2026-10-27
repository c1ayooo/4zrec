package toolparse

import (
	"regexp"
	"strings"
)

// fscanParser 解析 fscan 半结构化文本输出（C 档：stdout 判定行 + 挂钩层并入的 result.txt 段）。
// 输入形态按实测覆盖两代：
//   - v2.2.1（平台补丁版与目标侧同版本）：banner「Fscan <ver>」、`[*] ip:port`（裸开放端口行）、
//     `[*] http://ip:port  http  [Product:…] Banner:(…)`（服务识别）、
//     `[+]|[*] http://ip:port  code:200 len:443  title:… server:… [指纹]`（Web 标题）、
//     `[!] MySQL ip:port user:pass`（弱口令）、`[!] SSH密码认证成功: ip:port [user:pass]`、
//     `[!] 检测到漏洞 url poc-name`（POC 命中）、`[!] Svc ip:port 未授权访问`、
//     `[!] MS17-010漏洞 (ip)`、`[+] alive ip`（存活）；
//     result.txt 段：`# ===== 开放端口/服务信息/Web服务 =====` 下各自的行形态。
//   - 经典 1.x（目标侧老二进制回传）：`[+] StartScan`、`[*] 存活主机`、`[+] ip`、
//     `ip:port open`、`[+] ip:port 服务`、`http://ip:port [200] 标题`、
//     `[+] ip:port user pass`、`[!] ip 漏洞名`。
//
// 事实映射（与 nmap/httpx/nuclei 同口径，档案 §4.5）：
//   - 存活主机 → target/<host>（confirmed，TCP 连通即实证）
//   - 开放端口+服务 → infra/<ip>:<port>-<svc>（tentative；fscan 不产版本信息）
//   - Web 响应/标题 → target/<host>（confirmed）body 追加标题与状态码
//   - 弱口令命中 → auth/<ip>:<port>-<svc>-<user>（confirmed：登录成功是实证——高优先级事实）
//   - POC/漏洞命中 → finding/<slug>-<host>[-<port>]（tentative，复核链路升级——高优先级事实）
//
// 边：target/<host> --contains--> infra/*；target/<host> --discovered_on--> auth/finding。
type fscanParser struct{}

func (fscanParser) Tools() []string { return []string{"fscan"} }

// Match：fscan 文本输出无注入标志，按工具名全量接管（解析内部有 banner 特征门禁）。
func (fscanParser) Match(tool string, argv []string) bool { return tool == "fscan" }

// ── 特征与行形态 ──

// fscanFeatureRe 输入特征门禁（零误报）：v2 banner「Fscan <数字版本>」、
// v2 服务插件行、v2 完成摘要、经典 StartScan。四者皆无 → 判非 fscan 输出（fail-closed）。
var fscanFeatureRes = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^\s*Fscan\s+\d`),      // v2 banner（ASCII 艺术框下方的版本行）
	regexp.MustCompile(`(?m)^\[\*\]\s*服务插件:`),     // v2 插件清单行
	regexp.MustCompile(`扫描完成，发现\s*\d+\s*个开放端口`),   // v2 完成摘要
	regexp.MustCompile(`(?m)^\[\+\]\s*StartScan`), // 经典 1.x 启动行
}

var (
	// fscanHostPortRe host:port（IPv4/域名/括号 IPv6）
	fscanHostPortRe = regexp.MustCompile(`^(\[[0-9A-Fa-f:]+\]|[0-9A-Za-z._-]+):(\d{1,5})$`)
	// fscanBareIPRe 裸 IP/主机名（经典存活行 `[+] ip`；不含端口与斜杠）
	fscanBareIPRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.-]*$`)
	// fscanWebTitleRe v2 Web 标题行：URL code:len:title（title 可含空格，懒匹配到可选的 server: 段）
	fscanWebTitleRe = regexp.MustCompile(`^(https?://\S+?)\s+code:(\d{3})\s+len:(\d+)\s+title:(.+?)(?:\s+server:(.+))?$`)
	// fscanClassicWebRe 经典 Web 行：`http://ip:port [200] 标题`（result.txt 服务信息段为
	// `http://ip:port [标题] 200 server`——括号内容非数字时按标题处理、状态码取后续数字词）
	fscanClassicWebRe = regexp.MustCompile(`^(https?://\S+?)\s+\[([^\]]*)\]\s*(.*)$`)
	// fscanURLRe 行首 URL（服务识别/Web 段兜底）
	fscanURLRe = regexp.MustCompile(`^(https?)://(\[[0-9A-Fa-f:]+\]|[0-9A-Za-z._-]+)(?::(\d{1,5}))?\b`)
	// fscanV2CredRe v2 弱口令：`MySQL ip:port user:pass`（i18n: "MySQL {{t}} {{u}}:{{p}}" 族）
	fscanV2CredRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_-]*)\s+(\[[0-9A-Fa-f:]+\]|[0-9A-Za-z._-]+:\d{1,5})\s+([^\s:]+):([^\s:]+)\s*$`)
	// fscanSSHKeyPwdRe v2 SSH 命中：`SSH密码认证成功: ip:port [user:pass]`
	fscanSSHKeyPwdRe = regexp.MustCompile(`认证成功:?\s*(\[[0-9A-Fa-f:]+\]|[0-9A-Za-z._-]+:\d{1,5})\s*\[([^\s:\]]+):([^\s:\]]+)\]`)
	// fscanPocHitRe v2 POC 命中：`检测到漏洞 <url> <poc-name>`
	fscanPocHitRe = regexp.MustCompile(`检测到漏洞\s+(\S+)\s+(\S+)`)
	// fscanUnauthRe v2 未授权：`Redis ip:port 未授权访问`
	fscanUnauthRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_-]*)\s+(\[[0-9A-Fa-f:]+\]|[0-9A-Za-z._-]+:\d{1,5})\s+未授权`)
	// fscanMS17010Re MS17-010 族命中（含 DOUBLEPULSAR 后门）
	fscanMS17010Re = regexp.MustCompile(`MS17[-_]010`)
	// fscanPortOpenZhRe v2 中文端口行：`端口开放 ip:port [http](HTTP探测)?`
	fscanPortOpenZhRe = regexp.MustCompile(`^端口开放\s+(\[[0-9A-Fa-f:]+\]|[0-9A-Za-z._-]+:\d{1,5})`)
	// fscanAliveRe v2 存活行：`alive ip`
	fscanAliveRe = regexp.MustCompile(`^alive\s+(\S+)$`)
	// fscanSectionRe result.txt 段头：`# ===== 开放端口 =====`
	fscanSectionRe = regexp.MustCompile(`^#\s*=====\s*(.+?)\s*=====\s*$`)
)

// fscanANSIRe ANSI 转义序列（终端回传/管道混入时剥离）
var fscanANSIRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// fscanKnownSvc 已知服务名词表（区分「服务识别行」与「弱口令行」的第一词）
var fscanKnownSvc = map[string]bool{
	"mysql": true, "mariadb": true, "mssql": true, "oracle": true, "postgresql": true,
	"pgsql": true, "mongodb": true, "redis": true, "memcached": true, "elasticsearch": true,
	"neo4j": true, "rabbitmq": true, "rsync": true, "kafka": true, "cassandra": true,
	"ssh": true, "ftp": true, "smb": true, "telnet": true, "rdp": true, "vnc": true,
	"ldap": true, "snmp": true, "smtp": true, "pop3": true, "imap": true, "dns": true,
	"mssqlserver": true, "sqlserver": true, "http": true, "https": true,
}

// Parse 解析 fscan 文本输出。特征门禁不通过 → OK=false 零事实（fail-closed，
// 非 fscan 文本零误报）；通过后逐行提取，单行形态不符仅跳过该行。
func (p fscanParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "fscan", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	text := fscanANSIRe.ReplaceAllString(stdout, "")
	if strings.TrimSpace(text) == "" {
		return res, nil // 空输入：OK=true 零事实
	}
	if !fscanHasFeature(text) {
		res.OK = false
		res.Err = "非 fscan 输出（无 banner/插件行/完成摘要/StartScan 特征）"
		return res, nil
	}

	st := &fscanState{
		seenTarget:  map[string]bool{},
		seenInfra:   map[string]bool{},
		seenAuth:    map[string]bool{},
		seenFind:    map[string]bool{},
		hostBody:    map[string][]string{},
		portFactIdx: map[string]int{},
		portSvc:     map[string]string{},
		section:     "",
	}

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// result.txt 段头切换（挂钩层并入后 stdout 与文件段同流）
		if m := fscanSectionRe.FindStringSubmatch(trimmed); m != nil {
			st.section = m[1]
			continue
		}
		tag, rest := fscanSplitTag(trimmed)
		p.parseLine(st, res, tag, rest)
	}
	p.flushVulnDetail(st, res)

	// 计数字段（回执模型可见）
	res.Fields["hosts"] = len(st.seenTarget)
	res.Fields["open_ports"] = len(st.seenInfra)
	res.Fields["webs"] = st.webs
	res.Fields["weak_passwords"] = len(st.seenAuth)
	res.Fields["vulns"] = len(st.seenFind)
	return res, nil
}

// fscanState 单次解析的累积状态。
type fscanState struct {
	seenTarget map[string]bool
	seenInfra  map[string]bool
	seenAuth   map[string]bool
	seenFind   map[string]bool
	hostBody   map[string][]string
	section    string // result.txt 当前段名（开放端口/服务信息/Web服务…）
	webs       int
	// host:port → infra 事实在 Facts 里的下标与当前服务名（unknown → 已知服务名原地升级，
	// 避免「先裸端口行后服务识别行」产生 -unknown/-mysql 两条重复事实）
	portFactIdx map[string]int
	portSvc     map[string]string
	// v2 POC 多行明细（`[!] 目标: url` 后跟缩进的 漏洞类型/漏洞名称 行）
	vulnTarget string
	vulnType   string
	vulnName   string
}

// fscanHasFeature 特征门禁。
func fscanHasFeature(text string) bool {
	for _, re := range fscanFeatureRes {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// fscanSplitTag 剥离行首日志标记（[*] [+] [!] [-] [~]），返回 (tag, rest)。
func fscanSplitTag(line string) (string, string) {
	for _, tag := range []string{"[*]", "[+]", "[!]", "[-]", "[~]"} {
		if strings.HasPrefix(line, tag) {
			return tag, strings.TrimSpace(strings.TrimPrefix(line, tag))
		}
	}
	return "", line
}

// parseLine 单行分发。tag 为空 → result.txt 段内行或 POC 明细续行。
func (p fscanParser) parseLine(st *fscanState, res *Result, tag, rest string) {
	// ── POC 多行明细（`[!] 目标: url` 后跟缩进的 漏洞类型/漏洞名称 行；新判定行到达即落一条）──
	if st.vulnTarget != "" {
		if tag == "" && strings.HasPrefix(rest, "漏洞类型:") {
			st.vulnType = strings.TrimSpace(strings.TrimPrefix(rest, "漏洞类型:"))
			return
		}
		if tag == "" && strings.HasPrefix(rest, "漏洞名称:") {
			st.vulnName = strings.TrimSpace(strings.TrimPrefix(rest, "漏洞名称:"))
			return
		}
		p.flushVulnDetail(st, res)
	}

	// ── 存活主机 ──
	if m := fscanAliveRe.FindStringSubmatch(rest); m != nil && tag != "[-]" {
		p.addAlive(st, res, m[1])
		return
	}
	// 经典 1.x：`[+] ip`（裸主机行；要求含点，排除 `[+] StartScan` 之类的标记行）
	if tag == "[+]" && fscanBareIPRe.MatchString(rest) && strings.Contains(rest, ".") && !strings.ContainsAny(rest, ":/") {
		p.addAlive(st, res, rest)
		return
	}

	// ── URL 起始行（Web 服务识别 / Web 标题 / 服务信息段）──
	if fscanURLRe.MatchString(rest) {
		p.parseWebLine(st, res, tag, rest)
		return
	}

	// ── 中文端口开放行（v2）：`端口开放 ip:port` ──
	if m := fscanPortOpenZhRe.FindStringSubmatch(rest); m != nil {
		p.addPort(st, res, m[1], "unknown")
		return
	}

	// ── host:port 起始行 ──
	tokens := strings.Fields(rest)
	if len(tokens) > 0 && fscanHostPortRe.MatchString(tokens[0]) {
		p.parseHostPortLine(st, res, tag, tokens)
		return
	}

	// ── [!] 漏洞/弱口令杂行（非 host:port 起始形态）──
	if tag == "[!]" {
		p.parseVulnLine(st, res, rest)
	}
}

// parseHostPortLine `ip:port …` 行：开放端口 / 服务识别 / 弱口令。
func (p fscanParser) parseHostPortLine(st *fscanState, res *Result, tag string, tokens []string) {
	hostport := tokens[0]
	switch {
	case len(tokens) == 1:
		// 裸 `[*] ip:port`（v2 开放端口行，行尾有空白填充）或 result.txt 开放端口段
		if tag == "[*]" || tag == "" {
			p.addPort(st, res, hostport, "unknown")
		}
	case tokens[len(tokens)-1] == "open" && len(tokens) >= 2:
		// 经典：`ip:port open`
		p.addPort(st, res, hostport, "unknown")
	case len(tokens) >= 2 && fscanKnownSvc[strings.ToLower(tokens[1])]:
		// 服务识别：`ip:port mysql banner…`（v2/经典/result.txt 服务信息段）
		p.addPort(st, res, hostport, strings.ToLower(tokens[1]))
	case tag == "[+]" && len(tokens) == 3 && !strings.Contains(tokens[1]+tokens[2], ":"):
		// 经典弱口令（任务口径）：`[+] ip:port user pass`——首词非已知服务名
		p.addAuth(st, res, hostport, "unknown", tokens[1], tokens[2])
	}
}

// parseWebLine URL 起始行：v2 Web 标题 / 经典 Web 行 / v2 服务识别 / 段内裸 URL。
func (p fscanParser) parseWebLine(st *fscanState, res *Result, tag, rest string) {
	// v2 Web 标题：URL code:200 len:443 title:… server:… [指纹]
	if m := fscanWebTitleRe.FindStringSubmatch(rest); m != nil {
		url, code, title := m[1], m[2], m[4]
		if title == "None" {
			title = ""
		}
		p.addWeb(st, res, url, code, title)
		return
	}
	// 经典/服务信息段：`http://ip:port [200] 标题` 或 `http://ip:port [title] 200 server`
	if m := fscanClassicWebRe.FindStringSubmatch(rest); m != nil {
		url := m[1]
		// `[数字]` 为状态码 → 其后是标题；`[非数字]` 为标题 → 找随后的状态码
		if m[2] != "000" && isAllDigits(m[2]) {
			p.addWeb(st, res, url, m[2], strings.TrimSpace(m[3]))
			return
		}
		title := strings.Trim(m[2], "[]")
		code := ""
		for _, tok := range strings.Fields(m[3]) {
			if isAllDigits(tok) {
				code = tok
				break
			}
		}
		p.addWeb(st, res, url, code, title)
		return
	}
	// v2 服务识别：`http://ip:port  http  [Product:…] Banner:(…)`
	tokens := strings.Fields(rest)
	svc := ""
	if len(tokens) >= 2 {
		if fscanKnownSvc[strings.ToLower(tokens[1])] || tokens[1] == "https-gm" {
			svc = strings.ToLower(tokens[1])
		} else {
			svc = "http" // URL + 后续内容 → 至少识别为 Web 服务
		}
	} else {
		svc = "http" // 裸 URL（result.txt Web服务段）
	}
	if svc != "" {
		host, port := fscanSplitHostPortURL(rest)
		if hostport := fscanJoinHostPort(host, port); hostport != "" {
			p.addPort(st, res, hostport, svc)
			// URL 可达即目标存活（httpx 口径），标题缺失也给 target 实证
			p.addAlive(st, res, host)
		}
	}
}

// parseVulnLine `[!]` 杂行：v2 弱口令 / SSH 认证成功 / POC 命中 / 未授权 / MS17-010 / 经典 `ip 漏洞名`。
func (p fscanParser) parseVulnLine(st *fscanState, res *Result, rest string) {
	// v2 POC 命中：检测到漏洞 url poc-name
	if m := fscanPocHitRe.FindStringSubmatch(rest); m != nil {
		host, port := fscanSplitHostPortURL(m[1])
		name := m[2]
		if st.vulnName != "" {
			name = st.vulnName + "/" + name
		}
		p.addFinding(st, res, name, host, port, rest)
		return
	}
	// v2 多行明细头：`目标: url`（漏洞类型/名称在续行）
	if strings.HasPrefix(rest, "目标:") {
		p.flushVulnDetail(st, res)
		st.vulnTarget = strings.TrimSpace(strings.TrimPrefix(rest, "目标:"))
		return
	}
	// v2 SSH 命中：`SSH密码认证成功: ip:port [user:pass]`
	if m := fscanSSHKeyPwdRe.FindStringSubmatch(rest); m != nil {
		svc := "ssh"
		if strings.Contains(rest, "密钥") {
			svc = "ssh-key"
		}
		p.addAuth(st, res, m[1], svc, m[2], m[3])
		return
	}
	// v2 弱口令：`MySQL ip:port user:pass`
	if m := fscanV2CredRe.FindStringSubmatch(rest); m != nil {
		p.addAuth(st, res, m[2], strings.ToLower(m[1]), m[3], m[4])
		return
	}
	// v2 未授权：`Redis ip:port 未授权访问`
	if m := fscanUnauthRe.FindStringSubmatch(rest); m != nil {
		host, port := fscanSplitHostPort(m[2])
		p.addFinding(st, res, m[1]+"-unauthorized", host, port, rest)
		return
	}
	// MS17-010 族（`MS17-010漏洞 (ip)` / `MS17-010 ip has DOUBLEPULSAR SMB IMPLANT`）
	if fscanMS17010Re.MatchString(rest) {
		host, port := "", ""
		for _, tok := range strings.Fields(rest) {
			tok = strings.Trim(tok, "()[]，。")
			if h, pt := fscanSplitHostPort(tok); h != "" {
				host, port = h, pt
				break
			}
			if fscanBareIPRe.MatchString(tok) && strings.Contains(tok, ".") {
				host = tok
				break
			}
		}
		p.addFinding(st, res, "MS17-010", host, port, rest)
		return
	}
	// 经典（任务口径）：`[!] ip 漏洞名`
	tokens := strings.Fields(rest)
	if len(tokens) >= 2 && fscanBareIPRe.MatchString(tokens[0]) && strings.Contains(tokens[0], ".") {
		p.addFinding(st, res, strings.Join(tokens[1:], " "), tokens[0], "", rest)
	}
}

// flushVulnDetail 落一条 POC 多行明细（有目标时）。
func (p fscanParser) flushVulnDetail(st *fscanState, res *Result) {
	if st.vulnTarget == "" {
		return
	}
	host, port := fscanSplitHostPortURL(st.vulnTarget)
	name := st.vulnName
	if name == "" {
		name = st.vulnType
	}
	if name == "" {
		name = "poc"
	}
	p.addFinding(st, res, name, host, port, "目标: "+st.vulnTarget+"｜类型: "+st.vulnType+"｜名称: "+st.vulnName)
	st.vulnTarget, st.vulnType, st.vulnName = "", "", ""
}

// ── 事实构造 ──

func (p fscanParser) addAlive(st *fscanState, res *Result, host string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	slug := Sluggify(host)
	if slug == "" {
		return
	}
	key := "target/" + slug
	if !st.seenTarget[key] {
		st.seenTarget[key] = true
		res.Facts = append(res.Facts, FactCandidate{
			FactKey:    key,
			Category:   "target",
			Summary:    "存活主机: " + host + "（fscan）",
			Body:       "fscan 观测存活",
			Confidence: "confirmed",
		})
	}
}

func (p fscanParser) addPort(st *fscanState, res *Result, hostport, svc string) {
	host, port := fscanSplitHostPort(hostport)
	if host == "" || port == "" {
		return
	}
	svcSlug := Sluggify(svc)
	if svcSlug == "" {
		svcSlug = "unknown"
	}
	hp := Sluggify(host) + ":" + port

	// 已有该端口的事实：unknown → 已知服务原地升级；已知服务已存在 → 跳过
	if idx, ok := st.portFactIdx[hp]; ok {
		if st.portSvc[hp] != "unknown" {
			return
		}
		if svcSlug == "unknown" {
			return
		}
		oldKey := res.Facts[idx].FactKey
		delete(st.seenInfra, oldKey)
		st.seenInfra["infra/"+hp+"-"+svcSlug] = true
		st.portSvc[hp] = svcSlug
		res.Facts[idx].FactKey = "infra/" + hp + "-" + svcSlug
		res.Facts[idx].Summary = "开放端口+服务: " + port + "/" + svc + " @ " + host + "（fscan）"
		res.Facts[idx].Body = "端口: " + port + "｜服务: " + svc
		return
	}

	key := "infra/" + hp + "-" + svcSlug
	st.seenInfra[key] = true
	st.portSvc[hp] = svcSlug
	p.addAlive(st, res, host) // 可能追加 target 事实，先落再记下标
	st.portFactIdx[hp] = len(res.Facts)
	res.Facts = append(res.Facts, FactCandidate{
		FactKey:    key,
		Category:   "infra",
		Summary:    "开放端口+服务: " + port + "/" + svc + " @ " + host + "（fscan）",
		Body:       "端口: " + port + "｜服务: " + svc,
		Confidence: "tentative",
		Links:      []FactLink{{From: "target/" + Sluggify(host), Type: "contains"}},
	})
}

func (p fscanParser) addWeb(st *fscanState, res *Result, url, code, title string) {
	host, port := fscanSplitHostPortURL(url)
	if host == "" {
		return
	}
	st.webs++
	p.addAlive(st, res, host)
	entry := "Web: " + url
	if code != "" {
		entry += "｜状态码: " + code
	}
	if title != "" {
		entry += "｜标题: " + title
	}
	appendFactBody(res, "target/"+Sluggify(host), entry)
	// Web 端口同时落 infra（http/https），与端口扫描口径合并
	scheme := "http"
	if strings.HasPrefix(url, "https://") {
		scheme = "https"
	}
	if port != "" {
		p.addPort(st, res, host+":"+port, scheme)
	}
}

func (p fscanParser) addAuth(st *fscanState, res *Result, hostport, svc, user, pass string) {
	host, port := fscanSplitHostPort(hostport)
	if host == "" || port == "" || user == "" {
		return
	}
	svcSlug := Sluggify(svc)
	if svcSlug == "" {
		svcSlug = "unknown"
	}
	key := "auth/" + Sluggify(host) + ":" + port + "-" + svcSlug + "-" + Sluggify(user)
	if st.seenAuth[key] {
		return
	}
	st.seenAuth[key] = true
	p.addAlive(st, res, host)
	res.Facts = append(res.Facts, FactCandidate{
		FactKey:    key,
		Category:   "auth",
		Summary:    "弱口令命中: " + svc + " " + user + "@" + host + ":" + port + "（fscan）",
		Body:       "服务: " + svc + "｜账号: " + user + "｜口令: " + pass + "｜来源: fscan 爆破登录成功实证",
		Confidence: "confirmed",
		Links:      []FactLink{{From: "target/" + Sluggify(host), Type: "discovered_on"}},
	})
}

func (p fscanParser) addFinding(st *fscanState, res *Result, name, host, port, evidence string) {
	if host == "" {
		return
	}
	slug := Sluggify(name)
	if slug == "" {
		slug = "vuln"
	}
	key := "finding/" + slug + "-" + Sluggify(host)
	if port != "" {
		key += "-" + port
	}
	if st.seenFind[key] {
		return
	}
	st.seenFind[key] = true
	p.addAlive(st, res, host)
	res.Facts = append(res.Facts, FactCandidate{
		FactKey:    key,
		Category:   "finding",
		Summary:    "fscan 命中: " + name + " @ " + host + portSuffix(port),
		Body:       "漏洞/POC: " + name + "｜证据行: " + truncateRunes(evidence, 200),
		Confidence: "tentative",
		Links:      []FactLink{{From: "target/" + Sluggify(host), Type: "discovered_on"}},
	})
}

// ── 小工具 ──

// fscanSplitHostPort 拆 `host:port`（IPv6 括号形态兼容）；不合法返回 ("", "")。
func fscanSplitHostPort(s string) (string, string) {
	m := fscanHostPortRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", ""
	}
	return strings.Trim(m[1], "[]"), m[2]
}

// fscanSplitHostPortURL 从 URL 提取 host/port（无端口按 scheme 缺省 80/443）。
func fscanSplitHostPortURL(rawURL string) (string, string) {
	m := fscanURLRe.FindStringSubmatch(rawURL)
	if m == nil {
		// 非完整 URL：按 host:port 兜底
		return fscanSplitHostPort(rawURL)
	}
	port := m[3]
	if port == "" {
		if m[1] == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return strings.Trim(m[2], "[]"), port
}

// fscanJoinHostPort 拼回 `host:port`（host 为空返回 ""）。
func fscanJoinHostPort(host, port string) string {
	if host == "" || port == "" {
		return ""
	}
	return host + ":" + port
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func portSuffix(port string) string {
	if port == "" {
		return ""
	}
	return ":" + port
}

// truncateRunes 按字符截断（证据行防超长）。
func truncateRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
