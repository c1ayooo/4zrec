// 从 4zrec internal/toolface/guard/fence.go 抽出的纯助手（2026-10-24 移植）。
// 本文件不含宿主依赖；tldAllowlist 是 db.TLDAllowlist 的 vendored 副本，
// 改表需与 4zrec 侧同步（两仓库共享同一份判定口径）。

package guard

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// reHeredocStart 匹配 heredoc 开始（4zrec fence.go:83，stripHeredocs 消费）。
var reHeredocStart = regexp.MustCompile(`(?:^|[^<])<<-?[ \t]*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)

func stripHeredocs(text string) string {
	for {
		loc := reHeredocStart.FindStringSubmatchIndex(text)
		if loc == nil {
			return text
		}
		tag := text[loc[2]:loc[3]]
		// 结束标记:行首(可有空白)+ TAG + 行尾。
		endIdx := -1
		searchFrom := loc[1]
		for i := searchFrom; i < len(text); {
			nl := strings.IndexByte(text[i:], '\n')
			if nl < 0 {
				break
			}
			lineStart := i + nl + 1
			lineEnd := lineStart + strings.IndexByte(text[lineStart:], '\n')
			if lineEnd < lineStart {
				lineEnd = len(text)
			}
			line := strings.TrimSpace(text[lineStart:lineEnd])
			if line == tag {
				endIdx = lineEnd
				break
			}
			i = lineEnd
		}
		if endIdx < 0 {
			// 未闭合:只抹掉开始标记,标记后的文本(含同行后续命令)保留提取。
			// 保留标记前一字符(前缀约束吃掉的那个),避免贴邻形态的目标被啃字。
			text = text[:loc[0]+1] + " " + text[loc[1]:]
			continue
		}
		text = text[:loc[0]+1] + " " + text[endIdx:]
	}
}

// extBlocklist 这些后缀的带点 token 几乎总是文件/库/配置名而非目标主机;
// 误拦的代价是多一次审批,误放的代价是越界测试,宁可保守但也要控制噪音。
var extBlocklist = map[string]bool{
	"sh": true, "py": true, "js": true, "ts": true, "go": true, "json": true,
	"xml": true, "yaml": true, "yml": true, "txt": true, "log": true, "md": true,
	"sql": true, "html": true, "htm": true, "css": true, "png": true, "jpg": true,
	"jpeg": true, "gif": true, "svg": true, "ico": true, "pdf": true, "doc": true,
	"docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true, "csv": true,
	"conf": true, "cfg": true, "ini": true, "env": true, "toml": true, "lock": true,
	"tar": true, "gz": true, "zip": true, "rar": true, "7z": true, "bak": true,
	"so": true, "a": true, "o": true, "dll": true, "exe": true, "bin": true,
	"deb": true, "rpm": true, "apk": true, "img": true, "iso": true, "old": true,
}

// fence 工具输入 → 命令文本。其余工具返回空(不参与围栏)。

func fenceCommandText(toolName string, input []byte) string {
	var in map[string]any
	if err := json.Unmarshal(input, &in); err != nil {
		return ""
	}
	str := func(k string) string {
		if v, ok := in[k].(string); ok {
			return v
		}
		return ""
	}
	switch toolName {
	case "Bash", "shell_open":
		return str("command")
	case "shell_send":
		return str("text")
	case "WebFetch":
		return str("url")
	case "http_probe":
		// 审计展示用:单发取 url,批量取首个请求的 url(http_probe 的目标提取
		// 在 fenceToolTargets 里按字段结构化进行,不走命令文本)。
		if u := str("url"); u != "" {
			return u
		}
		if reqs, ok := in["requests"].([]any); ok && len(reqs) > 0 {
			if first, ok := reqs[0].(map[string]any); ok {
				if u, ok := first["url"].(string); ok {
					return u
				}
			}
		}
		if tmpl, ok := in["template"].(map[string]any); ok {
			if u, ok := tmpl["url"].(string); ok {
				return u
			}
		}
		return ""
	}
	return ""
}

// fenceToolTargets 按工具提取围栏对象:Bash/shell 的「命令对象」、WebFetch 的
// URL、http_probe 的结构化 URL(url / requests[].url / template×matrix/range)。
// http_probe 的 proxy/headers/body/extract 等字段不是测试目标,绝不参与提取
// (见 fence_http.go)。返回空且非 Opaque 时,该调用不参与围栏。
func fenceToolTargets(toolName string, input []byte, workDir string) fenceTargets {
	switch toolName {
	case "Bash", "shell_open", "WebFetch":
		return ExtractFenceTargetsWithDir(fenceCommandText(toolName, input), workDir)
	case "shell_send":
		// 往已授权的交互会话里输入的内容:只用字面目标提取,不按未知命令判 Opaque。
		return extractFenceTargetsLegacy(fenceCommandText(toolName, input))
	case "http_probe":
		return extractHTTPProbeTargets(input)
	}
	return fenceTargets{}
}

// validFenceIPv4 校验四组 octet ≤255;loopback/未指定地址不是渗透目标。

func validFenceIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return false
		}
		if len(p) > 1 && p[0] == '0' {
			return false
		}
	}
	if ip := net.ParseIP(s); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return false
	}
	return true
}

// inetAtonIP 按 glibc inet_aton 语义把 IP 变体归一化为标准点分十进制:
// 每段可用十进制/前导 0 八进制/0x 十六进制;不足 4 段时末段占多字节
// (a.b.c → a.b.0.c;a → 整个 32 位)。解析失败返回空串。
// 背景(2026-10-16 围栏加固):curl/wget/ping 都接受这些形态,16909060、
// 0x7f000001、0177.0.0.1 此前两条校验路都过不了,被静默丢弃。
func inetAtonIP(s string) string {
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return ""
	}
	var val uint64
	for i, p := range parts {
		if p == "" {
			return ""
		}
		var n uint64
		var err error
		switch {
		case len(p) > 2 && (p[:2] == "0x" || p[:2] == "0X"):
			n, err = strconv.ParseUint(p[2:], 16, 64)
		case len(p) > 1 && p[0] == '0':
			n, err = strconv.ParseUint(p[1:], 8, 64)
		default:
			n, err = strconv.ParseUint(p, 10, 64)
		}
		if err != nil {
			return ""
		}
		// 末段可占剩余全部字节(共 k 段时末段占 5-k 字节),非末段必须单字节。
		if i == len(parts)-1 {
			rem := uint64(1) << uint(8*(5-len(parts)))
			if n >= rem {
				return ""
			}
			val |= n
		} else {
			if n > 0xFF {
				return ""
			}
			val |= n << (8 * uint(3-i))
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
}

// suspiciousIPVariant 判定裸 token 是否为"带非十进制特征的 IP 变体":
//   - 无点形态:≥8 位纯数字(最小公网 1.0.0.0=16777216,端口号/PID 到不了
//     这个量级)或 8 位 0x 十六进制(=完整 32 位地址,如 0x7f000001);
//   - 有点形态:各段为十进制/0x 十六进制,且带前导零段、十六进制段或非法
//     四段(某段 >255)——纯十进制三段(1.2.3)刻意不判:它与版本号碎片完全
//     同形,误报代价高,维持"宁漏勿扰"(已知边界,见 fence.go 头注释)。
//
// 无点十六进制必须满 8 位:2~7 位(0x7e/0x27/0xffffff)是 payload 与代码里的
// 字节/掩码常量,不是地址。SQLi 的 concat(0x7e,version()) 曾被当成单段
// inet_aton 归一化成 0.0.0.126,把整条已授权命令拖进审批(2026-10-17 实测)。
//
// 命中的 token 由调用方归一化后按 IP 提取;归一化失败的仍按目标上报
// (fail-closed:宁可多一次审批,不给变体形态留静默放行)。
func suspiciousIPVariant(tok string) bool {
	if tok == "" {
		return false
	}
	if !strings.Contains(tok, ".") {
		if len(tok) >= 2 && (tok[:2] == "0x" || tok[:2] == "0X") {
			hex := tok[2:]
			if len(hex) < 8 {
				return false // 字节/掩码常量(0x7e、0x27、0xffffff),不是单段地址
			}
			n, err := strconv.ParseUint(hex, 16, 64)
			return err == nil && n <= 0xFFFFFFFF
		}
		if len(tok) >= 8 && len(tok) <= 10 {
			n, err := strconv.ParseUint(tok, 10, 64)
			return err == nil && n <= 0xFFFFFFFF
		}
		return false
	}
	parts := strings.Split(tok, ".")
	if len(parts) < 3 {
		return false // 两段小数(3.14/2.0)与三段纯十进制(1.2.3)不判,见上
	}
	suspicious := false
	for _, p := range parts {
		if p == "" {
			return false
		}
		if len(p) > 2 && (p[:2] == "0x" || p[:2] == "0X") {
			if _, err := strconv.ParseUint(p[2:], 16, 64); err != nil {
				return false
			}
			suspicious = true
			continue
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return false // 含非数字字符:不是 IP 变体
		}
		if len(p) > 1 && p[0] == '0' {
			suspicious = true // 前导零(八进制)
		}
		if len(parts) == 4 && n > 0xFF {
			suspicious = true // 非法四段(10.0.0.256 这类打错的/变体目标)
		}
	}
	return suspicious
}

// tldAllowlist 引用 db.TLDAllowlist(单一事实源,范围候选生成器共用同一张
// 表):代码标识符的尾缀——re.findall 的 findall、os.path 的 path、
// json.dumps 的 dumps——不在表内,一律不当作目标。URL host 分支同样走这张
// 表(见 urlHostIsTarget),只对单段内网短名豁免。扩表直接改 db.TLDAllowlist。
// tldAllowlist 是真实 TLD 后缀白名单:常见通用/国别 TLD + 内网伪 TLD +
// ICANN 保留字。两处消费:①范围候选生成器——把代码标识符化石(f.write、
// data.get、json.loads 这类旧 bug 存进资产的脏数据)挡在候选之外;②执行侧
// 围栏的裸 token 域名校验(guard 包引用本表,单一事实源)。冷门新 TLD 会
// 漏——宁漏勿扰:漏拦只是少问一次,误拦是每个脚本都要审批。
var tldAllowlist = map[string]bool{
	// 通用/主流
	"com": true, "net": true, "org": true, "edu": true, "gov": true,
	"mil": true, "int": true, "info": true, "biz": true, "io": true,
	"co": true, "ai": true, "app": true, "dev": true, "cloud": true,
	"tech": true, "xyz": true, "top": true, "vip": true, "site": true,
	"online": true, "shop": true, "club": true, "fun": true, "ltd": true,
	"group": true, "work": true, "website": true, "space": true, "icu": true,
	"pro": true, "live": true, "life": true, "me": true, "tv": true, "cc": true,
	// 常见国家/地区
	"cn": true, "uk": true, "jp": true, "kr": true, "hk": true, "tw": true,
	"ru": true, "in": true, "de": true, "fr": true, "it": true, "nl": true,
	"se": true, "es": true, "br": true, "au": true, "ca": true, "us": true,
	"sg": true, "my": true, "th": true, "id": true, "vn": true, "ph": true,
	"nz": true, "za": true, "il": true, "ae": true, "sa": true, "mx": true,
	"ar": true, "cl": true, "ch": true, "pl": true, "pt": true, "cz": true,
	"gr": true, "hu": true, "ro": true, "ua": true,
	// 内网命名伪 TLD(渗透现场常见内部主机名)
	"local": true, "internal": true, "corp": true, "lan": true,
	"prod": true, "lab": true, "vpn": true, "staging": true, "intranet": true,
	// ICANN 保留(文档/测试用,测试夹具大量使用 *.example)
	"example": true, "invalid": true, "test": true,
}

// validFenceDomain 校验裸 token 是否像主机名:≥2 个 label、末 label 在
// TLD 白名单内(见 tldAllowlist)、各 label 合法、后缀不在文件扩展名黑名单。
func validFenceDomain(s string) bool {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if len(s) < 4 || len(s) > 253 || strings.Contains(s, "..") {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	tld := labels[len(labels)-1]
	if extBlocklist[tld] {
		return false
	}
	if !tldAllowlist[tld] {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// allDigits 判断字符串是否全为十进制数字(空串为 false)。
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// nonTargetSingleLabelHosts 单段主机名里明显不是目标的名字:本机回环名与
// 文档/代码里的占位符。真实的单段内网主机名(jira、gitlab、dc01)仍按
// 目标处理——不因为"没有点"就放行,否则 `curl http://intranet/` 成为
// 围栏盲区。
var nonTargetSingleLabelHosts = map[string]bool{
	"localhost": true, "ip6-localhost": true, "host": true, "hostname": true,
	"target": true, "example": true, "domain": true, "server": true, "url": true,
}

// urlHostIsTarget 判定 URL 的 host 是否是值得围栏的目标。URL 分支此前不做
// 任何校验(占位符/文档文本都会变成目标),现在与裸 token 分支同口径:
// 带点的主机过 TLD 白名单 + 文件扩展名黑名单;单段主机名保留(内网短名是
// 真目标),只排除本机名/占位符/单字符伪主机。
func urlHostIsTarget(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return false
	}
	if !strings.Contains(h, ".") {
		return len(h) >= 2 && !nonTargetSingleLabelHosts[h]
	}
	return validFenceDomain(h)
}

// urlHost 从 URL 提取 host(去用户信息/端口/shell 变量尾巴)。不直接用
// url.Parse:端口里含变量(host:8000$p)会让它整体失败,目标就此隐身——
// 手工按 authority 截取更稳。
func urlHost(u string) string {
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	} else if strings.HasPrefix(rest, "//") {
		rest = rest[2:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	// 渗透脚本常把 shell 变量拼进 URL(woniuxy.com$2 —— 循环/函数参数拼
	// 路径是常态),字面 token 会带着 $ 尾巴:剥掉再归类;剥完为空(整个
	// host 都是变量)或以裸 $ 结尾(变量表达式被 URL 正则截断,如
	// x.${port}a)都整段丢弃——变量运行时才展开,不可见即宁漏勿扰。
	if i := strings.Index(rest, "$"); i >= 0 {
		if i == len(rest)-1 {
			return ""
		}
		rest = rest[:i]
	}
	// IPv6 字面量:[::1] → ::1(端口剥离对多冒号地址不适用)。
	if strings.HasPrefix(rest, "[") {
		if i := strings.Index(rest, "]"); i > 0 {
			return rest[1:i]
		}
		return ""
	}
	// 端口:单冒号且冒号后纯数字才按端口处理。
	if strings.Count(rest, ":") == 1 {
		if i := strings.IndexByte(rest, ':'); i > 0 && allDigits(rest[i+1:]) {
			rest = rest[:i]
		}
	}
	return strings.TrimSpace(rest)
}

// publicInfraIPs 是公网公共基础设施地址(以公共 DNS 解析器为主):dig/nslookup
// 拿它们当解析器是正常操作,不是「测试目标」——从围栏提取中直接排除,否则
// 每条 dig @8.8.8.8 都要弹一次审批(用户拍板:这类地址不应进围栏)。
// 需要扩表(如内网解析器)时往这里加一行即可。

var publicInfraIPs = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true, // Google
	"1.1.1.1": true, "1.0.0.1": true, // Cloudflare
	"9.9.9.9": true, "149.112.112.112": true, // Quad9
	"208.67.222.222": true, "208.67.220.220": true, // OpenDNS
	"94.140.14.14": true, "94.140.15.15": true, // AdGuard
	"223.5.5.5": true, "223.6.6.6": true, // AliDNS
	"119.29.29.29": true, "182.254.116.116": true, // DNSPod
	"114.114.114.114": true, "114.114.115.115": true, // 114DNS
	"180.76.76.76": true,                    // Baidu
	"1.2.4.8":      true, "210.2.4.8": true, // CNNIC
	// IPv6 公共解析器(围栏不提取 IPv6;空间测绘导入过滤复用本表)
	"2001:4860:4860::8888": true, "2001:4860:4860::8844": true, // Google
	"2606:4700:4700::1111": true, "2606:4700:4700::1001": true, // Cloudflare
	"2620:fe::fe": true, "2620:fe::9": true, // Quad9
	"2400:3200::1": true, "2400:3200:baba::1": true, // AliDNS
	"2402:4e00::": true, "2400:da00::6666": true, // DNSPod / Baidu
}

// IsPublicInfraIP 报告 ip 是否是公共基础设施地址(公共 DNS 解析器等)。
// 空间测绘导入等旁路复用它过滤噪音;围栏提取仍直接查 publicInfraIPs。
func IsPublicInfraIP(ip string) bool {
	return publicInfraIPs[strings.TrimSpace(ip)]
}

// displayList 供审批文案使用的目标清单:超过 32 条截断并标注总数。只影响
// 展示——判定与登记永远用完整列表(见 ExtractFenceTargets 尾注)。

// displayList 供审批文案使用的目标清单:超过 32 条截断并标注总数。只影响
// 展示,不影响判定。
func (t fenceTargets) displayList() string {
	all := t.list()
	if len(all) <= 32 {
		return strings.Join(all, "、")
	}
	return strings.Join(all[:32], "、") + fmt.Sprintf(" 等 %d 个目标", len(all))
}
