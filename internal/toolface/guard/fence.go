package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/kernel/askernel"
	"github.com/c1ayooo/4zrec/internal/toolface/intercept"
)

// =====================================================================
// 资产围栏(执行侧授权闸门)—— 框架层强制,不依赖提示词。
//
// 渗透过程中 agent 可能把命令直接打向「未获授权的目标」(扫描输出里新看到的
// IP/域名,未经 insert_assets 登记、未经人工批准)。本闸门在 guard.PreToolUse
// 这个对话/任务共享的单咽喉上:
//
//  1. 从出网类工具(Bash/shell_open/shell_send/WebFetch/http_probe)的输入提取
//     目标对象(IP/域名/URL host):Bash 走「命令对象」解析,http_probe 按字段
//     结构化取 URL(见 fenceToolTargets/fence_http.go);
//  2. 命中全局/任务黑名单 → 硬阻断(平台管控文案);
//  3. 目标已获授权(项目范围命中,或库中 authz='approved' 的资产)→ 放行;
//  4. 其余 → 合成 ask 审批(复用 intercept.HandleAsk:pending 记录 + 内联卡片 +
//     无限等待,与「审批长阻塞」不变量一致);人工批准 → 目标就地登记为
//     approved 资产(批准即授权,后续不再询问)并放行本次调用;拒绝/取消 → 阻断。
//
// 未挂项目的任务/会话不启用围栏(projectID=0),保持旧行为,项目可渐进接入。
// 已知边界:只拦命令文本中字面可见的目标;变量拼接、IPv6、先解析再打等形态
// 不在第一版覆盖内(见 docs/asset-fence)。代码标识符(re.findall/os.path 等)
// 已由 TLD 后缀白名单排除,冷门后缀的真实域名会漏拦(宁漏勿扰,见
// tldAllowlist 注释)。纯十进制三段 IP 变体(1.2.3=1.2.0.3)与版本号碎片同形,
// 刻意不判(suspiciousIPVariant 注释);整数/八进制/十六进制变体已覆盖。
// =====================================================================

// fenceTargets 是一次提取出的目标对象集合。Opaque 表示命令会联网、但静态
// 无法确定其实际对象（解释器脚本、未知命令、不可读的目标列表等）；此时围栏
// 必须走审批，而不是因为「没提取到字面目标」就放行。
type fenceTargets struct {
	Domains []string
	IPs     []string
	Opaque  bool
	Reason  string
}

func (t fenceTargets) empty() bool { return len(t.Domains) == 0 && len(t.IPs) == 0 }

func (t fenceTargets) list() []string {
	out := append([]string(nil), t.Domains...)
	out = append(out, t.IPs...)
	return out
}

// reURL 抓取带 scheme 的 URL(含 //host 形态),先于裸 token 提取,避免把
// URL 的 path/query 误当域名。

// reIPv4 独立提取 IPv4(四组 1-3 位数字,边界由前后字符校验兜底)。

// reToken 裸 token 切分:非 [字母数字.-] 均为分隔符。

// reQuoted 单引号段:shell 里它们是字面载荷——python -c 代码、awk/sed 脚本、
// curl -d 的 JSON 数据、解析日志用的正则——里面的裸 token 是代码/数据不是命令
// 行目标,从裸 token 扫描中整段剔除。双引号不剔除:双引号常用来包裹真实参数
// (nmap "sub.example.com"),漏掉真实目标的代价大于双引号载荷里偶发的裸域名
// 噪音(后者还有 TLD 白名单兜底)。带 scheme 的 URL 不在此列——第一步已在全
// 文提取,引号内外一视同仁。
//
// 反引号不剔除(2026-10-16 围栏加固):反引号与 $() 是同一语义的命令替换,
// 运行时都会执行并展开——只剔除反引号等于给"把目标藏进替换体"留了一条单
// 向通道(`dig +short evil.com` 隐身而 $(dig ...) 不隐身)。剔除后的噪音由
// TLD 白名单与扩展名黑名单兜底。

// reEmailParam 匹配查询参数位的邮箱(紧邻 =/?/&/双引号),提取时整体剔除。

// reHeredocStart 匹配 heredoc 开始(<<EOF / <<-'EOF';<<< here-string 变体通过
// 前置字符约束排除:<< 前不能再是 <)。Go 的 RE2 不支持反向引用/环视,结束
// 标记(单独成行的同名 TAG)由 stripHeredocs 手工扫描。
var reHeredocStart = regexp.MustCompile(`(?:^|[^<])<<-?[ \t]*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// reCodePayload 匹配解释器的内联代码参数(python3 -c "…"、node -e "…"):
// 这类双引号段是代码,里面的裸 token(m.group、re.findall)不是命令行目标。
// 整体从裸 token 扫描中剔除;段内带 scheme 的 URL 已在第一步全文提取,不丢目标。

// stripHeredocs 把每段 heredoc(开始标记之后到单独成行的同名结束标记)整体
// 替换为空格:heredoc 是喂给 stdin 的脚本/数据,里面的裸 token 不是命令行
// 目标(worker 写 python 脚本的常态形态,m.group/re.finditer 是任务实测
// 最大误报源);段内的出网目标只会以 URL 形态出现,而 URL 已在第一步全文
// 提取。未闭合的 heredoc 只剔除开始标记本身、保留其余全部文本——此前"余下
// 全当载荷"的写法意味着一行合法前缀(cat <<EOF)就能让后续所有目标对围栏
// 隐身;宁可多扫到几段代码 token(TLD 白名单可兜住),不给整段消失留通道。
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
var tldAllowlist = db.TLDAllowlist

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
func (t fenceTargets) displayList() string {
	all := t.list()
	if len(all) <= 32 {
		return strings.Join(all, "、")
	}
	return strings.Join(all[:32], "、") + fmt.Sprintf(" 等 %d 个目标", len(all))
}

// AssetFence 是资产围栏的 DB 支撑实现(guard 通过接口持有,便于测试替身)。
type AssetFence struct {
	dbh *db.DB
}

// NewAssetFence 构造围栏;dbh 为nil时围栏不生效。
func NewAssetFence(dbh *db.DB) *AssetFence { return &AssetFence{dbh: dbh} }

// fenceDecision 是一次围栏判定的结果。
type fenceDecision struct {
	ProjectID    int64
	Targets      fenceTargets // 本次提取到的全部目标
	Unauthorized fenceTargets // 其中未获授权的子集(审批/展示/登记只认它)
	Allow        bool         // true=放行(已授权或无目标/无项目)
	HardBlock    bool         // true=命中黑名单,直接阻断
	Opaque       bool         // true=命令联网但对象不可静态确定,必须审批
	Reason       string       // HardBlock 或 Ask 的说明
}

// fenceTargetPayload 是审批记录里持久化的结构化目标(domains/ips 分列,
// 前端按类型渲染复选框,批准时按勾选子集登记授权)。
type fenceTargetPayload struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

func (t fenceTargets) payload() json.RawMessage {
	raw, _ := json.Marshal(fenceTargetPayload{Domains: t.Domains, IPs: t.IPs})
	return raw
}

// evaluate 执行判定:黑名单 → 未授权(ask) → 放行。
func (f *AssetFence) evaluate(ctx context.Context, toolName string, input []byte) fenceDecision {
	if f == nil || f.dbh == nil {
		return fenceDecision{Allow: true}
	}
	projectID := f.resolveProject(ctx)
	if projectID <= 0 {
		return fenceDecision{Allow: true}
	}
	// 按「对象」解析:Bash 取命令目标操作数;http_probe 按字段结构化取 URL
	// (proxy/headers/body 不参与);解释器/未知命令无法静态确定对象则 Opaque,
	// 交给人工审批——不能因为没提取到字面目标就放行。
	targets := fenceToolTargets(toolName, input, intercept.ReviewWorkingDirectory(ctx))
	if targets.empty() && !targets.Opaque {
		return fenceDecision{Allow: true}
	}
	// 黑名单(全局 ∪ 任务级 block)优先:命中即硬阻断,不给审批机会。
	// Opaque 命令里已识别出的目标也要过黑名单（例如解释器代码里的 .gov 域名）。
	blockRules, _ := f.dbh.ListAssetInterceptRules()
	taskIDStr, _ := intercept.TaskInfoFromContext(ctx)
	if taskID := parseTaskID(taskIDStr); taskID > 0 {
		if tb, _, err := f.dbh.Assets().TaskInterceptRulesSplit(taskID); err == nil {
			blockRules = append(blockRules, tb...)
		}
	}
	if !targets.empty() {
		if rule, val, ok := db.MatchAssetInterceptRules(blockRules, targets.Domains, targets.IPs, nil); ok {
			return fenceDecision{
				ProjectID: projectID, Targets: targets, HardBlock: true,
				Reason: fmt.Sprintf("%s(命中值 %s)", rule.Reason(), val),
			}
		}
	}
	if targets.Opaque {
		return fenceDecision{
			ProjectID: projectID, Targets: targets, Opaque: true,
			Reason: targets.Reason,
		}
	}
	if f.dbh.AuthorizedTarget(projectID, targets.Domains, targets.IPs) {
		return fenceDecision{Allow: true, ProjectID: projectID, Targets: targets}
	}
	// 只把未授权的目标放进审批:文案与登记都用子集——已授权目标不再列进
	// 「不在授权范围内」,批准也不会把范围内目标重复写成资产。
	unauth := f.unauthorized(projectID, targets)
	return fenceDecision{
		ProjectID: projectID, Targets: targets, Unauthorized: unauth,
		Reason: "目标资产不在项目授权范围内：" + unauth.displayList() +
			"。若确属本次委托范围，请批准；否则请拒绝并改测授权内资产。",
	}
}

// unauthorized 逐目标判定授权状态,返回未授权子集(ALL 语义的补集)。
func (f *AssetFence) unauthorized(projectID int64, targets fenceTargets) fenceTargets {
	var out fenceTargets
	for _, dom := range targets.Domains {
		if !f.dbh.AuthorizedTarget(projectID, []string{dom}, nil) {
			out.Domains = append(out.Domains, dom)
		}
	}
	for _, ip := range targets.IPs {
		if !f.dbh.AuthorizedTarget(projectID, nil, []string{ip}) {
			out.IPs = append(out.IPs, ip)
		}
	}
	return out
}

// resolveProject 从上下文解析项目:任务优先,其次会话。
func (f *AssetFence) resolveProject(ctx context.Context) int64 {
	taskIDStr, _ := intercept.TaskInfoFromContext(ctx)
	if taskID := parseTaskID(taskIDStr); taskID > 0 {
		if pid, err := f.dbh.TaskProjectID(taskID); err == nil && pid > 0 {
			return pid
		}
	}
	if convID := intercept.ConvIDFromContext(ctx); convID > 0 {
		if pid, err := f.dbh.ConvProjectID(convID); err == nil && pid > 0 {
			return pid
		}
	}
	return 0
}

func parseTaskID(s string) int64 {
	id, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return id
}

// authorize 在人工批准后把目标就地登记为 approved 资产(批准即授权)。
func (f *AssetFence) authorize(projectID int64, targets fenceTargets) {
	if f == nil || f.dbh == nil || projectID <= 0 {
		return
	}
	for _, dom := range targets.Domains {
		if id, err := f.dbh.EnsureDiscoveredAsset(projectID, "subdomain", dom, ""); err == nil && id > 0 {
			_ = f.dbh.Assets().SetAssetAuthz([]int64{id}, "approved")
		}
	}
	for _, ip := range targets.IPs {
		if id, err := f.dbh.EnsureDiscoveredAsset(projectID, "ip", "", ip); err == nil && id > 0 {
			_ = f.dbh.Assets().SetAssetAuthz([]int64{id}, "approved")
		}
	}
}

// PendingProject 解析一条审批记录的归属项目:任务优先,其次会话;0=无项目。
func (f *AssetFence) PendingProject(p db.InterceptPending) int64 {
	if f == nil || f.dbh == nil {
		return 0
	}
	projectID := int64(0)
	if p.TaskID != nil {
		if tid := parseTaskID(*p.TaskID); tid > 0 {
			projectID, _ = f.dbh.TaskProjectID(tid)
		}
	}
	if projectID <= 0 && p.ConversationID != nil {
		projectID, _ = f.dbh.ConvProjectID(*p.ConversationID)
	}
	return projectID
}

// PendingTargets 返回一条围栏审批的目标清单:优先读记录里的结构化 targets
// (新记录);旧记录没有该列,退回从工具输入重新提取(按全部目标处理)。
func (f *AssetFence) PendingTargets(p db.InterceptPending) (domains, ips []string) {
	if len(p.Targets) > 0 {
		var payload fenceTargetPayload
		if json.Unmarshal(p.Targets, &payload) == nil &&
			(len(payload.Domains) > 0 || len(payload.IPs) > 0) {
			return payload.Domains, payload.IPs
		}
	}
	if !strings.Contains(p.Reason, "【资产围栏】") {
		return nil, nil
	}
	targets := fenceToolTargets(p.ToolName, p.ToolInput, "")
	return targets.Domains, targets.IPs
}

// Authorize 把人工批准的目标登记为 approved 资产(批准即授权)。供审批
// 决定接口按勾选子集调用。
func (f *AssetFence) Authorize(projectID int64, domains, ips []string) {
	f.authorize(projectID, fenceTargets{Domains: domains, IPs: ips})
}

// AskAuthorized 报告一条挂起的审批记录是否已因「资产获批」而可以放行——
// 资产批准联动的谓词(配合 intercept.ReleaseAsks):仅认【资产围栏】消息的
// 记录;从审批记录的归属(任务→项目,会话→项目)解析项目,对工具输入重提
// 目标,全部已获授权(项目范围或 approved 资产)即 true。普通拦截规则的
// ask 不受影响。
func (f *AssetFence) AskAuthorized(p db.InterceptPending) bool {
	if f == nil || f.dbh == nil {
		return false
	}
	if !strings.Contains(p.Reason, "【资产围栏】") {
		return false
	}
	projectID := f.PendingProject(p)
	if projectID <= 0 {
		return false
	}
	targets := fenceToolTargets(p.ToolName, p.ToolInput, "")
	if targets.empty() {
		return false
	}
	return f.dbh.AuthorizedTarget(projectID, targets.Domains, targets.IPs)
}

// applyFence 在工具规则判定之前执行资产围栏。返回值 true 表示已产生终局决定。
func (g *Guard) applyFence(ctx context.Context, ev askernel.Event) (askernel.Result, bool) {
	if g.fence == nil || g.interceptor == nil {
		return askernel.Result{}, false
	}
	d := g.fence.evaluate(ctx, ev.ToolName, ev.Input)
	if d.Allow {
		return askernel.Result{}, false
	}
	if d.HardBlock {
		return g.block(ev.ToolName, systemBlockMessage("目标资产命中拦截规则："+d.Reason), ""), true
	}
	// 未授权 → 合成 ask 审批(无限等待,与「审批长阻塞」不变量一致)。
	// 结构化目标随记录落库:审批页按目标复选(全选/部分),决定接口只把
	// 勾选的目标登记为 approved。
	dec := intercept.Decision{
		Action:  "ask",
		Message: "【资产围栏】" + d.Reason,
		Targets: d.Unauthorized.payload(),
	}
	convID := intercept.ConvIDFromContext(ctx)
	if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
		return g.block(ev.ToolName, systemBlockMessage("目标资产未获项目授权（人工拒绝或工作已取消）"), ""), true
	}
	// 批准后的登记动作在审批决定接口里按勾选子集完成(见 server.interceptDecide);
	// 这里不再无条件把全部目标写成 approved——旧实现会把范围内目标与
	// 未勾选目标一并登记。
	return askernel.Result{}, false
}
