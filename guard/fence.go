package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/askernel"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// =====================================================================
// 资产围栏(执行侧授权闸门)—— 框架层强制,不依赖提示词。
//
// 渗透过程中 agent 可能把命令直接打向「未获授权的目标」(扫描输出里新看到的
// IP/域名,未经 insert_assets 登记、未经人工批准)。本闸门在 guard.PreToolUse
// 这个对话/任务共享的单咽喉上:
//
//  1. 从出网类工具(Bash/shell_open/shell_send/WebFetch)的输入提取字面目标
//     (IP/域名/URL host);
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
// tldAllowlist 注释)。
// =====================================================================

// fenceTargets 是一次提取出的字面目标集合。
type fenceTargets struct {
	Domains []string
	IPs     []string
}

func (t fenceTargets) empty() bool { return len(t.Domains) == 0 && len(t.IPs) == 0 }

func (t fenceTargets) list() []string {
	out := append([]string(nil), t.Domains...)
	out = append(out, t.IPs...)
	return out
}

// reURL 抓取带 scheme 的 URL(含 //host 形态),先于裸 token 提取,避免把
// URL 的 path/query 误当域名。
var reURL = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]*)?://[^\s"'<>()\[\]{}]+`)

// reIPv4 独立提取 IPv4(四组 1-3 位数字,边界由前后字符校验兜底)。
var reIPv4 = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)

// reToken 裸 token 切分:非 [字母数字.-] 均为分隔符。
var reToken = regexp.MustCompile(`[a-z0-9.-]+`)

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
	}
	return ""
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

// tldAllowlist 是裸 token 域名校验的后缀白名单:常见真实 TLD(渗透目标里
// 实际会出现的)+ 内网命名伪 TLD + ICANN 保留字。代码标识符的尾缀——
// re.findall 的 findall、os.path 的 path、json.dumps 的 dumps——不在表内,
// 一律不当作目标:Python 一行流/脚本里的模块属性引用不再触发围栏审批。
// URL host 分支不受此表影响(能被 url.Parse 解析出 host 的可信度高)。
// 未列出的冷门新 TLD 会漏拦(宁漏勿扰:漏拦只是少问一次,误拦是每个脚本
// 都要审批);发现实际目标命中冷门后缀时往这张表加一行即可。
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

// ExtractFenceTargets 从任意文本提取字面目标(IPv4 + 域名,URL 的 host 归类)。
// 提取顺序:URL(剥离)→ IPv4 → 裸域名 token。导出供测试与后续网络层兜底复用。
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
		if ip != "" && !seen["i:"+ip] {
			seen["i:"+ip] = true
			t.IPs = append(t.IPs, ip)
		}
	}
	rest := text
	// 1) URL:取 host(去端口),按 IP/域名归类后从剩余文本剔除整段 URL。
	for _, m := range reURL.FindAllString(text, -1) {
		u := m
		if !strings.Contains(u, "://") {
			u = "http:" + u
		}
		if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
			host := parsed.Hostname()
			if pip := net.ParseIP(host); pip != nil {
				if pip.To4() != nil && validFenceIPv4(pip.String()) {
					addIP(pip.String())
				}
			} else {
				addDomain(host)
			}
		}
		rest = strings.ReplaceAll(rest, m, " ")
	}
	lower := strings.ToLower(rest)
	// 2) IPv4(边界校验:前后不能是数字或点,避免版本号 1.2.3.4.5 的截断误报)。
	for _, loc := range reIPv4.FindAllStringIndex(lower, -1) {
		s, e := loc[0], loc[1]
		if s > 0 {
			c := lower[s-1]
			if (c >= '0' && c <= '9') || c == '.' {
				continue
			}
		}
		if e < len(lower) {
			c := lower[e]
			if (c >= '0' && c <= '9') || c == '.' {
				continue
			}
		}
		cand := lower[s:e]
		if validFenceIPv4(cand) {
			addIP(cand)
		}
	}
	// 3) 裸域名 token(跳过 URL 段,已剔除)。
	for _, tok := range reToken.FindAllString(lower, -1) {
		if !strings.Contains(tok, ".") {
			continue
		}
		// 纯数字/点已由 IPv4 分支处理
		if validFenceIPv4(tok) || net.ParseIP(tok) != nil {
			continue
		}
		if validFenceDomain(tok) {
			addDomain(tok)
		}
	}
	sort.Strings(t.Domains)
	sort.Strings(t.IPs)
	// 上限保护:超长目标集(如整段 IP 清单)截断,防止审批消息爆炸;
	// 授权判定仍用截断前结果由调用方控制(此处只影响展示)。
	if len(t.Domains) > 32 {
		t.Domains = t.Domains[:32]
	}
	if len(t.IPs) > 32 {
		t.IPs = t.IPs[:32]
	}
	return t
}

// AssetFence 是资产围栏的 DB 支撑实现(guard 通过接口持有,便于测试替身)。
type AssetFence struct {
	dbh *db.DB
}

// NewAssetFence 构造围栏;dbh 为nil时围栏不生效。
func NewAssetFence(dbh *db.DB) *AssetFence { return &AssetFence{dbh: dbh} }

// fenceDecision 是一次围栏判定的结果。
type fenceDecision struct {
	ProjectID int64
	Targets   fenceTargets
	Allow     bool   // true=放行(已授权或无目标/无项目)
	HardBlock bool   // true=命中黑名单,直接阻断
	Reason    string // HardBlock 或 Ask 的说明
}

// evaluate 执行判定:黑名单 → 未授权(ask) → 放行。
func (f *AssetFence) evaluate(ctx context.Context, toolName string, input []byte) fenceDecision {
	if f == nil || f.dbh == nil {
		return fenceDecision{Allow: true}
	}
	cmd := fenceCommandText(toolName, input)
	if strings.TrimSpace(cmd) == "" {
		return fenceDecision{Allow: true}
	}
	targets := ExtractFenceTargets(cmd)
	if targets.empty() {
		return fenceDecision{Allow: true}
	}
	projectID := f.resolveProject(ctx)
	if projectID <= 0 {
		return fenceDecision{Allow: true}
	}
	// 黑名单(全局 ∪ 任务级 block)优先:命中即硬阻断,不给审批机会。
	blockRules, _ := f.dbh.ListAssetInterceptRules()
	taskIDStr, _ := intercept.TaskInfoFromContext(ctx)
	if taskID := parseTaskID(taskIDStr); taskID > 0 {
		if tb, _, err := f.dbh.Assets().TaskInterceptRulesSplit(taskID); err == nil {
			blockRules = append(blockRules, tb...)
		}
	}
	if rule, val, ok := db.MatchAssetInterceptRules(blockRules, targets.Domains, targets.IPs, nil); ok {
		return fenceDecision{
			ProjectID: projectID, Targets: targets, HardBlock: true,
			Reason: fmt.Sprintf("%s(命中值 %s)", rule.Reason(), val),
		}
	}
	if f.dbh.AuthorizedTarget(projectID, targets.Domains, targets.IPs) {
		return fenceDecision{Allow: true, ProjectID: projectID, Targets: targets}
	}
	return fenceDecision{
		ProjectID: projectID, Targets: targets,
		Reason: "目标资产不在项目授权范围内：" + strings.Join(targets.list(), "、") +
			"。若确属本次委托范围，请批准；否则请拒绝并改测授权内资产。",
	}
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
	projectID := int64(0)
	if p.TaskID != nil {
		if tid := parseTaskID(*p.TaskID); tid > 0 {
			projectID, _ = f.dbh.TaskProjectID(tid)
		}
	}
	if projectID <= 0 && p.ConversationID != nil {
		projectID, _ = f.dbh.ConvProjectID(*p.ConversationID)
	}
	if projectID <= 0 {
		return false
	}
	targets := ExtractFenceTargets(fenceCommandText(p.ToolName, p.ToolInput))
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
	dec := intercept.Decision{
		Action:  "ask",
		Message: "【资产围栏】" + d.Reason,
	}
	convID := intercept.ConvIDFromContext(ctx)
	if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
		return g.block(ev.ToolName, systemBlockMessage("目标资产未获项目授权（人工拒绝或工作已取消）"), ""), true
	}
	// 人工批准:目标登记为 approved,后续不再询问;本次放行,继续走规则判定。
	g.fence.authorize(d.ProjectID, d.Targets)
	return askernel.Result{}, false
}
