// Package redirectguard 30x 跳转的逐跳安全判定：http_probe 与 http_session 共用，
// 保证两套 HTTP 客户端对重定向的处理语义一致。
//
// 设计约束（302 不能随便跳）：
//   - 默认不跟随；agent 工具层为硬门禁（无跟随参数，FollowRedirects 恒 false，
//     残留调用被拒绝，shell 跟随命令由 security.Executor 拦截），本包跟随能力
//     仅供平台内部流程（如 WebShell 投递/curl 回放）显式使用；
//   - 显式跟随时逐跳调用 Guard：项目授权范围逐跳复验（授权管理语义）。平台定位
//     安全工具，敏感地址/跨域不做 SSRF 类自我限制（2026-09-18 用户决策），相关属性
//     随 Hop 分析结果返回供 agent/用户决策；
//   - 被拒绝时调用方保留当前 30x 报文（http.ErrUseLastResponse 语义），跳转目标的
//     分析结果随 Result.Redirects 返回，由用户决定下一轮是否测试该跳转。
package redirectguard

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Hop 一次跳转的观测与分析结果（随工具结果返回，供用户决策）。
type Hop struct {
	Index       int    `json:"index"`
	FromURL     string `json:"from_url"`
	ToURL       string `json:"to_url"`
	Status      int    `json:"status"` // 触发跳转的响应状态码（301/302/303/307/308）
	CrossDomain bool   `json:"cross_domain,omitempty"`
	// SchemeDowngrade https→http 降级（凭据可能被中间人截获，仅标注不拦截）
	SchemeDowngrade bool `json:"scheme_downgrade,omitempty"`
	// CredentialsStripped 跨站跳转已剥离 Cookie/Authorization（仅在显式允许跨域时出现）
	CredentialsStripped bool `json:"credentials_stripped,omitempty"`
	// NotFollowed 默认不跟随（follow_redirects=false）时的首跳记录
	NotFollowed bool `json:"not_followed,omitempty"`
	// Blocked 被 Guard 拦截（BlockReason 说明原因）
	Blocked     bool   `json:"blocked,omitempty"`
	BlockReason string `json:"block_reason,omitempty"`
}

// Guard 逐跳校验：返回非 nil 表示不跟随该跳（调用方保留当前 30x 报文）。
type Guard func(hop Hop) error

// ScopeChecker 授权范围判定（重复清单收敛：原 infocollect/pipeline 各抄一份 CheckRedirect）。
// 由调用方适配注入（通常 *project.ScopeRule，Configured/Allows 均 nil 安全），
// 本包不 import project，避免 redirectguard ↔ project 的包依赖。
type ScopeChecker interface {
	Configured() bool
	Allows(host, ip string) (bool, string)
}

// NewRedirectChecker 组装探针类 http.Client 的 CheckRedirect：跳数上限 +
// 已配置授权范围时逐跳复验（范围内站点 302 到范围外主机时拒绝跟随，避免请求被
// 重定向带出授权边界）。scope 为 nil 或未配置时只做跳数上限。
func NewRedirectChecker(scope ScopeChecker, maxHops int) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxHops {
			return fmt.Errorf("重定向过多")
		}
		host := req.URL.Hostname()
		if scope != nil && scope.Configured() {
			if allowed, _ := scope.Allows(host, host); !allowed {
				return fmt.Errorf("重定向目标 %s 超出项目授权范围，已停止跟随", host)
			}
		}
		return nil
	}
}

// Policy 跳转策略：项目授权范围复验（授权管理语义，非 SSRF 门禁）。
// 平台定位安全工具，敏感地址/跨域不做自我限制（2026-09-18 用户决策）——
// 相关属性（Hop.CrossDomain/SchemeDowngrade 等）随分析结果返回供决策。
// CheckScope 为 nil 表示无授权边界可依（如会话未绑定项目）时不额外收紧。
type Policy struct {
	AllowCrossDomain bool // 历史字段，跨域不再硬拦；保留避免调用方签名变动
	CheckScope       func(rawURL string) error
}

// Check 逐跳判定：返回 nil 允许跟随，否则给出用户可读的拒绝原因。
func (p Policy) Check(hop Hop) error {
	u, err := url.Parse(strings.TrimSpace(hop.ToURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("重定向目标 %q 不是有效的 http(s) 地址，已停止跟随", hop.ToURL)
	}
	if p.CheckScope != nil {
		if err := p.CheckScope(hop.ToURL); err != nil {
			return fmt.Errorf("重定向目标超出授权边界，已停止跟随：%w", err)
		}
	}
	return nil
}

// Analyze 计算一次跳转的属性（跨域以原始请求 host 为基准，与浏览器凭据策略一致）。
func Analyze(index int, fromURL, toURL string, status int, initialURL string) Hop {
	return Hop{
		Index:           index,
		FromURL:         fromURL,
		ToURL:           toURL,
		Status:          status,
		CrossDomain:     !sameHost(hostname(toURL), hostname(initialURL)),
		SchemeDowngrade: scheme(initialURL) == "https" && scheme(toURL) == "http",
	}
}

// SameSiteOrSubdomain 判断 host 是否与 base 同站（同 host 或 base 的子域）。
// 跨站跳转的凭据保留策略与此对齐（镜像 Go 标准库 shouldCopyHeaderOnRedirect 的语义）。
func SameSiteOrSubdomain(host, base string) bool {
	host, base = normalizeHost(host), normalizeHost(base)
	if host == "" || base == "" {
		return false
	}
	return host == base || strings.HasSuffix(host, "."+base)
}

// CrossSite 判定跳转目标是否跨站（不是初始 URL 的同站/子域）：
// 跨站跳转必须隔离凭据（Cookie/Authorization），与 Go 标准库重定向语义一致。
func CrossSite(rawURL, baseURL string) bool {
	return !SameSiteOrSubdomain(hostname(rawURL), hostname(baseURL))
}

// IsCredentialHeader 跳转时必须隔离的凭据头。
func IsCredentialHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Authorization", "Cookie", "Cookie2", "Proxy-Authorization":
		return true
	}
	return false
}

// metadataHosts 云元数据地址显式清单（含通用的 Go IP 分类覆盖不到的 CGNAT 段）。
var metadataHosts = map[string]string{
	"100.100.100.200":          "云元数据地址（阿里云）",
	"169.254.169.254":          "云元数据地址",
	"metadata.google.internal": "云元数据地址（GCP）",
	"metadata.goog":            "云元数据地址（GCP）",
	"metadata.tencentyun.com":  "云元数据地址（腾讯云）",
	"metadata.azure.com":       "云元数据地址（Azure）",
	"fd00:ec2::254":            "云元数据地址（AWS IPv6）",
}

// cgnat 100.64.0.0/10（RFC6598）：云元数据/内网穿透高发段，Go 的 IsPrivate 不覆盖。
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// IsSensitiveTarget 判定跳转目标是否为敏感地址（回环/内网/链路本地/元数据等）。
// 仅做字面量与 hostname 判定，不做 DNS 解析（DNS 重绑定防护依赖请求前的范围校验）。
func IsSensitiveTarget(rawURL string) (bool, string) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false, ""
	}
	host := normalizeHost(u.Hostname())
	if host == "" {
		return false, ""
	}
	if reason, ok := metadataHosts[host]; ok {
		return true, reason
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true, "本机地址（localhost）"
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false, ""
	}
	switch {
	case ip.IsLoopback():
		return true, "回环地址"
	case ip.IsUnspecified():
		return true, "未指定地址"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return true, "链路本地地址"
	case ip.IsPrivate():
		return true, "内网地址"
	case ip.IsMulticast():
		return true, "组播地址"
	case ip.Equal(net.IPv4bcast):
		return true, "广播地址"
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 {
			return true, "保留地址（0.0.0.0/8）"
		}
		if cgnat.Contains(ip) {
			return true, "运营商级 NAT 保留地址（100.64.0.0/10）"
		}
	}
	return false, ""
}

func hostname(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return normalizeHost(u.Hostname())
}

// normalizeHost 小写、去尾部点（example.com. 与 example.com 视为同 host）。
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func scheme(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme)
}

func sameHost(a, b string) bool {
	return a != "" && a == b
}
