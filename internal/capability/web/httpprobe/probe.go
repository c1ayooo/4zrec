// Package httpprobe 结构化 HTTP 探测：发送请求并捕获完整请求/响应报文，
// 供证据库归档（渗透报告的数据包证据来源）。
package httpprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/web/redirectguard"
)

const (
	// 分隔标记：报告模板按它切分请求/响应两段
	RequestMarker  = "=== REQUEST ==="
	ResponseMarker = "=== RESPONSE ==="

	maxBodyCapture = 256 * 1024 // 报文捕获的 body 上限（请求+响应各自）
	defaultTimeout = 20 * time.Second
	maxRedirects   = 10 // 跳数上限（对齐浏览器/Go 默认）
)

type Request struct {
	Method  string            `json:"method"`
	Proxy   string            `json:"proxy,omitempty"` // 出站代理（http/socks5；空=直连）
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	// UploadFile / UploadField / FormFields multipart 文件上传（curl -F 等价）：
	// UploadFile 为本地文件路径，UploadField 为表单字段名（默认 file），FormFields 为附加表单字段。
	// 设置后 Body 忽略，Content-Type 由 multipart 编码器自动生成。
	UploadFile  string            `json:"upload_file,omitempty"`
	UploadField string            `json:"upload_field,omitempty"`
	FormFields  map[string]string `json:"form_fields,omitempty"`
	// FollowRedirects 是否跟随 30x 跳转。默认 false（curl 不加 -L 的语义）：
	// 捕获原始 30x 报文，跳转目标/跨域/范围判定随 Result.Redirects 返回。
	// agent 工具层为硬门禁（schema 无此参数、恒 false、残留调用被拒绝）；
	// 仅供平台内部流程显式开启（如 WebShell 投递）。
	FollowRedirects bool `json:"follow_redirects,omitempty"`
	// RedirectGuard 逐跳跳转校验（仅 FollowRedirects=true 时生效）：
	// 返回非 nil 即停止跟随并保留当前 30x 报文（证据不丢），原因写入 Result.Redirects。
	// 调用方注入项目授权范围/跨域策略（app 层 agentRedirectPolicy）。
	RedirectGuard redirectguard.Guard `json:"-"`
	// RandomFingerprint 指纹随机化（默认开）：
	// 未显式指定 User-Agent 时从真实浏览器 UA 池随机取一，并补齐 Accept/Accept-Language，
	// 避免固定 "Probe" UA / 裸 Go 默认头被 WAF 指纹识别。设为 "off"/"false" 关闭。
	RandomFingerprint string `json:"random_fingerprint,omitempty"`
	// TimeoutSeconds 客户端整体超时（含连接/跳转/读体）。0 = 默认 20s，上限由调用方约束。
	// client.Timeout 必须跟随该值：只放大 ctx 超时而不放大 client.Timeout 时，
	// 慢目标在 20s 处依旧被 client 掐断（timeout_seconds 参数形同虚设）。
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// BodySink 非空时把响应体完整流式写入该 writer（大文件/二进制落盘），
	// 内存里的报文捕获仍按 maxBodyCapture 截断。writer 由调用方负责关闭；
	// 写失败会让本次请求返回错误（与 curl -o 落盘失败同语义）。
	BodySink io.Writer `json:"-"`
}

type Result struct {
	StatusCode   int         `json:"status_code"`
	StatusText   string      `json:"status_text"`
	DurationMS   int64       `json:"duration_ms"`
	RespHeaders  http.Header `json:"-"`
	RespBody     string      `json:"resp_body"`
	UserAgent    string      `json:"user_agent,omitempty"` // 实际使用的 UA（粘性/显式），截图透传保证指纹一致
	RequestText  string      `json:"request_text"`         // 完整请求报文
	ResponseText string      `json:"response_text"`        // 完整响应报文
	Transcript   string      `json:"transcript"`           // RequestMarker + ResponseMarker 拼好的完整数据包
	FinalURL     string      `json:"final_url,omitempty"`  // 实际取到响应的 URL（未跟随时=原始 URL）
	// Redirects 30x 跳转链（含未跟随/被拦截的跳转），供用户决定下一轮是否测试
	Redirects []redirectguard.Hop `json:"redirects,omitempty"`
	// BodyBytes 是响应体实际读到的总字节数（BodySink 未设时也统计，供落盘/截断提示）。
	BodyBytes int64 `json:"body_bytes,omitempty"`
}

// DoRequest 执行探测并生成完整报文。
// 安全约束（调用方负责）：URL 必须已通过项目授权范围校验；此包只管发请求和捕获。
func DoRequest(ctx context.Context, req Request) (*Result, error) {
	if strings.TrimSpace(req.Method) == "" {
		req.Method = http.MethodGet
	}
	req.Method = strings.ToUpper(req.Method)

	var body io.Reader
	var contentType string
	var dumpBody string // 报文 dump 用的 body 副本（DumpRequestOut 会消费共享的 Body 引用）
	if req.UploadFile != "" {
		// multipart 上传（curl -F 等价）：附加表单字段 + 文件字段
		fileData, err := os.ReadFile(req.UploadFile)
		if err != nil {
			return nil, fmt.Errorf("读取上传文件失败: %w", err)
		}
		field := strings.TrimSpace(req.UploadField)
		if field == "" {
			field = "file"
		}
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		for k, v := range req.FormFields {
			if err := w.WriteField(k, v); err != nil {
				return nil, fmt.Errorf("写入表单字段失败: %w", err)
			}
		}
		fh, ferr := w.CreateFormFile(field, filepath.Base(req.UploadFile))
		if ferr != nil {
			return nil, fmt.Errorf("构造上传字段失败: %w", ferr)
		}
		if _, werr := fh.Write(fileData); werr != nil {
			return nil, fmt.Errorf("写入上传内容失败: %w", werr)
		}
		if cerr := w.Close(); cerr != nil {
			return nil, fmt.Errorf("编码 multipart 失败: %w", cerr)
		}
		body = bytes.NewReader(buf.Bytes())
		contentType = w.FormDataContentType()
		dumpBody = buf.String()
	} else {
		body = strings.NewReader(req.Body)
		dumpBody = req.Body
	}
	r, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	for k, v := range req.Headers {
		r.Header.Set(k, v)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	// 指纹随机化：显式 UA 优先（agent 指定了就用指定的），否则真实浏览器 UA 池随机；
	// 同时补齐浏览器特征头（Accept/Accept-Language），避免"有 UA 没Accept"的畸形指纹。
	// 报文 dump 在此之后进行，报告里呈现的就是实际使用的随机头。
	if strings.TrimSpace(strings.ToLower(req.RandomFingerprint)) != "off" && strings.TrimSpace(strings.ToLower(req.RandomFingerprint)) != "false" {
		if r.Header.Get("User-Agent") == "" {
			// 粘性 UA：同一 host 固定一个浏览器指纹（跨 host 随机）。
			// 真实用户会话内 UA 不变，同 IP 高频换 UA 是 WAF 的扫描器特征。
			if ua := stickyUserAgentForURL(req.URL); ua != "" {
				r.Header.Set("User-Agent", ua)
			}
		}
		if r.Header.Get("Accept") == "" {
			r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		}
		if r.Header.Get("Accept-Language") == "" {
			// 粘性 Accept-Language:与 UA 同理按 host 确定性取值——同一业务
			// 整套浏览器指纹恒定,跨 host 才不同(2026-10-17 用户口径:
			// 同一业务不得逐请求换头)。
			r.Header.Set("Accept-Language", stickyAcceptLanguageForURL(req.URL))
		}
	}

	// 请求报文（OutRequest 带 Body 可完整 dump；无 body 时也补全）
	dumpReq := r.Clone(ctx)
	if dumpBody != "" {
		dumpReq.Body = io.NopCloser(strings.NewReader(dumpBody))
	}
	reqDump, err := httputil.DumpRequestOut(dumpReq, true)
	if err != nil {
		reqDump = []byte(fmt.Sprintf("%s %s\n(headers dump failed: %v)", req.Method, req.URL, err))
	}

	// 渗透目标常见自签/过期/域名不匹配证书（内网/测试环境），与其他平台 HTTP 通道
	// （httpsession/fingerprint/infocollect）同语义：忽略校验，不因 x509 掐断探测。
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // 渗透场景自签证书，全平台统一语义
	// 私网/回环旁路按出口 kind 四象限决策（bypassProxyForTarget）：隧道型出口下私网
	// 目标不旁路——socks 隧道正是打内网的通路，旁路等于打断隧道打法。
	proxy := strings.TrimSpace(req.Proxy)
	if proxy != "" && bypassProxyForTarget(req.URL, proxy) {
		proxy = ""
	}
	var transport http.RoundTripper
	if pu, perr := url.Parse(proxy); perr == nil && (pu.Scheme == "http" || pu.Scheme == "https" || pu.Scheme == "socks5") {
		transport = &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 15 * time.Second}
	} else {
		transport = &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 15 * time.Second}
	}
	// 逐跳记录跳转链：CheckRedirect 与 client.Do 同 goroutine 执行，无需加锁。
	// 拦截/超限时返回 ErrUseLastResponse（而非 error）以保留最后一个 30x 响应体，
	// 原始跳转报文仍可归档为证据，跳转分析随 Result 返回供用户决策。
	var redirects []redirectguard.Hop
	clientTimeout := defaultTimeout
	if req.TimeoutSeconds > 0 {
		clientTimeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	client := &http.Client{
		Timeout:   clientTimeout,
		Transport: transport,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			from := req.URL
			if len(via) > 0 {
				from = via[len(via)-1].URL.String()
			}
			status := 0
			if next.Response != nil {
				status = next.Response.StatusCode
			}
			hop := redirectguard.Analyze(len(redirects), from, next.URL.String(), status, req.URL)
			if !req.FollowRedirects {
				// 默认不跟随：捕获原始 30x，把跳转目标与分析结果交回调用方（用户决定下一轮）
				hop.NotFollowed = true
				redirects = append(redirects, hop)
				return http.ErrUseLastResponse
			}
			if len(via) >= maxRedirects {
				hop.Blocked = true
				hop.BlockReason = fmt.Sprintf("重定向次数超过上限（%d），已停止跟随", maxRedirects)
				redirects = append(redirects, hop)
				return http.ErrUseLastResponse
			}
			if req.RedirectGuard != nil {
				if err := req.RedirectGuard(hop); err != nil {
					hop.Blocked = true
					hop.BlockReason = err.Error()
					redirects = append(redirects, hop)
					return http.ErrUseLastResponse
				}
			}
			// 真正发起该跳时才标注凭据剥离：跨站跳转 Go 标准库不复制
			// Authorization/Cookie（同站/子域语义），报文里能看到剥离结果。
			hop.CredentialsStripped = redirectguard.CrossSite(hop.ToURL, req.URL) && hasCredentialHeaders(req.Headers)
			redirects = append(redirects, hop)
			return nil
		},
	}
	start := time.Now()
	resp, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	respBodyBytes, totalBytes, readErr := readResponseBody(resp.Body, req.BodySink)
	if readErr != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", readErr)
	}
	respBody := printable(respBodyBytes)

	// 响应报文：状态行 + 头 + body
	var respBuf bytes.Buffer
	fmt.Fprintf(&respBuf, "HTTP/1.1 %s\n", resp.Status)
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			fmt.Fprintf(&respBuf, "%s: %s\n", k, v)
		}
	}
	respBuf.WriteString("\n")
	respBuf.WriteString(respBody)
	respText := respBuf.String()

	finalURL := req.URL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return &Result{
		StatusCode:   resp.StatusCode,
		StatusText:   resp.Status,
		DurationMS:   duration.Milliseconds(),
		RespHeaders:  resp.Header,
		RespBody:     respBody,
		UserAgent:    r.Header.Get("User-Agent"),
		RequestText:  string(reqDump),
		ResponseText: respText,
		Transcript:   RequestMarker + "\n" + string(reqDump) + "\n" + ResponseMarker + "\n" + respText,
		FinalURL:     finalURL,
		Redirects:    redirects,
		BodyBytes:    totalBytes,
	}, nil
}

// readResponseBody 读取响应体:内存捕获截断到 maxBodyCapture(证据/快照用),
// sink 非空时把完整字节流式写入(大文件/二进制落盘)。返回(截断后的快照,
// 实际读到的总字节数,错误)。
func readResponseBody(r io.Reader, sink io.Writer) ([]byte, int64, error) {
	var capture bytes.Buffer
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if sink != nil {
				if _, werr := sink.Write(buf[:n]); werr != nil {
					return capture.Bytes(), total, werr
				}
			}
			if remain := maxBodyCapture - capture.Len(); remain > 0 {
				if n > remain {
					capture.Write(buf[:remain])
				} else {
					capture.Write(buf[:n])
				}
			}
		}
		if err == io.EOF {
			return capture.Bytes(), total, nil
		}
		if err != nil {
			return capture.Bytes(), total, err
		}
	}
}

// egressKindForURL 出口 kind 判据（URL 键）：按注册 URL 精确匹配 netproxy 动态出口表
// （会话选中的出口 URL 即注册时的原串，见 Manager.URLFor）。fail-open：无匹配/未知
// kind 返回空串，调用方按普通代理处理（维持老旁路行为）。包级变量供测试注入。
// egressKindForURL 出口 kind 判据(4zrec:动态出口表为包级注入,首版恒空=普通代理;
// netproxy 代理池迁移后接入)。
var egressKindForURL = func(proxyURL string) string {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return ""
	}
	for _, e := range DynamicEgresses() {
		if e.URL == proxyURL {
			return e.Kind
		}
	}
	return ""
}

// Egress 动态出口条目(netproxy 迁移前的最小替身)。
type Egress struct {
	URL  string
	Kind string
}

// dynamicEgresses 可注入出口表(代理池迁移后由 netproxy 接管)。
var dynamicEgresses []Egress

// DynamicEgresses 返回当前动态出口表。
func DynamicEgresses() []Egress { return dynamicEgresses }

// SetDynamicEgresses 注入动态出口表(代理池接线用)。
func SetDynamicEgresses(e []Egress) { dynamicEgresses = e }

// IsLoopbackHost 回环判定(容错完整 URL)。
func IsLoopbackHost(raw string) bool {
	host := raw
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	host = strings.Trim(host, "[]")
	return host == "localhost" || strings.HasPrefix(host, "127.")
}

// IsLocalOrPrivateHost 私网/链路本地判定。
func IsLocalOrPrivateHost(raw string) bool {
	host := raw
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	return false
}

// bypassProxyForTarget 私网/回环目标的代理旁路决策（四象限，本包旁路策略的唯一权威）：
//
//	回环（127.0.0.0/8、::1、localhost）× 任意出口：旁路——回环经远端代理必死，也不该绕道；
//	私网/链路本地 × 隧道型出口：不旁路——socks 隧道（webshell/frp）就是打内网的通路，
//	  旁路等于打断「webshell 入口 → 隧道 → 工具流量打内网」的主链路；
//	私网/链路本地 × 普通公网代理：旁路——公网出口路由不到私网（老行为：全局代理下
//	  私网探测 100% 超时的实测教训）；
//	公网目标：不旁路（现状，与出口 kind 无关）。
func bypassProxyForTarget(targetURL, proxyURL string) bool {
	if IsLoopbackHost(targetURL) { // 函数内已容错完整 URL
		return true
	}
	if !IsLocalOrPrivateHost(targetURL) {
		return false
	}
	return egressKindForURL(proxyURL) != "tunnel"
}

// hasCredentialHeaders 请求头里是否带凭据（用于跳转链标注凭据剥离）。
func hasCredentialHeaders(headers map[string]string) bool {
	for k := range headers {
		if redirectguard.IsCredentialHeader(k) {
			return true
		}
	}
	return false
}

// stickyUserAgentForURL 从 URL 提取 host 并取粘性 UA
func stickyUserAgentForURL(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return StickyUserAgentFor(u.Hostname())
	}
	return RandUserAgent()
}

// randAcceptLanguage 常见地区权重随机（配合 UA 的地区特征，避免全站同值）
// stickyAcceptLanguageForURL 按 host 确定性取 Accept-Language(fnv 散列;
// 无 host 时退化为随机,与 stickyUserAgentForURL 同构)。
func stickyAcceptLanguageForURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return randAcceptLanguage()
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(u.Hostname())))
	langs := acceptLanguagePool()
	return langs[int(h.Sum32())%len(langs)]
}

func acceptLanguagePool() []string {
	return []string{
		"zh-CN,zh;q=0.9,en;q=0.8",
		"zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
		"en-US,en;q=0.9,zh-CN;q=0.8",
		"en-US,en;q=0.5",
		"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
	}
}

func randAcceptLanguage() string {
	langs := acceptLanguagePool()
	return langs[rand.Intn(len(langs))]
}

// printable 二进制 body 转可打印（报文证据里不能有乱码控制符）
func printable(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == '\n' || c == '\t' || c == '\r' || (c >= 0x20 && c < 0x7f) {
			buf = append(buf, c)
			continue
		}
		if c >= 0x80 { // UTF-8/多字节原样保留
			buf = append(buf, c)
			continue
		}
		buf = append(buf, '.')
	}
	return string(buf)
}

// Summarize 给 agent 的简短结果摘要（完整报文在 Transcript，由调用方归档）
func Summarize(r *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %s | %dms\n", r.StatusText, r.DurationMS)
	if len(r.Redirects) > 0 {
		b.WriteString(SummarizeRedirects(r.Redirects))
	}
	body := r.RespBody
	if len(body) > 600 {
		body = body[:600] + "…(截断，完整报文已归档证据库)"
	}
	if body != "" {
		b.WriteString("响应片段:\n")
		b.WriteString(body)
	}
	return b.String()
}

// SummarizeRedirects 跳转链的决策摘要：标注跨域/降级/未跟随/被拦截，
// 并给出下一轮显式跟随所需的参数，让"是否测试跳转"由用户决定。
func SummarizeRedirects(hops []redirectguard.Hop) string {
	var b strings.Builder
	blocked, notFollowed, crossDomain, downgrade := false, false, false, false
	for _, h := range hops {
		fmt.Fprintf(&b, "↪ 跳转#%d %d → %s", h.Index+1, h.Status, h.ToURL)
		if h.CrossDomain {
			b.WriteString(" [跨域]")
			crossDomain = true
		}
		if h.SchemeDowngrade {
			b.WriteString(" [https→http]")
			downgrade = true
		}
		if h.CredentialsStripped {
			b.WriteString(" [已剥离凭据]")
		}
		switch {
		case h.Blocked:
			b.WriteString(" [已拦截]")
			blocked = true
		case h.NotFollowed:
			b.WriteString(" [未跟随]")
			notFollowed = true
		default:
			b.WriteString(" [已跟随]")
		}
		b.WriteString("\n")
		if h.BlockReason != "" {
			fmt.Fprintf(&b, "   拦截原因: %s\n", h.BlockReason)
		}
	}
	if notFollowed {
		b.WriteString("⚠ 需要用户决策：以上跳转未跟随（平台硬门禁，302 不能随便跳）。请向用户报告跳转目标并等待确认；")
		b.WriteString("用户确认要测试该跳转后，把目标 URL 作为新的 url 单独发起请求即可逐跳验证（新请求重新校验授权范围并独立存证）。")
		if crossDomain {
			b.WriteString("跨域目标需在项目授权范围内，且新请求不会携带原站 Cookie/Authorization。")
		}
		b.WriteString("未跟随的跳转不得表述为已访问。\n")
	}
	if blocked {
		b.WriteString("⚠ 跳转已被拦截（超出项目授权范围），不得绕过；如需测试，请扩大授权后直接对目标发起请求。\n")
	}
	if downgrade {
		b.WriteString("⚠ 跳转存在 https→http 降级，凭据可能以明文传输。\n")
	}
	return b.String()
}
