package icp

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/tidwall/gjson"
)

// 上游端点（beian.miit.gov.cn 的 icpproject_query 网关）。
const (
	authEndpoint      = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
	checkImagePoint   = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/getCheckImagePoint"
	checkImage        = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/checkImage"
	queryByCondition  = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition"
	blackByCondition  = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/blackListDomain/queryByCondition"
	blackAppCondition = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/blackListDomain/queryByCondition_appAndMini"
	appDetailEndpoint = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryDetailByAppAndMiniId"
)

const (
	beianUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36 Edg/101.0.1210.32"

	// authKey 的固定盐：上游校验 md5("testtest"+timeStamp)。
	authSalt = "testtest"

	// 上游验证码关闭时使用的兜底 sign（预签发的 JWT）。
	fallbackSign = "eyJ0eXBlIjozLCJleHREYXRhIjp7InZhZnljb2RlX2ltYWdlX2tleSI6IjUyZWI1ZTcyODViNzRmNWJhM2YwYzBkNTg0YTg3NmVmIn0sImUiOjE3NTY5NzAyNDg4MjN9.Ngpkwn4T7sQoQF9pCk_sQQpH61wQUEKnK2sQ8hDIq-Q"

	// 创宇盾拦截页特征串。
	wafBlocked = "当前访问疑似黑客攻击"

	detailConcurrency = 8
	bodyLimit         = 4 << 20
)

const hexDigits = "0123456789abcdef"

// Client 是 MIIT beian 上游的协议客户端。所有出站请求都经 core.Fetcher，
// 因此代理/超时/限速/审计由宿主统一实施。
type Client struct {
	fetcher core.Fetcher
	proxy   string
	timeout time.Duration
}

// NewClient 构造客户端。timeout<=0 时取 20s（验证码链路请求较多，略放宽）。
func NewClient(fetcher core.Fetcher) *Client {
	return &Client{fetcher: fetcher, timeout: 20 * time.Second}
}

// WithProxy 指定出站代理（空字符串表示直连）。
func (c *Client) WithProxy(proxy string) *Client {
	c.proxy = strings.TrimSpace(proxy)
	return c
}

// ---- 请求原语 ----

func baseHeaders() map[string]string {
	return map[string]string{
		"User-Agent": beianUA,
		"Origin":     "https://beian.miit.gov.cn",
		"Referer":    "https://beian.miit.gov.cn/",
		"Cookie":     "__jsluid_s=" + randHex(32),
		"Accept":     "application/json, text/plain, */*",
	}
}

func (c *Client) post(ctx context.Context, url string, headers map[string]string, body []byte, contentType string) (string, error) {
	if c == nil || c.fetcher == nil {
		return "", core.Unavailable("icpkit: fetcher 端口未配置")
	}
	h := make(map[string]string, len(headers)+1)
	for k, v := range headers {
		h[k] = v
	}
	if contentType != "" {
		h["Content-Type"] = contentType
	}
	resp, err := c.fetcher.Fetch(ctx, core.Request{
		Method: "POST", URL: url, Headers: h, Body: body, Proxy: c.proxy, Timeout: c.timeout,
	})
	if err != nil {
		return "", err
	}
	if resp.Status != 200 {
		return "", core.Unavailable(fmt.Sprintf("beian 上游返回 HTTP %d", resp.Status))
	}
	text := string(resp.Body)
	if strings.Contains(text, wafBlocked) {
		return "", core.Unavailable("当前访问已被创宇盾拦截，请稍后重试或更换出口 IP")
	}
	if len(text) > bodyLimit {
		text = text[:bodyLimit]
	}
	return text, nil
}

// ---- 鉴权 ----

// authToken 取一次访问令牌。authKey = md5("testtest"+timeStamp)，随表单提交。
func (c *Client) authToken(ctx context.Context) (string, map[string]string, error) {
	headers := baseHeaders()
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	sum := md5.Sum([]byte(authSalt + ts))
	authKey := hex.EncodeToString(sum[:])
	body := []byte("authKey=" + authKey + "&timeStamp=" + ts)

	text, err := c.post(ctx, authEndpoint, headers, body, "application/x-www-form-urlencoded")
	if err != nil {
		return "", nil, err
	}
	token := gjson.Get(text, "params.bussiness").String()
	if token == "" {
		return "", nil, core.Unavailable("beian auth 响应缺少 token: " + truncate(text, 200))
	}
	headers["token"] = token
	return token, headers, nil
}

// solveCaptcha 走完整滑块验证流程，返回 (uuid, token, sign, 基础头, 是否成功)。
// 任一环节失败都返回 ok=false，由调用方决定是否退化到兜底 sign。
func (c *Client) solveCaptcha(ctx context.Context) (uuid, token, sign string, base map[string]string, ok bool) {
	token, base, err := c.authToken(ctx)
	if err != nil {
		return "", "", "", nil, false
	}

	imgText, err := c.post(ctx, checkImagePoint, base, []byte(clientUIDBody()), "application/json")
	if err != nil {
		return "", "", "", nil, false
	}
	uuid = gjson.Get(imgText, "params.uuid").String()
	big := gjson.Get(imgText, "params.bigImage").String()
	small := gjson.Get(imgText, "params.smallImage").String()
	if uuid == "" || big == "" || small == "" {
		return "", "", "", nil, false
	}

	offset, err := matchSliderOffset(small, big)
	if err != nil {
		return "", "", "", nil, false
	}
	checkBody := `{"key":"` + uuid + `","value":"` + strconv.Itoa(offset) + `"}`
	respText, err := c.post(ctx, checkImage, base, []byte(checkBody), "application/json")
	if err != nil {
		return "", "", "", nil, false
	}
	if !gjson.Get(respText, "success").Bool() {
		return "", "", "", nil, false
	}
	sign = gjson.Get(respText, "params").String()
	if sign == "" {
		sign = strings.Trim(gjson.Get(respText, "params").Raw, `"`)
	}
	if sign == "" {
		return "", "", "", nil, false
	}
	return uuid, token, sign, base, true
}

// auth 返回可直接用于查询的 (uuid, token, sign, 头部集)。优先真实滑块验证，
// 失败时退化到兜底 sign（对应上游验证码关闭的场景）。
func (c *Client) auth(ctx context.Context) (uuid, token, sign string, headers map[string]string, err error) {
	if u, t, s, base, ok := c.solveCaptcha(ctx); ok {
		base["token"] = t
		base["sign"] = s
		base["uuid"] = u
		return u, t, s, base, nil
	}
	token, base, aerr := c.authToken(ctx)
	if aerr != nil {
		return "", "", "", nil, aerr
	}
	base["token"] = token
	base["sign"] = fallbackSign
	return "", token, fallbackSign, base, nil
}

// ---- 查询 ----

// Query 查询普通备案。qtype ∈ web|app|mapp|kapp；app/mapp/kapp 会并发补齐详情。
func (c *Client) Query(ctx context.Context, name, qtype string, page, size int) (string, error) {
	meta, ok := typeTable[qtype]
	if !ok || meta.Black {
		return "", core.InvalidInput("不是普通备案查询类型: " + qtype)
	}
	uuid, _, sign, headers, err := c.auth(ctx)
	if err != nil {
		return "", err
	}
	if uuid == "" {
		delete(headers, "uuid")
	}
	_ = sign

	body, err := json.Marshal(map[string]any{
		"pageNum":     pageNumValue(page),
		"pageSize":    pageNumValue(size),
		"unitName":    name,
		"serviceType": serviceTypeCode(meta.SP),
	})
	if err != nil {
		return "", err
	}
	text, err := c.post(ctx, queryByCondition, headers, body, "application/json")
	if err != nil {
		return "", err
	}
	return c.enrichAppDetails(ctx, text, meta, uuid, headers)
}

// QueryBlack 查询黑名单备案。qtype ∈ bweb|bapp|bmapp|bkapp。
func (c *Client) QueryBlack(ctx context.Context, name, qtype string) (string, error) {
	meta, ok := typeTable[qtype]
	if !ok || !meta.Black {
		return "", core.InvalidInput("不是黑名单查询类型: " + qtype)
	}
	uuid, _, _, headers, err := c.auth(ctx)
	if err != nil {
		return "", err
	}
	if uuid == "" {
		delete(headers, "uuid")
	}

	var payload map[string]any
	endpoint := blackByCondition
	if meta.SP == 0 {
		payload = map[string]any{"domainName": name}
	} else {
		payload = map[string]any{"serviceName": name, "serviceType": serviceTypeCode(meta.SP)}
		endpoint = blackAppCondition
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return c.post(ctx, endpoint, headers, body, "application/json")
}

// enrichAppDetails 对 App/小程序/快应用结果并发补齐详情，把 params.list 的每一项
// 替换为详情接口返回的 params 对象；失败或缺少 dataId 的项保留原样。
func (c *Client) enrichAppDetails(ctx context.Context, text string, meta typeMeta, uuid string, headers map[string]string) (string, error) {
	if !meta.Detail {
		return text, nil
	}
	if code := gjson.Get(text, "code").Int(); code == 500 {
		return `{"code":122,"message":"工信部服务器异常"}`, nil
	}
	if !gjson.Get(text, "success").Bool() {
		return text, nil
	}
	list := gjson.Get(text, "params.list")
	if !list.IsArray() {
		return text, nil
	}
	items := list.Array()
	if len(items) == 0 {
		return text, nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(text), &root); err != nil {
		return text, nil
	}

	detailST := serviceTypeCode(meta.SP)
	detailed := make([]json.RawMessage, len(items))
	for i, it := range items {
		detailed[i] = json.RawMessage(it.Raw)
	}

	sem := make(chan struct{}, detailConcurrency)
	var wg sync.WaitGroup
	for i, it := range items {
		dataID := it.Get("dataId")
		if !dataID.Exists() || dataID.String() == "" {
			continue
		}
		wg.Add(1)
		go func(idx int, rawID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if params, derr := c.appDetail(ctx, rawID, detailST, uuid, headers); derr == nil && params != "" {
				detailed[idx] = json.RawMessage(params)
			}
		}(i, dataID.Raw)
	}
	wg.Wait()

	if params, ok := root["params"].(map[string]any); ok {
		params["list"] = detailed
	}
	out, err := json.Marshal(root)
	if err != nil {
		return text, nil
	}
	return string(out), nil
}

// appDetail 拉取单条 App/小程序/快应用详情，返回 params 对象的原始 JSON。
func (c *Client) appDetail(ctx context.Context, rawDataID string, detailServiceType int, uuid string, headers map[string]string) (string, error) {
	body := []byte(`{"dataId":` + rawDataID + `,"serviceType":` + strconv.Itoa(detailServiceType) + `}`)
	text, err := c.post(ctx, appDetailEndpoint, headers, body, "application/json")
	if err != nil {
		return "", err
	}
	if !gjson.Get(text, "success").Bool() {
		return "", fmt.Errorf("详情获取失败")
	}
	params := gjson.Get(text, "params")
	if !params.Exists() {
		return "", fmt.Errorf("详情响应缺少 params")
	}
	return params.Raw, nil
}

// ---- 工具函数 ----

// pageNumValue 上游接受数字或空串：分页缺省时沿用空串语义。
func pageNumValue(v int) any {
	if v <= 0 {
		return ""
	}
	return v
}

// clientUIDBody 生成形如 {"clientUid":"point-<uuid>"} 的请求体。uuid 为 36 位
// 带连字符的十六进制串，第 14 位固定为 4，第 19 位按 variant 规则置位。
func clientUIDBody() string {
	b := make([]byte, 36)
	for i := range b {
		b[i] = hexDigits[randInt(len(hexDigits))]
	}
	b[14] = '4'
	v := hexVal(b[19])
	b[19] = hexDigits[(3&v)|8]
	b[8], b[13], b[18], b[23] = '-', '-', '-', '-'
	return `{"clientUid":"point-` + string(b) + `"}`
}

// randHex 返回 n 个十六进制字符（n 为偶数）。
func randHex(n int) string {
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand 失败极罕见；退化为时间派生的确定性值，仍可用于 Cookie。
		seed := time.Now().UnixNano()
		for i := range buf {
			buf[i] = byte(seed >> (uint(i%8) * 8))
		}
	}
	return hex.EncodeToString(buf)[:n]
}

// randInt 返回 [0,n) 的随机整数，使用密码学安全随机源。
func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return int(time.Now().UnixNano()) % n
	}
	return int(b[0]) % n
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return 0
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
