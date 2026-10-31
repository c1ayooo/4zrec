package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// feishuChannel 实现飞书（含 Lark）通知，两种接入形态共用一套卡片渲染：
//
//   - webhook：群「自定义机器人」，只需 Webhook 地址（+可选签名密钥）；
//   - app：企业「自建应用」机器人，App ID/Secret 换 tenant_access_token 后走
//     IM 消息 API，可单聊（open_id/user_id/union_id/email）或发群（chat_id）。
type feishuChannel struct{}

func (feishuChannel) Kind() string { return KindFeishu }

// 飞书两种形态的官方建议限频均远高于通知场景的实际峰值，沿用 100/min。
func (feishuChannel) DefaultRatePerMin() int { return 100 }

// Webhook 地址末段、App Secret、签名密钥都属凭据。
func (feishuChannel) SecretKeys() []string { return []string{"webhook", "secret", "app_secret"} }

// 目标地址与凭据是两套独立字段：改投递目标必须对新目标重新表态全部凭据。
func (feishuChannel) DestinationKeys() []string { return []string{"webhook", "receive_id"} }

// feishuAppMode 报告配置是否为应用机器人形态。缺省 mode 视为 webhook，
// 兼容只有 webhook 字段的存量配置。
func feishuAppMode(cfg map[string]any) bool { return cfgString(cfg, "mode") == "app" }

var feishuReceiveIDTypes = map[string]bool{
	"open_id": true, "user_id": true, "union_id": true, "email": true, "chat_id": true,
}

func (c feishuChannel) Validate(cfg map[string]any) error {
	if feishuAppMode(cfg) {
		for key, label := range map[string]string{
			"app_id":     "App ID",
			"app_secret": "App Secret",
			"receive_id": "接收者 ID",
		} {
			if cfgString(cfg, key) == "" {
				return errors.New("应用机器人模式缺少 " + label)
			}
		}
		typ := cfgString(cfg, "receive_id_type")
		if typ == "" {
			typ = "open_id"
		}
		if !feishuReceiveIDTypes[typ] {
			return fmt.Errorf("接收者 ID 类型无效: %s（可用 open_id/user_id/union_id/email/chat_id）", typ)
		}
		return nil
	}
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("缺少 Webhook 地址")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Webhook 地址无效: %w", err)
	}
	return nil
}

func (c feishuChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	if feishuAppMode(cfg) {
		return c.sendApp(ctx, cfg, m)
	}
	return c.sendWebhook(ctx, cfg, m)
}

// sendWebhook 是群自定义机器人形态：卡片 + 可选签名直投 Webhook。
func (c feishuChannel) sendWebhook(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	card, kept := feishuCard(m)
	payload := map[string]any{
		"msg_type": "interactive",
		"card":     card,
	}
	// 加签参数与消息同层，且只在配置了 secret 时出现。
	if secret := cfgString(cfg, "secret"); secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		payload["timestamp"] = ts
		payload["sign"] = feishuSign(ts, secret)
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		// 部分版本的飞书 hook 用这套字段名，一并兼容。
		StatusCode    int    `json:"StatusCode"`
		StatusMessage string `json:"StatusMessage"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("解析飞书响应失败: %w (%s)", err, snippet(raw))
	}
	if res.Code != 0 {
		return 0, Permanent(fmt.Errorf("飞书返回错误 %d: %s", res.Code, res.Msg))
	}
	if res.StatusCode != 0 {
		return 0, Permanent(fmt.Errorf("飞书返回错误 %d: %s", res.StatusCode, res.StatusMessage))
	}
	return kept, nil
}

// ---- 应用机器人形态 ----

// feishuTokenEntry 缓存 tenant_access_token。token 按 app_id 缓存、进程内共享：
// 通知渠道实现本身无状态（凭据从 cfg 传入），但 token 是派生凭据，逐条消息
// 重取会把凭据校验接口打成热点，且该接口有频率限制。
type feishuTokenEntry struct {
	token    string
	expireAt time.Time
}

var (
	feishuTokenMu    sync.Mutex
	feishuTokenCache = map[string]feishuTokenEntry{}
)

// feishuTokenStaleCodes 是「token 失效需重取」的飞书错误码。命中后强制刷新
// 重试一次——缓存提前 5 分钟过期，正常不会走到，这是双机时钟漂移等的兜底。
var feishuTokenStaleCodes = map[int]bool{99991663: true, 99991661: true, 99991679: true}

func feishuTenantToken(ctx context.Context, appID, appSecret string, force bool) (string, error) {
	feishuTokenMu.Lock()
	defer feishuTokenMu.Unlock()
	if e, ok := feishuTokenCache[appID]; ok && !force && time.Now().Before(e.expireAt) {
		return e.token, nil
	}
	raw, err := doJSON(ctx, "POST", "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
		nil, map[string]string{"app_id": appID, "app_secret": appSecret})
	if err != nil {
		return "", err
	}
	var res struct {
		Code              int    `json:"code"`
		Msg               string `json:"msg"`
		TenantAccessToken string `json:"tenant_access_token"`
		Expire            int64  `json:"expire"` // 秒
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", fmt.Errorf("解析飞书 token 响应失败: %w (%s)", err, snippet(raw))
	}
	if res.Code != 0 {
		return "", Permanent(fmt.Errorf("飞书应用凭据无效（%d）: %s", res.Code, res.Msg))
	}
	if res.TenantAccessToken == "" {
		return "", Permanent(errors.New("飞书 token 响应缺少 tenant_access_token"))
	}
	// 提前 5 分钟视为过期，避免边界上的在途请求被拒。
	feishuTokenCache[appID] = feishuTokenEntry{
		token:    res.TenantAccessToken,
		expireAt: time.Now().Add(time.Duration(res.Expire)*time.Second - 5*time.Minute),
	}
	return res.TenantAccessToken, nil
}

// sendApp 是自建应用形态：换 token 后走 IM 消息 API，单聊/群发由 receive_id_type 决定。
func (c feishuChannel) sendApp(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	card, kept := feishuCard(m)
	content, err := json.Marshal(card)
	if err != nil {
		return 0, Permanent(fmt.Errorf("构造飞书卡片失败: %w", err))
	}
	typ := cfgString(cfg, "receive_id_type")
	if typ == "" {
		typ = "open_id"
	}
	url := "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=" + typ
	body := map[string]any{
		"receive_id": cfgString(cfg, "receive_id"),
		"msg_type":   "interactive",
		// IM API 的 content 是「卡片 JSON 的字符串」，不是嵌套对象。
		"content": string(content),
	}
	send := func(token string) (int, []byte, error) {
		raw, serr := doJSON(ctx, "POST", url, map[string]string{"Authorization": "Bearer " + token}, body)
		if serr != nil {
			return 0, nil, serr
		}
		var res struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		if uerr := json.Unmarshal(raw, &res); uerr != nil {
			return 0, raw, fmt.Errorf("解析飞书响应失败: %w (%s)", uerr, snippet(raw))
		}
		return res.Code, raw, nil
	}
	token, err := feishuTenantToken(ctx, cfgString(cfg, "app_id"), cfgString(cfg, "app_secret"), false)
	if err != nil {
		return 0, err
	}
	code, raw, err := send(token)
	if err != nil {
		return 0, err
	}
	if feishuTokenStaleCodes[code] {
		// token 意外失效：强制刷新后整条重发一次（卡片渲染无副作用）。
		if token, err = feishuTenantToken(ctx, cfgString(cfg, "app_id"), cfgString(cfg, "app_secret"), true); err != nil {
			return 0, err
		}
		if code, raw, err = send(token); err != nil {
			return 0, err
		}
	}
	if code != 0 {
		// 凭据/参数/权限类错误重试无意义；频率限制（9499/230020）交由上层退避。
		return 0, Permanent(fmt.Errorf("飞书应用消息发送失败（%d）: %s", code, snippet(raw)))
	}
	return kept, nil
}

// feishuSign 按飞书官方规则计算签名。
//
// 这里特别容易踩坑：官方样例是
//
//	hmac.new(string_to_sign.encode(), digestmod=sha256)
//
// 也就是 **key = timestamp + "\n" + secret，message 为空**，而不是直觉上的
// 「key=secret, message=stringToSign」——那正是钉钉的算法。两边算法刚好反过来，
// 照着另一家的实现写必然签名校验失败（报 19021）。
func feishuSign(timestamp, secret string) string {
	stringToSign := timestamp + "\n" + secret
	mac := hmac.New(sha256.New, []byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// feishuSeverityTemplate 把漏洞级别映射到卡片 header 配色模板。
// 未知级别用 grey——不用 blue，免得和 low 混淆。
func feishuSeverityTemplate(severity string) string {
	switch severity {
	case "critical":
		return "red"
	case "high":
		return "orange"
	case "medium":
		return "yellow"
	case "low":
		return "blue"
	default:
		return "grey"
	}
}

// feishuMaxCardBytes 是卡片内容的保守上限。飞书对卡片有体积限制，超了整条被拒；
// 取一个明显低于官方上限的值，把 JSON 包装开销也算进来。
const feishuMaxCardBytes = 24000

// feishuCard 构造交互式卡片，返回卡片与**实际写入的条目数**。
// kept 的用途同 markdownBody：只有真正进了卡片的条目才该被标记为已送达。
func feishuCard(m Message) (map[string]any, int) {
	elements := []any{}
	kept := 0
	if m.Batch {
		// 先按整条打包再拼头部：头部要写「其余 N 条将在下一条消息继续」，
		// N 必须来自实际装下的条数。
		kept = packItemCount(m.Items, feishuMaxCardBytes, markdownReservedBytes, "", byteSize, func(it Item, idx int) string {
			return feishuBatchLine(it, idx+1)
		})
		items := m.Items[:kept]
		elements = append(elements, feishuMarkdownDiv(markdownBatchIntro(m, items, len(m.Items))))
		for i, it := range items {
			elements = append(elements, feishuMarkdownDiv(feishuBatchLine(it, i+1)))
		}
		if m.HomeURL != "" {
			elements = append(elements, feishuButton("在平台中查看全部", m.HomeURL))
		}
	} else if len(m.Items) > 0 {
		kept = 1
		it := m.Items[0]
		elements = append(elements, feishuMarkdownDiv(feishuItemLines(it)))
		if it.DetailURL != "" {
			elements = append(elements, feishuButton("查看详情", it.DetailURL))
		}
	}

	card := map[string]any{
		"config":   map[string]any{"wide_screen_mode": true},
		"header":   map[string]any{"title": map[string]any{"tag": "plain_text", "content": markdownTitle(m)}},
		"elements": elements,
	}
	if len(m.Items) > 0 {
		card["header"].(map[string]any)["template"] = feishuSeverityTemplate(m.Items[0].Severity)
	}
	return card, kept
}

func feishuMarkdownDiv(content string) map[string]any {
	return map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": content}}
}

func feishuButton(label, url string) map[string]any {
	return map[string]any{
		"tag": "action",
		"actions": []any{map[string]any{
			"tag":  "button",
			"text": map[string]any{"tag": "lark_md", "content": label},
			"url":  url,
			"type": "primary",
		}},
	}
}

// feishuItemLines 渲染单个漏洞的 lark_md 正文。
//
// lark_md 与 markdown 是同族的文本格式，同样会解析链接与强调，所以来自外部
// 的字段一律过 markdownText（单行化 + 转义）——否则一条漏洞标题就能在
// 飞书里变成可点击的外链。
func feishuItemLines(it Item) string {
	out := fmt.Sprintf("**%s · %s**", SeverityLabel(it.Severity), markdownText(it.DisplayTitle(), 0))
	if it.IsStatusChange() {
		out += fmt.Sprintf("\n**状态变更**：%s → %s",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.IsFinding() && it.VulnClass != "" && it.VulnClass != it.Title() {
		out += fmt.Sprintf("\n**类型**：%s", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		out += fmt.Sprintf("\n**资产**：%s", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			out += fmt.Sprintf("\n**摘要**：%s", s)
		}
	}
	return out
}

// feishuBatchLine 渲染汇总卡片里的一条。
func feishuBatchLine(it Item, index int) string {
	line := fmt.Sprintf("**%d. %s · %s**", index, SeverityLabel(it.Severity), markdownText(it.DisplayTitle(), 0))
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		line += " — " + markdownText(a, 0)
	}
	return line
}

// FeishuTenantToken 为需要直接调飞书开放平台 API 的模块（如 IM 接入网关）导出
// 租户 token；缓存与失效语义同通知渠道内部实现。
func FeishuTenantToken(ctx context.Context, appID, appSecret string, force bool) (string, error) {
	return feishuTenantToken(ctx, appID, appSecret, force)
}
