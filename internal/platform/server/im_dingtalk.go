package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// im_dingtalk.go 钉钉适配器：Stream 模式（WebSocket 长连接）收机器人消息，
// 走开放平台 API 回发（单聊 oToMessages / 群聊 groupMessages）。协议对齐官方
// dingtalk-stream-sdk-go：
//  1. POST /v1.0/gateway/connections/open {clientId, clientSecret,
//     subscriptions:[{type:"EVENT",topic:"/v1.0/im/bot/messages/get"}]} →
//     {endpoint, ticket}；WS 连 endpoint?ticket=。
//  2. 帧是 JSON：{specVersion,type,time,headers:{topic,messageId,...},data}；
//     type=SYSTEM 且 headers.topic=ping → 回 {code:200,headers:{contentType:
//     "application/json",messageId},data:<原样>}；type=EVENT → 处理后同样回 ACK。
//  3. EVENT.data 是机器人消息 JSON 字符串（chatbot model）。

const (
	imDingtalkHost          = "https://api.dingtalk.com"
	imDingtalkBotTopic      = "/v1.0/im/bot/messages/get"
	imDingtalkMaxText       = 4000
	imDingtalkReconnectMax  = 60 * time.Second
	imDingtalkWriteTimeout  = 10 * time.Second
	imDingtalkKeepaliveIdle = 120 * time.Second
)

// imDingtalkLoop 长连接主循环：断线退避重连。
func (s *Server) imDingtalkLoop(ctx context.Context, cfg imBotConfig) {
	delay := 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := s.imDingtalkSession(ctx, cfg); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[im dingtalk] 连接断开：%v（%v 后重连）", err, delay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < imDingtalkReconnectMax {
			delay *= 2
		}
	}
}

// imDingtalkFrame 是网关帧的收发形态（官方 DataFrame 同构）。
type imDingtalkFrame struct {
	SpecVersion string          `json:"specVersion,omitempty"`
	Type        string          `json:"type"`
	Time        int64           `json:"time,omitempty"`
	Headers     map[string]string `json:"headers"`
	Data        string          `json:"data"`
}

type imDingtalkFrameResp struct {
	Code    int               `json:"code"`
	Headers map[string]string `json:"headers"`
	Message string            `json:"message"`
	Data    string            `json:"data"`
}

// imDingtalkSession 维持一条 Stream 连接直到出错或 ctx 取消。
func (s *Server) imDingtalkSession(ctx context.Context, cfg imBotConfig) error {
	endpoint, ticket, err := imDingtalkOpen(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	header := http.Header{}
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, endpoint+"?ticket="+ticket, header)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	// ctx 取消（停用/换配置）时立即关连接，让阻塞中的 ReadMessage 马上返回。
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	var writeMu sync.Mutex
	writeJSON := func(v any) error {
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(imDingtalkWriteTimeout))
		return conn.WriteMessage(websocket.TextMessage, raw)
	}

	// 服务端在 keepalive 空闲后可能静默断开：读超时兜底重连。
	_ = conn.SetReadDeadline(time.Now().Add(imDingtalkKeepaliveIdle * 2))

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(imDingtalkKeepaliveIdle * 2))
		var frame imDingtalkFrame
		if err := json.Unmarshal(raw, &frame); err != nil {
			log.Printf("[im dingtalk] 帧解析失败: %v", err)
			continue
		}
		topic := frame.Headers["topic"]
		messageID := frame.Headers["messageId"]
		switch {
		case frame.Type == "SYSTEM" && topic == "ping":
			// pong：messageId 原样带回，data 原样回显（官方 SDK 语义）。
			_ = writeJSON(&imDingtalkFrameResp{
				Code: 200,
				Headers: map[string]string{
					"contentType": "application/json",
					"messageId":   messageID,
				},
				Message: "ok",
				Data:    frame.Data,
			})
		case frame.Type == "SYSTEM" && topic == "disconnect":
			return fmt.Errorf("服务端要求断开")
		case frame.Type == "EVENT" && topic == imDingtalkBotTopic:
			ack := &imDingtalkFrameResp{
				Code: 200,
				Headers: map[string]string{
					"contentType": "application/json",
					"messageId":   messageID,
				},
				Message: "ok",
			}
			if err := writeJSON(ack); err != nil {
				return err
			}
			s.imDingtalkDispatch(frame.Data)
		default:
			// 未订阅的其他帧：按通用成功 ACK 回执，避免服务端重推。
			_ = writeJSON(&imDingtalkFrameResp{
				Code: 200,
				Headers: map[string]string{
					"contentType": "application/json",
					"messageId":   messageID,
				},
				Message: "ok",
			})
		}
	}
}

// imDingtalkOpen 换取长连接接入点。
func imDingtalkOpen(ctx context.Context, cfg imBotConfig) (endpoint, ticket string, err error) {
	body, _ := json.Marshal(map[string]any{
		"clientId":     cfg.Dingtalk.ClientID,
		"clientSecret": cfg.Dingtalk.ClientSecret,
		"subscriptions": []map[string]string{
			{"type": "EVENT", "topic": imDingtalkBotTopic},
		},
		"ua": "4zrec-im-gateway",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		imDingtalkHost+"/v1.0/gateway/connections/open", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("open http %d: %s", resp.StatusCode, imSnippet(raw))
	}
	var res struct {
		Endpoint string `json:"endpoint"`
		Ticket   string `json:"ticket"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", "", err
	}
	if res.Endpoint == "" || res.Ticket == "" {
		return "", "", fmt.Errorf("open 响应缺少 endpoint/ticket: %s", imSnippet(raw))
	}
	return res.Endpoint, res.Ticket, nil
}

// imDingtalkDispatch 解析机器人消息并喂给网关。
func (s *Server) imDingtalkDispatch(data string) {
	var msg struct {
		MsgID            string `json:"msgId"`
		ConversationID   string `json:"conversationId"`
		ConversationType string `json:"conversationType"` // 1=单聊 2=群聊
		SenderStaffID    string `json:"senderStaffId"`
		SenderID         string `json:"senderId"`
		Text             struct {
			Content string `json:"content"`
		} `json:"text"`
		RobotCode string `json:"robotCode"`
		MsgType   string `json:"msgtype"`
	}
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return
	}
	if msg.MsgType != "text" {
		return
	}
	// 群聊里 @ 机器人的占位文本已被服务端去掉；单聊直接是原文。
	text := strings.TrimSpace(msg.Text.Content)
	if text == "" {
		return
	}
	// chatID 编码回复所需的路由信息（对 hub 不透明）：类型|会话|机器人|发送者。
	chatID := strings.Join([]string{msg.ConversationType, msg.ConversationID, msg.RobotCode, msg.SenderStaffID}, "|")
	if msg.ConversationType == "1" {
		chatID = strings.Join([]string{"1", msg.SenderStaffID, msg.RobotCode}, "|")
	}
	go s.imHandleText("dingtalk", chatID, msg.SenderStaffID, msg.MsgID, text)
}

// ---- 发送（开放平台 API）----

var (
	imDingtalkTokenMu   sync.Mutex
	imDingtalkToken     string
	imDingtalkTokenFrom string // 所属 clientID，配置换绑时强制刷新
	imDingtalkTokenExp  time.Time
)

func imDingtalkAccessToken(ctx context.Context, clientID, clientSecret string, force bool) (string, error) {
	imDingtalkTokenMu.Lock()
	defer imDingtalkTokenMu.Unlock()
	if !force && imDingtalkToken != "" && imDingtalkTokenFrom == clientID && time.Now().Before(imDingtalkTokenExp) {
		return imDingtalkToken, nil
	}
	body, _ := json.Marshal(map[string]string{"appKey": clientID, "appSecret": clientSecret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, imDingtalkHost+"/v1.0/oauth2/accessToken", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var res struct {
		AccessToken string `json:"accessToken"`
		ExpireIn    int64  `json:"expireIn"` // 秒
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", err
	}
	if res.AccessToken == "" {
		return "", fmt.Errorf("钉钉 token 响应异常: %s", imSnippet(raw))
	}
	imDingtalkToken = res.AccessToken
	imDingtalkTokenFrom = clientID
	imDingtalkTokenExp = time.Now().Add(time.Duration(res.ExpireIn)*time.Second - 5*time.Minute)
	return imDingtalkToken, nil
}

// imDingtalkSend 回发文本。chatID 是 imDingtalkDispatch 编码的路由串。
func (s *Server) imDingtalkSend(ctx context.Context, cfg imBotConfig, chatID, text string) error {
	parts := strings.Split(chatID, "|")
	if len(parts) < 2 {
		return fmt.Errorf("dingtalk: 非法 chatID %q", chatID)
	}
	token, err := imDingtalkAccessToken(ctx, cfg.Dingtalk.ClientID, cfg.Dingtalk.ClientSecret, false)
	if err != nil {
		return err
	}
	// sampleMarkdown：标题 + markdown 正文，加粗/列表/链接在钉钉里可渲染。
	content, _ := json.Marshal(map[string]string{
		"title": "4zrec",
		"text":  imTruncateRunes(text, imDingtalkMaxText),
	})
	var body map[string]any
	apiURL := imDingtalkHost + "/v1.0/robots/oToMessages?access_token=" + token
	if parts[0] == "2" { // 群聊：类型|会话|机器人|发送者
		if len(parts) < 4 {
			return fmt.Errorf("dingtalk: 群聊 chatID 缺段 %q", chatID)
		}
		apiURL = imDingtalkHost + "/v1.0/robots/groupMessages?access_token=" + token
		body = map[string]any{
			"robotCode":          parts[2],
			"openConversationId": parts[1],
			"msgKey":             "sampleMarkdown",
			"msgParam":           string(content),
		}
	} else { // 单聊：类型|发送者|机器人
		if len(parts) < 3 {
			return fmt.Errorf("dingtalk: 单聊 chatID 缺段 %q", chatID)
		}
		body = map[string]any{
			"robotCode": parts[2],
			"userIds":   []string{parts[1]},
			"msgKey":    "sampleMarkdown",
			"msgParam":  string(content),
		}
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var res struct {
		ErrCode      json.Number `json:"errcode"`
		ErrMsg       string      `json:"errmsg"`
		ProcessQuery string      `json:"processQueryKey"`
	}
	_ = json.Unmarshal(data, &res)
	if res.ErrCode.String() != "" && res.ErrCode.String() != "0" {
		return fmt.Errorf("钉钉发送错误 %s: %s", res.ErrCode, res.ErrMsg)
	}
	return nil
}
