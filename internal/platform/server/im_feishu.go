package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/platform/notify"
	"github.com/gorilla/websocket"
)

// im_feishu.go 飞书（含 Lark）适配器：长连接模式收事件 + IM API 发文本。
//
// 协议（对齐官方 Go SDK oapi-sdk-go/v3/ws 的实现）：
//  1. bootstrap：POST /callback/ws/endpoint，body {"AppID","AppSecret"}（字段名
//     大写），响应 data.URL 是 wss 地址（query 带 device_id/service_id），
//     data.ClientConfig.PingInterval 是心跳周期（秒）。
//  2. WS 全部是二进制 protobuf 帧（pbbp2.Frame，编解码见下方手写实现）：
//     - Method=0 控制帧：headers.type=ping/pong；本端按周期发 ping（Service 取
//       bootstrap URL 的 service_id），服务端 pong 的 payload 可能带新配置。
//     - Method=1 数据帧：headers.type=event，message_id/sum/seq；sum>1 时按
//       seq 分片重组；处理完把原帧的 headers 原样带回、payload 换成
//       {"code":200,...} 的 Response JSON 回写，即 ACK。
//  3. 事件 payload 是 schema 2.0 JSON；这里只处理 im.message.receive_v1 的文本。

const (
	imFeishuDomain          = "https://open.feishu.cn"
	imFeishuDefaultPingSec  = 120
	imFeishuReconnectMaxSec = 60 * time.Second
)

// ---- pbbp2 最小编解码（协议私有形状，无需引入 protobuf 运行时）----

type imFeishuFrame struct {
	SeqID   uint64
	LogID   uint64
	Service int32
	Method  int32
	Headers []imFeishuHeader
	Payload []byte
}

type imFeishuHeader struct{ Key, Value string }

func imFeishuFrameEncode(f *imFeishuFrame) []byte {
	var buf bytes.Buffer
	putVarint := func(v uint64) {
		var tmp [binary.MaxVarintLen64]byte
		buf.Write(tmp[:binary.PutUvarint(tmp[:], v)])
	}
	putBytes := func(field int, b []byte) {
		putVarint(uint64(field)<<3 | 2)
		putVarint(uint64(len(b)))
		buf.Write(b)
	}
	putVarint(1<<3 | 0) // SeqID
	putVarint(f.SeqID)
	putVarint(2<<3 | 0) // LogID
	putVarint(f.LogID)
	putVarint(3<<3 | 0) // Service
	putVarint(uint64(uint32(f.Service)))
	putVarint(4<<3 | 0) // Method
	putVarint(uint64(uint32(f.Method)))
	for _, h := range f.Headers { // Headers field 5
		var hb bytes.Buffer
		var tmp [binary.MaxVarintLen64]byte
		writeLenDelim := func(field int, s string) {
			hb.Write(tmp[:binary.PutUvarint(tmp[:], uint64(field)<<3|2)])
			hb.Write(tmp[:binary.PutUvarint(tmp[:], uint64(len(s)))])
			hb.WriteString(s)
		}
		writeLenDelim(1, h.Key)
		writeLenDelim(2, h.Value)
		putBytes(5, hb.Bytes())
	}
	putBytes(8, f.Payload) // Payload
	return buf.Bytes()
}

func imFeishuFrameDecode(b []byte) (*imFeishuFrame, error) {
	f := &imFeishuFrame{}
	pos := 0
	readVarint := func() (uint64, int, error) {
		v, n := binary.Uvarint(b[pos:])
		if n <= 0 {
			return 0, 0, fmt.Errorf("im feishu: 帧截断(varint)")
		}
		pos += n
		return v, n, nil
	}
	for pos < len(b) {
		tag, _, err := readVarint()
		if err != nil {
			return nil, err
		}
		field, wire := int(tag>>3), int(tag&7)
		switch {
		case wire == 0 && (field == 1 || field == 2 || field == 3 || field == 4):
			v, _, err := readVarint()
			if err != nil {
				return nil, err
			}
			switch field {
			case 1:
				f.SeqID = v
			case 2:
				f.LogID = v
			case 3:
				f.Service = int32(uint32(v))
			case 4:
				f.Method = int32(uint32(v))
			}
		case wire == 2 && field == 5: // Header
			ln, _, err := readVarint()
			if err != nil {
				return nil, err
			}
			if pos+int(ln) > len(b) {
				return nil, fmt.Errorf("im feishu: 帧截断(header)")
			}
			hb := b[pos : pos+int(ln)]
			pos += int(ln)
			h := imFeishuHeader{}
			hp := 0
			for hp < len(hb) {
				ht, hn := binary.Uvarint(hb[hp:])
				if hn <= 0 {
					return nil, fmt.Errorf("im feishu: 帧截断(header tag)")
				}
				hp += hn
				if ht>>3 != 1 && ht>>3 != 2 {
					return nil, fmt.Errorf("im feishu: 未知 header 字段 %d", ht>>3)
				}
				hl, hn2 := binary.Uvarint(hb[hp:])
				if hn2 <= 0 {
					return nil, fmt.Errorf("im feishu: 帧截断(header len)")
				}
				hp += hn2
				if hp+int(hl) > len(hb) {
					return nil, fmt.Errorf("im feishu: 帧截断(header value)")
				}
				if ht>>3 == 1 {
					h.Key = string(hb[hp : hp+int(hl)])
				} else {
					h.Value = string(hb[hp : hp+int(hl)])
				}
				hp += int(hl)
			}
			f.Headers = append(f.Headers, h)
		case wire == 2 && field == 8: // Payload
			ln, _, err := readVarint()
			if err != nil {
				return nil, err
			}
			if pos+int(ln) > len(b) {
				return nil, fmt.Errorf("im feishu: 帧截断(payload)")
			}
			f.Payload = b[pos : pos+int(ln)]
			pos += int(ln)
		case wire == 2: // 6 PayloadEncoding / 7 PayloadType / 9 LogIDNew：跳过
			ln, _, err := readVarint()
			if err != nil {
				return nil, err
			}
			if pos+int(ln) > len(b) {
				return nil, fmt.Errorf("im feishu: 帧截断(跳过字段)")
			}
			pos += int(ln)
		case wire == 0: // 服务端新增的未知 varint 字段：protobuf 前向兼容，跳过
			if _, _, err := readVarint(); err != nil {
				return nil, err
			}
		case wire == 1: // fixed64：跳过
			if pos+8 > len(b) {
				return nil, fmt.Errorf("im feishu: 帧截断(fixed64)")
			}
			pos += 8
		case wire == 5: // fixed32：跳过
			if pos+4 > len(b) {
				return nil, fmt.Errorf("im feishu: 帧截断(fixed32)")
			}
			pos += 4
		default:
			return nil, fmt.Errorf("im feishu: 不支持的线型 field=%d wire=%d", field, wire)
		}
	}
	return f, nil
}

// ---- 收发循环 ----

type imFeishuEvent struct {
	Schema string `json:"schema"`
	Header struct {
		EventType string `json:"event_type"`
	} `json:"header"`
	Event struct {
		Sender struct {
			SenderID struct {
				OpenID string `json:"open_id"`
			} `json:"sender_id"`
		} `json:"sender"`
		Message struct {
			MessageID   string `json:"message_id"`
			ChatID      string `json:"chat_id"`
			ChatType    string `json:"chat_type"` // p2p / group
			MessageType string `json:"message_type"`
			Content     string `json:"content"` // 消息类型的 JSON 字符串，如 {"text":"..."}
			Mentions    []struct {
				Key  string `json:"key"` // 文本里的占位，如 @_user_1
				Name string `json:"name"`
			} `json:"mentions"`
		} `json:"message"`
	} `json:"event"`
}

// imFeishuLoop 长连接主循环：bootstrap → 读帧 → 事件派发；断线退避重连。
func (s *Server) imFeishuLoop(ctx context.Context, cfg imBotConfig) {
	delay := 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := s.imFeishuSession(ctx, cfg); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[im feishu] 连接断开：%v（%v 后重连）", err, delay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < imFeishuReconnectMaxSec {
			delay *= 2
		}
	}
}

// imFeishuSession 维持一条连接直到出错或 ctx 取消。
func (s *Server) imFeishuSession(ctx context.Context, cfg imBotConfig) error {
	rawURL, serviceID, pingInterval, err := imFeishuBootstrap(ctx, cfg)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	conn, _, err := (&websocket.Dialer{Proxy: nil, HandshakeTimeout: 20 * time.Second}).DialContext(ctx, rawURL, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(pingInterval*2 + 30*time.Second))
	log.Printf("[im feishu] 长连接已建立")
	// ctx 取消（停用/换配置）时立即关连接，让阻塞中的 ReadMessage 马上返回。
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	// 分片重组缓存：message_id → 各分片
	var segMu sync.Mutex
	segs := map[string][][]byte{}

	// 心跳：对齐官方 SDK——连接建立后【立即】发第一个 ping，再按服务端下发的
	// 周期发后续 ping（Service 用 bootstrap URL 里的值）。首 ping 延迟发会被
	// 服务端判定失联直接断开。
	go func() {
		ping := &imFeishuFrame{Method: 0, Service: serviceID,
			Headers: []imFeishuHeader{{Key: "type", Value: "ping"}}}
		sendPing := func() bool {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.BinaryMessage, imFeishuFrameEncode(ping)); err != nil {
				return false
			}
			return true
		}
		if !sendPing() {
			return
		}
		tick := time.NewTicker(pingInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if !sendPing() {
					return
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(pingInterval*2 + 30*time.Second))
		frame, err := imFeishuFrameDecode(msg)
		if err != nil {
			log.Printf("[im feishu] 帧解析失败: %v", err)
			continue
		}
		switch frame.Method {
		case 0: // 控制帧：pong 可能带新配置（简化处理：忽略配置变化，用初始周期）
			continue
		case 1: // 数据帧
			hs := map[string]string{}
			for _, h := range frame.Headers {
				hs[h.Key] = h.Value
			}
			payload := frame.Payload
			sum, _ := strconv.Atoi(hs["sum"])
			seq, _ := strconv.Atoi(hs["seq"])
			msgID := hs["message_id"]
			if sum > 1 {
				segMu.Lock()
				buf, ok := segs[msgID]
				if !ok {
					buf = make([][]byte, sum)
					segs[msgID] = buf
				}
				buf[seq] = frame.Payload
				complete := true
				total := 0
				for _, part := range buf {
					if len(part) == 0 {
						complete = false
						break
					}
					total += len(part)
				}
				if !complete {
					segMu.Unlock()
					continue
				}
				delete(segs, msgID)
				segMu.Unlock()
				payload = make([]byte, 0, total)
				for _, part := range buf {
					payload = append(payload, part...)
				}
			}
			// ACK：原帧头原样带回，payload 换成 Response JSON（官方 SDK 同款语义）。
			ack := &imFeishuFrame{SeqID: frame.SeqID, LogID: frame.LogID, Service: frame.Service,
				Method:  1,
				Headers: frame.Headers,
				Payload: []byte(`{"code":200,"headers":{},"data":null}`)}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if werr := conn.WriteMessage(websocket.BinaryMessage, imFeishuFrameEncode(ack)); werr != nil {
				return werr
			}
			if hs["type"] == "event" && strings.TrimSpace(string(payload)) != "" {
				s.imFeishuDispatch(payload)
			}
		}
	}
}

// imFeishuBootstrap 换取长连接地址。响应字段名是官方定义的大写形态。
func imFeishuBootstrap(ctx context.Context, cfg imBotConfig) (rawURL string, serviceID int32, pingInterval time.Duration, err error) {
	body, _ := json.Marshal(map[string]string{"AppID": cfg.Feishu.AppID, "AppSecret": cfg.Feishu.AppSecret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, imFeishuDomain+"/callback/ws/endpoint", bytes.NewReader(body))
	if err != nil {
		return "", 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("locale", "zh")
	resp, err := imFeishuHTTP.Do(req)
	if err != nil {
		return "", 0, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, 0, fmt.Errorf("endpoint http %d: %s", resp.StatusCode, imSnippet(raw))
	}
	var er struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			URL          string `json:"URL"`
			ClientConfig struct {
				PingInterval int `json:"PingInterval"`
			} `json:"ClientConfig"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &er); err != nil {
		return "", 0, 0, err
	}
	if er.Code != 0 || er.Data.URL == "" {
		return "", 0, 0, fmt.Errorf("endpoint 错误 %d: %s", er.Code, er.Msg)
	}
	u, err := url.Parse(er.Data.URL)
	if err != nil {
		return "", 0, 0, err
	}
	if sid, err := strconv.ParseInt(u.Query().Get("service_id"), 10, 32); err == nil {
		serviceID = int32(sid)
	}
	pi := er.Data.ClientConfig.PingInterval
	if pi <= 0 {
		pi = imFeishuDefaultPingSec
	}
	return er.Data.URL, serviceID, time.Duration(pi) * time.Second, nil
}

// imFeishuDispatch 解析事件并喂给网关：只处理文本消息；群里把 @ 提及替换成
// 名字后剥掉首个 @ 前缀（机器人被 @ 的部分）。
func (s *Server) imFeishuDispatch(payload []byte) {
	var ev imFeishuEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return
	}
	if ev.Header.EventType != "im.message.receive_v1" || ev.Event.Message.MessageType != "text" {
		return
	}
	var content struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(ev.Event.Message.Content), &content); err != nil {
		return
	}
	text := content.Text
	for _, m := range ev.Event.Message.Mentions {
		text = strings.ReplaceAll(text, m.Key, "@"+m.Name)
	}
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "@") {
		if i := strings.IndexAny(text, " \n"); i > 0 {
			text = strings.TrimSpace(text[i:])
		} else {
			text = ""
		}
	}
	if text == "" {
		return
	}
	userID := ev.Event.Sender.SenderID.OpenID
	go s.imHandleText("feishu", ev.Event.Message.ChatID, userID, ev.Event.Message.MessageID, text)
}

// imFeishuCard 内容截断：卡片上限 24000 字节，按最坏 CJK（3 字节/符）留裕量取 6000 符。
const imFeishuCardMaxBytes = 6000

// imFeishuHTTP 飞书开放平台是国内直连接口：显式不走系统代理环境变量——
// 否则本机代理（clash 等）一挂，长连接 bootstrap 和发消息会跟着全体断连
// （2026-10-29 实锤：进程继承的 http_proxy 失联后 bootstrap 连续失败）。
var imFeishuHTTP = &http.Client{
	Transport: &http.Transport{Proxy: nil},
	Timeout:   20 * time.Second,
}

// imFeishuCard 把回复包成交互卡片（lark_md）：agent 回复里的加粗/行内代码/链接
// 在飞书里可渲染；纯文本消息会把 markdown 语法原样显示。
func imFeishuCard(text string) map[string]any {
	return map[string]any{
		"config": map[string]any{"wide_screen_mode": true},
		"header": map[string]any{
			"title": map[string]any{"tag": "plain_text", "content": "4zrec"},
		},
		"elements": []any{
			map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": imTruncateRunes(text, imFeishuCardMaxBytes)}},
		},
	}
}

// imFeishuWorkingEmoji 「处理中」表情：Typing（敲键盘/正在输入）。
const imFeishuWorkingEmoji = "Typing"

// imFeishuReact 在消息上盖表情（reaction_type 用表情库的 key，如 Typing），
// 成功返回 reaction_id（移除用）。
func (s *Server) imFeishuReact(ctx context.Context, cfg imBotConfig, messageID, emojiKey string) (string, error) {
	token, err := notify.FeishuTenantToken(ctx, cfg.Feishu.AppID, cfg.Feishu.AppSecret, false)
	if err != nil {
		return "", err
	}
	raw, _ := json.Marshal(map[string]string{"reaction_type": emojiKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		imFeishuDomain+"/open-apis/im/v1/messages/"+messageID+"/reactions", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := imFeishuHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var res struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			ReactionID string `json:"reaction_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(data, &res)
	if res.Code != 0 {
		return "", fmt.Errorf("盖表情错误 %d: %s", res.Code, res.Msg)
	}
	return res.Data.ReactionID, nil
}

// imFeishuUnreact 移除消息上的表情。
func (s *Server) imFeishuUnreact(ctx context.Context, cfg imBotConfig, messageID, reactionID string) error {
	token, err := notify.FeishuTenantToken(ctx, cfg.Feishu.AppID, cfg.Feishu.AppSecret, false)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		imFeishuDomain+"/open-apis/im/v1/messages/"+messageID+"/reactions/"+reactionID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := imFeishuHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var res struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	_ = json.Unmarshal(data, &res)
	if res.Code != 0 {
		return fmt.Errorf("移除表情错误 %d: %s", res.Code, res.Msg)
	}
	return nil
}

// imFeishuSend 通过 IM API 给 chat（单聊/群通用）发交互卡片。
func (s *Server) imFeishuSend(ctx context.Context, cfg imBotConfig, chatID, text string) error {
	token, err := notify.FeishuTenantToken(ctx, cfg.Feishu.AppID, cfg.Feishu.AppSecret, false)
	if err != nil {
		return err
	}
	content, _ := json.Marshal(imFeishuCard(text))
	body := map[string]any{
		"receive_id": chatID,
		"msg_type":   "interactive",
		"content":    string(content),
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		imFeishuDomain+"/open-apis/im/v1/messages?receive_id_type=chat_id", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := imFeishuHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var res struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	_ = json.Unmarshal(data, &res)
	if res.Code != 0 {
		return fmt.Errorf("飞书发送错误 %d: %s", res.Code, res.Msg)
	}
	return nil
}
