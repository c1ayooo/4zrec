package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// im_telegram.go Telegram 适配器：Bot API 长轮询收消息 + sendMessage 回发。
// 轮询不需要公网回调；国内网络可在配置里填出口代理（http/https）。

const (
	imTelegramPollTimeoutSec = 50 // 长轮询挂起时长，断线窗口内保持连接
	imTelegramMaxText        = 4000
	imTelegramRetryDelay     = 5 * time.Second
)

// imTelegramLoop 长轮询主循环；ctx 取消即退出（配置热更/停用）。
func (s *Server) imTelegramLoop(ctx context.Context, cfg imBotConfig) {
	token := cfg.Telegram.BotToken
	offset := int64(0)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		updates, err := s.imTelegramGetUpdates(ctx, token, offset)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[im telegram] 拉取消息失败: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(imTelegramRetryDelay):
			}
			continue
		}
		for _, u := range updates {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			if u.Message == nil || strings.TrimSpace(u.Message.Text) == "" {
				continue
			}
			chatID := strconv.FormatInt(u.Message.Chat.ID, 10)
			userID := ""
			if u.Message.From != nil {
				userID = strconv.FormatInt(u.Message.From.ID, 10)
			}
			text := imTelegramNormalize(u.Message.Text)
			if text == "" {
				continue
			}
			go s.imHandleText("telegram", chatID, userID, strconv.FormatInt(u.Message.MessageID, 10), text)
		}
	}
}

// imTelegramNormalize 归一化 Telegram 消息文本：剥掉群聊里的 /cmd@BotName 后缀。
func imTelegramNormalize(text string) string {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "/") {
		fields := strings.SplitN(text, " ", 2)
		if i := strings.Index(fields[0], "@"); i > 1 {
			fields[0] = fields[0][:i]
		}
		if len(fields) == 1 {
			return fields[0]
		}
		return fields[0] + " " + strings.TrimSpace(fields[1])
	}
	return text
}

func (s *Server) imTelegramClient(cfg imBotConfig) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if p := strings.TrimSpace(cfg.Telegram.Proxy); p != "" {
		if u, err := url.Parse(p); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Transport: transport, Timeout: (imTelegramPollTimeoutSec + 15) * time.Second}
}

func (s *Server) imTelegramGetUpdates(ctx context.Context, token string, offset int64) ([]imTelegramUpdate, error) {
	api := "https://api.telegram.org/bot" + token + "/getUpdates"
	q := url.Values{}
	q.Set("offset", strconv.FormatInt(offset, 10))
	q.Set("timeout", strconv.Itoa(imTelegramPollTimeoutSec))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var payload struct {
		OK     bool               `json:"ok"`
		Desc   string             `json:"description"`
		Result []imTelegramUpdate `json:"result"`
	}
	if err := s.imTelegramDo(ctx, token, req, &payload); err != nil {
		return nil, err
	}
	if !payload.OK {
		return nil, fmt.Errorf("telegram: %s", payload.Desc)
	}
	return payload.Result, nil
}

// imTelegramDo 复用同一代理客户端发请求并解析 JSON。轮询请求用长超时客户端，
// 发送请求也走它（超时上限一致，可接受）。
func (s *Server) imTelegramDo(ctx context.Context, token string, req *http.Request, out any) error {
	cfg := s.imBotLoad()
	resp, err := s.imTelegramClient(cfg).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram http %d: %s", resp.StatusCode, imSnippet(body))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (s *Server) imTelegramSend(ctx context.Context, cfg imBotConfig, chatID, text string) error {
	chat, err := strconv.ParseInt(chatID, 10, 64)
	if err != nil {
		return fmt.Errorf("telegram: 非法 chat_id %q", chatID)
	}
	payload := map[string]any{
		"chat_id":                   chat,
		"text":                      imTruncateRunes(text, imTelegramMaxText),
		"disable_web_page_preview":  true,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.telegram.org/bot"+cfg.Telegram.BotToken+"/sendMessage", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return s.imTelegramDo(ctx, cfg.Telegram.BotToken, req, nil)
}

// imTruncateRunes 按字符截断（不切断 UTF-8），超限给省略标记。
func imTruncateRunes(s string, max int) string {
	rs := []rune(strings.TrimSpace(s))
	if len(rs) <= max {
		return strings.TrimSpace(s)
	}
	return string(rs[:max]) + "\n…（已截断）"
}

// imSnippet 报错用的响应片段（截 200 字节）。
func imSnippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

type imTelegramUpdate struct {
	UpdateID int64             `json:"update_id"`
	Message  *imTelegramUpdateMessage `json:"message"`
}

type imTelegramUpdateMessage struct {
	MessageID int64  `json:"message_id"`
	Text      string `json:"text"`
	Chat struct {
		ID int64 `json:"id"`
	} `json:"chat"`
	From *struct {
		ID int64 `json:"id"`
	} `json:"from"`
}
