package server

import (
	"encoding/json"
	"strings"
)

// im_config.go IM 接入的凭据与开关。整包存一个 settings key（JSON），读侧只回
// `*_set` 布尔不回明文（同 web_search key 的口径）；写侧 nil=不改、""=清除。

const settingIMBot = "im_bot_config"

type imFeishuConfig struct {
	Enabled   bool   `json:"enabled"`
	AppID     string `json:"app_id"`
	AppSecret string `json:"app_secret"`
}

type imDingtalkConfig struct {
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client_id"` // 即 AppKey
	ClientSecret string `json:"client_secret"`
}

type imTelegramConfig struct {
	Enabled  bool   `json:"enabled"`
	BotToken string `json:"bot_token"`
	Proxy    string `json:"proxy"` // 可选出口代理(http/https/socks5)，空=直连
}

type imWecomConfig struct {
	Enabled        bool   `json:"enabled"`
	CorpID         string `json:"corp_id"`
	CorpSecret     string `json:"corp_secret"`
	AgentID        int64  `json:"agent_id"`
	CallbackToken  string `json:"callback_token"`       // 回调配置的 Token(验签)
	EncodingAESKey string `json:"encoding_aes_key"`     // 回调配置的 EncodingAESKey(加解密)
}

// imBotConfig 四平台的接入配置。AgentKey 是 IM 新会话用的对话 agent（默认 auto）。
type imBotConfig struct {
	Feishu   imFeishuConfig   `json:"feishu"`
	Dingtalk imDingtalkConfig `json:"dingtalk"`
	Telegram imTelegramConfig `json:"telegram"`
	Wecom    imWecomConfig    `json:"wecom"`
	AgentKey string           `json:"agent_key"`
}

// imBotAgentKey IM 会话默认 agent；空/不存在的 key 回落 auto。
func (s *Server) imBotAgentKey(cfg imBotConfig) string {
	key := strings.TrimSpace(cfg.AgentKey)
	if key != "" {
		if a, err := s.m.pg.GetAgentByKey(key); err == nil && a != nil {
			return key
		}
	}
	if a, err := s.m.pg.GetAgentByKey("auto"); err == nil && a != nil {
		return "auto"
	}
	return key
}

func (s *Server) imBotLoad() imBotConfig {
	cfg := imBotConfig{AgentKey: "auto"}
	if s.m == nil || s.m.pg == nil {
		return cfg
	}
	v, ok, _ := s.m.pg.GetSetting(settingIMBot)
	if !ok || strings.TrimSpace(v) == "" {
		return cfg
	}
	_ = json.Unmarshal([]byte(v), &cfg) // 半截 JSON 按零值字段回落
	if strings.TrimSpace(cfg.AgentKey) == "" {
		cfg.AgentKey = "auto"
	}
	return cfg
}

func (s *Server) imBotSave(cfg imBotConfig) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.m.pg.SetSetting(settingIMBot, string(raw))
}

// imBotPayload 是 /api/settings 里 im_bot 的回显形态：凭据只回 *_set。
func (s *Server) imBotPayload() map[string]any {
	cfg := s.imBotLoad()
	base := notifyPublicBaseURL(s.m.pg)
	return map[string]any{
		"agent_key": cfg.AgentKey,
		"feishu": map[string]any{
			"enabled":        cfg.Feishu.Enabled,
			"app_id":         cfg.Feishu.AppID,
			"app_secret_set": cfg.Feishu.AppSecret != "",
		},
		"dingtalk": map[string]any{
			"enabled":         cfg.Dingtalk.Enabled,
			"client_id":       cfg.Dingtalk.ClientID,
			"client_secret_set": cfg.Dingtalk.ClientSecret != "",
		},
		"telegram": map[string]any{
			"enabled":      cfg.Telegram.Enabled,
			"bot_token_set": cfg.Telegram.BotToken != "",
			"proxy":        cfg.Telegram.Proxy,
		},
		"wecom": map[string]any{
			"enabled":              cfg.Wecom.Enabled,
			"corp_id":              cfg.Wecom.CorpID,
			"corp_secret_set":      cfg.Wecom.CorpSecret != "",
			"agent_id":             cfg.Wecom.AgentID,
			"callback_token_set":   cfg.Wecom.CallbackToken != "",
			"encoding_aes_key_set": cfg.Wecom.EncodingAESKey != "",
			"callback_url":         strings.TrimRight(base, "/") + "/api/im/wecom/callback",
			"base_url_set":         strings.TrimSpace(base) != "",
		},
	}
}

// imBotApply 把请求里的 im_bot 部分合并进存量配置。凭据指针语义：nil=不改、
// ""=清除；enabled 用 *bool 显式表达。
func (s *Server) imBotApply(in imBotSettingsInput) error {
	cfg := s.imBotLoad()
	if in.AgentKey != nil {
		cfg.AgentKey = strings.TrimSpace(*in.AgentKey)
	}
	if in.Feishu != nil {
		if in.Feishu.Enabled != nil {
			cfg.Feishu.Enabled = *in.Feishu.Enabled
		}
		if in.Feishu.AppID != nil {
			cfg.Feishu.AppID = strings.TrimSpace(*in.Feishu.AppID)
		}
		if in.Feishu.AppSecret != nil {
			cfg.Feishu.AppSecret = *in.Feishu.AppSecret
		}
	}
	if in.Dingtalk != nil {
		if in.Dingtalk.Enabled != nil {
			cfg.Dingtalk.Enabled = *in.Dingtalk.Enabled
		}
		if in.Dingtalk.ClientID != nil {
			cfg.Dingtalk.ClientID = strings.TrimSpace(*in.Dingtalk.ClientID)
		}
		if in.Dingtalk.ClientSecret != nil {
			cfg.Dingtalk.ClientSecret = *in.Dingtalk.ClientSecret
		}
	}
	if in.Telegram != nil {
		if in.Telegram.Enabled != nil {
			cfg.Telegram.Enabled = *in.Telegram.Enabled
		}
		if in.Telegram.Proxy != nil {
			cfg.Telegram.Proxy = strings.TrimSpace(*in.Telegram.Proxy)
		}
		if in.Telegram.BotToken != nil {
			cfg.Telegram.BotToken = strings.TrimSpace(*in.Telegram.BotToken)
		}
	}
	if in.Wecom != nil {
		if in.Wecom.Enabled != nil {
			cfg.Wecom.Enabled = *in.Wecom.Enabled
		}
		if in.Wecom.CorpID != nil {
			cfg.Wecom.CorpID = strings.TrimSpace(*in.Wecom.CorpID)
		}
		if in.Wecom.CorpSecret != nil {
			cfg.Wecom.CorpSecret = *in.Wecom.CorpSecret
		}
		if in.Wecom.AgentID != nil {
			cfg.Wecom.AgentID = *in.Wecom.AgentID
		}
		if in.Wecom.CallbackToken != nil {
			cfg.Wecom.CallbackToken = strings.TrimSpace(*in.Wecom.CallbackToken)
		}
		if in.Wecom.EncodingAESKey != nil {
			cfg.Wecom.EncodingAESKey = strings.TrimSpace(*in.Wecom.EncodingAESKey)
		}
	}
	if err := s.imBotSave(cfg); err != nil {
		return err
	}
	s.imApplyConfig() // 凭据/开关变化即时生效：停旧循环、起新循环
	return nil
}

// putSettings 请求体里 im_bot 的形状（指针省略=不改）。
type imBotSettingsInput struct {
	AgentKey *string `json:"agent_key"`
	Feishu   *struct {
		Enabled   *bool   `json:"enabled"`
		AppID     *string `json:"app_id"`
		AppSecret *string `json:"app_secret"`
	} `json:"feishu"`
	Dingtalk *struct {
		Enabled      *bool   `json:"enabled"`
		ClientID     *string `json:"client_id"`
		ClientSecret *string `json:"client_secret"`
	} `json:"dingtalk"`
	Telegram *struct {
		Enabled  *bool   `json:"enabled"`
		BotToken *string `json:"bot_token"`
		Proxy    *string `json:"proxy"`
	} `json:"telegram"`
	Wecom *struct {
		Enabled        *bool   `json:"enabled"`
		CorpID         *string `json:"corp_id"`
		CorpSecret     *string `json:"corp_secret"`
		AgentID        *int64  `json:"agent_id"`
		CallbackToken  *string `json:"callback_token"`
		EncodingAESKey *string `json:"encoding_aes_key"`
	} `json:"wecom"`
}
