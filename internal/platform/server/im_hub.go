package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// im_hub.go IM 接入网关：把飞书/钉钉/Telegram/企业微信里发来的消息接进平台的
// 对话链路。每个 IM chat(platform+chat_id) 固定映射一个平台会话（im_sessions 表）：
// 斜杠命令 /bond /new /commands 直接复用对话页那套处理（chat_commands.go），自然
// 语言走同一个 agent 轮（runConversationSync），web 与 IM 看到同一条会话记录。
//
// 回程按平台适配器发送（im_send.go / im_feishu.go / im_dingtalk.go / im_wecom.go）。
// 配置存 settings（im_config.go），变化即全停重起各平台循环。

// startIMHub 在 Server 装配时启动已启用平台的收发循环。
func (s *Server) startIMHub() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	s.imMu.Lock()
	if s.imCancels == nil {
		s.imCancels = map[string]context.CancelFunc{}
	}
	s.imMu.Unlock()
	s.imApplyConfig()
}

// imApplyConfig 按当前配置对齐各平台循环：停掉已关闭/多余的，补启新开启的。
// 企业微信没有常驻循环（入站走 HTTP 回调、出站按需发送），不在这里管理。
func (s *Server) imApplyConfig() {
	cfg := s.imBotLoad()
	want := map[string]bool{}
	if cfg.Feishu.Enabled && cfg.Feishu.AppID != "" && cfg.Feishu.AppSecret != "" {
		want["feishu"] = true
	}
	if cfg.Dingtalk.Enabled && cfg.Dingtalk.ClientID != "" && cfg.Dingtalk.ClientSecret != "" {
		want["dingtalk"] = true
	}
	if cfg.Telegram.Enabled && cfg.Telegram.BotToken != "" {
		want["telegram"] = true
	}

	type imSpawn struct {
		platform string
		ctx      context.Context
	}
	var spawns []imSpawn
	s.imMu.Lock()
	for platform, cancel := range s.imCancels {
		if !want[platform] {
			cancel()
			delete(s.imCancels, platform)
		}
	}
	for platform := range want {
		if _, running := s.imCancels[platform]; running {
			continue
		}
		ctx, cancel := context.WithCancel(s.ctx)
		s.imCancels[platform] = cancel
		spawns = append(spawns, imSpawn{platform: platform, ctx: ctx})
	}
	s.imMu.Unlock()

	for _, sp := range spawns {
		switch sp.platform {
		case "feishu":
			go s.imFeishuLoop(sp.ctx, cfg)
		case "dingtalk":
			go s.imDingtalkLoop(sp.ctx, cfg)
		case "telegram":
			go s.imTelegramLoop(sp.ctx, cfg)
		}
		log.Printf("[im] %s 接入已启动", sp.platform)
	}
}

// imHandleText 是所有平台入站文本的统一入口。text 已由适配器归一化（去 @ 提及、
// 去空白）；msgID 是平台侧的原消息 id（用于盖「处理中」表情，可为空）。
// 命令即时回执；agent 轮先盖表情（或回文本）再回结果。
func (s *Server) imHandleText(platform, chatID, userID, msgID, text string) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	pg := s.m.pg
	cfg := s.imBotLoad()

	conv := s.imSessionConversation(platform, chatID, userID, cfg)
	if conv == nil {
		return // 开会话失败已回执
	}

	if cmd, ok := parseChatCommand(text); ok {
		reply := s.imHandleCommand(pg, platform, chatID, userID, conv, cmd)
		if reply != "" {
			s.imReply(platform, chatID, reply)
		}
		return
	}

	// 处理中信号：支持表情的平台在原消息上盖 Typing、回复后移除；否则回一条文本。
	reactionID := s.imAckWorking(platform, msgID)
	if reactionID == "" {
		s.imReply(platform, chatID, "收到，正在处理…")
	}
	if reply := s.imAgentTurn(conv, text); reply != "" {
		s.imReply(platform, chatID, reply)
	}
	if reactionID != "" {
		s.imClearWorking(platform, msgID, reactionID)
	}
}

// imAckWorking 给原消息盖「处理中」表情（仅飞书实现）；返回 reaction_id 供回复后
// 移除，空串表示平台不支持或盖失败（调用方退回文本回执）。
func (s *Server) imAckWorking(platform, msgID string) string {
	if msgID == "" || s.m == nil || s.m.pg == nil {
		return ""
	}
	cfg := s.imBotLoad()
	switch platform {
	case "feishu":
		rid, err := s.imFeishuReact(context.Background(), cfg, msgID, imFeishuWorkingEmoji)
		if err != nil {
			log.Printf("[im feishu] 盖处理中表情失败: %v", err)
			return ""
		}
		return rid
	}
	return ""
}

// imClearWorking 回复送达后移除「处理中」表情（失败只记日志，不影响结果）。
func (s *Server) imClearWorking(platform, msgID, reactionID string) {
	if msgID == "" || reactionID == "" {
		return
	}
	cfg := s.imBotLoad()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	switch platform {
	case "feishu":
		if err := s.imFeishuUnreact(ctx, cfg, msgID, reactionID); err != nil {
			log.Printf("[im feishu] 移除处理中表情失败: %v", err)
		}
	}
}

// imSessionConversation 返回该 chat 映射的会话；没有或已删则按配置开新会话。
func (s *Server) imSessionConversation(platform, chatID, userID string, cfg imBotConfig) *db.Conversation {
	pg := s.m.pg
	if m, err := pg.GetIMSession(platform, chatID); err == nil && m != nil {
		if c, err := pg.GetConversation(m.ConversationID); err == nil && c != nil {
			return c
		}
	}
	// 新会话：IM 来源标注进标题，web 对话页一眼可辨。
	agentKey := s.imBotAgentKey(cfg)
	title := "IM · " + platform
	if userID != "" {
		title += " · " + userID
	}
	nc, err := pg.CreateConversation(agentKey, title, nil)
	if err != nil {
		log.Printf("[im %s/%s] 开会话失败: %v", platform, chatID, err)
		s.imReply(platform, chatID, "开会话失败："+err.Error())
		return nil
	}
	if err := pg.UpsertIMSession(platform, chatID, nc.ID, userID); err != nil {
		log.Printf("[im %s/%s] 会话映射失败: %v", platform, chatID, err)
	}
	note := "会话由 IM（" + platform + "）创建。\n/bond 绑定项目/任务；/commands 看全部指令。"
	_, _ = pg.AppendConvActivity(nc.ID, db.Activity{
		Worker: agentKey, Kind: "text", Summary: firstLine(note, 200), Detail: note})
	return nc
}

// imHandleCommand 处理斜杠命令，返回要发回 IM 的文本。/new 会轮换映射到新会话。
func (s *Server) imHandleCommand(pg *db.DB, platform, chatID, userID string, conv *db.Conversation, cmd chatCommand) string {
	switch cmd.name {
	case "bond":
		return applyBondCommand(pg, conv.ID, cmd.args)
	case "commands", "help":
		return chatCommandHelp()
	case "new":
		nc, err := createSuccessorConversation(pg, conv)
		if err != nil {
			return "创建新会话失败：" + err.Error()
		}
		_ = pg.UpsertIMSession(platform, chatID, nc.ID, userID)
		note := successorNote(pg, conv)
		_, _ = pg.AppendConvActivity(nc.ID, db.Activity{
			Worker: nc.AgentKey, Kind: "text", Summary: firstLine(note, 200), Detail: note})
		_ = pg.TouchConversation(conv.ID)
		_ = pg.TouchConversation(nc.ID)
		return note
	default: // 形似指令但未知：回清单，避免打错字被静默喂给 LLM
		return "未知指令 " + cmd.raw + "。\n\n" + chatCommandHelp()
	}
}

// imAgentTurn 跑一轮 agent 对话并收集最终回复。与对话页共用 busy 控制与运行链路。
func (s *Server) imAgentTurn(conv *db.Conversation, text string) string {
	pg := s.m.pg
	busyKey := s.convBusyKey(conv.ID)
	s.chatMu.Lock()
	if s.chatBusy[busyKey] {
		s.chatMu.Unlock()
		return "这个会话正在处理上一条消息，请稍候再发。"
	}
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()
	defer func() {
		s.chatMu.Lock()
		delete(s.chatBusy, busyKey)
		s.chatMu.Unlock()
	}()

	before := imLatestActivityID(pg, conv.ID)
	ua := db.Activity{Worker: conv.AgentKey, Kind: "user", Summary: firstLine(text, 200), Detail: text}
	if _, err := pg.AppendConvActivity(conv.ID, ua); err != nil {
		log.Printf("[im conv %d] append user msg failed: %v", conv.ID, err)
	}
	_ = pg.TouchConversation(conv.ID)
	s.runConversationSync(conv, text, busyKey)
	return imCollectReply(pg, conv.ID, before)
}

// imLatestActivityID 取该会话最新活动的 id（增量收集回复的起点）。
func imLatestActivityID(pg *db.DB, convID int64) int64 {
	rows, _, err := pg.ConvActivityPage(convID, 0, 1)
	if err != nil || len(rows) == 0 {
		return 0
	}
	return rows[0].ID
}

// imCollectReply 从 before 之后的活动里取最终回复：优先本轮的 result（agent 终答，
// Detail 是完整 markdown），退而取最后的 text（含出错说明）。
func imCollectReply(pg *db.DB, convID, before int64) string {
	rows, _, err := pg.ConvActivityList(convID, before, 500)
	if err != nil {
		return "读取回复失败：" + err.Error()
	}
	var resultID, textID int64
	var textSummary string
	for _, a := range rows {
		switch a.Kind {
		case "result":
			resultID = a.ID
		case "text":
			textID = a.ID
			textSummary = a.Summary
		}
	}
	id, fallback := resultID, ""
	if id == 0 {
		id, fallback = textID, textSummary
	}
	if id == 0 {
		return "（本轮没有产出回复）"
	}
	detail, err := pg.ConvActivityDetail(convID, id)
	if err != nil {
		return "读取回复失败：" + err.Error()
	}
	if strings.TrimSpace(detail) == "" {
		detail = fallback
	}
	if strings.TrimSpace(detail) == "" {
		return "（本轮没有产出回复）"
	}
	return detail
}

// imReply 把文本发回 IM 聊天。各平台的发送差异在适配器里；失败只记日志（IM 侧
// 用户会自己重发，没有可靠的重试队列前不做投递引擎）。
func (s *Server) imReply(platform, chatID, text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	cfg := s.imBotLoad()
	ctx := context.Background()
	var err error
	switch platform {
	case "telegram":
		err = s.imTelegramSend(ctx, cfg, chatID, text)
	case "feishu":
		err = s.imFeishuSend(ctx, cfg, chatID, text)
	case "dingtalk":
		err = s.imDingtalkSend(ctx, cfg, chatID, text)
	case "wecom":
		err = s.imWecomSend(ctx, cfg, chatID, text)
	default:
		err = fmt.Errorf("im: 未知平台 %s", platform)
	}
	if err != nil {
		log.Printf("[im %s/%s] 发送失败: %v", platform, chatID, err)
	}
}

// imStopAll 停掉全部平台循环（进程关闭时由 context 取消，无需额外调用；
// 这里保留给配置热更时的全停场景）。
func (s *Server) imStopAll() {
	s.imMu.Lock()
	defer s.imMu.Unlock()
	for platform, cancel := range s.imCancels {
		cancel()
		delete(s.imCancels, platform)
	}
}
