package db

import "database/sql"

// im_sessions.go IM 接入的聊天↔会话映射:IM 里每个 chat(单聊=用户,群聊=群)
// 固定绑定一个平台会话,/bond /new 与对话页操作同一条链路。会话被删时 FK 级联
// 清掉映射,下次该 chat 来消息自动开新会话。

// IMSession is one IM chat's binding to a platform conversation.
type IMSession struct {
	Platform       string `json:"platform"`
	ChatID         string `json:"chat_id"`
	ConversationID int64  `json:"conversation_id"`
	UserID         string `json:"user_id,omitempty"`
}

const imSessionCols = `platform, chat_id, conversation_id, COALESCE(user_id,'')`

// GetIMSession returns the chat's mapping (nil if none yet).
func (d *DB) GetIMSession(platform, chatID string) (*IMSession, error) {
	var m IMSession
	err := d.QueryRow(`SELECT `+imSessionCols+` FROM im_sessions WHERE platform=$1 AND chat_id=$2`,
		platform, chatID).Scan(&m.Platform, &m.ChatID, &m.ConversationID, &m.UserID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// UpsertIMSession binds the chat to a conversation (the /new rotation path
// overwrites the previous binding; the old conversation itself is kept).
func (d *DB) UpsertIMSession(platform, chatID string, conversationID int64, userID string) error {
	_, err := d.Exec(`
INSERT INTO im_sessions(platform, chat_id, conversation_id, user_id) VALUES ($1,$2,$3,NULLIF($4,''))
ON CONFLICT (platform, chat_id) DO UPDATE
SET conversation_id = EXCLUDED.conversation_id, user_id = EXCLUDED.user_id`,
		platform, chatID, conversationID, userID)
	return err
}
