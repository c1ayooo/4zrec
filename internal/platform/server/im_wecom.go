package server

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// im_wecom.go 企业微信适配器。入站走「接收消息回调」（需要公网可访问的
// /api/im/wecom/callback，回调配置的 Token/EncodingAESKey 在设置里），
// 出站走自建应用 message/send API 回发到发起人单聊。
//
// 回调协议（官方加解密方案）：
//   - 签名：sha1(sort(Token, timestamp, nonce, encrypt) 拼接)
//   - 加密体：AES-CBC，key=Base64Decode(EncodingAESKey+"=")（32B），iv=key[:16]，
//     明文 = 16B 随机 + 4B 大端消息长度 + 消息 + receiveid
//   - GET 验证 URL：解密 echostr 后原样返回；POST 收到消息后 5s 内必须回
//     "success"（否则企微重推），所以业务派发是异步的。

const (
	imWecomHost      = "https://qyapi.weixin.qq.com"
	imWecomTokenTTL  = 110 * time.Minute
	imWecomURLVerify = "/api/im/wecom/callback"
)

// ---- 回调端点 ----

type imWecomCallbackEnvelope struct {
	XMLName  xml.Name `xml:"xml"`
	ToUserName string `xml:"ToUserName"`
	Encrypt    string `xml:"Encrypt"`
	AgentID    string `xml:"AgentID"`
}

type imWecomPlainMessage struct {
	XMLName  xml.Name `xml:"xml"`
	ToUserName   string `xml:"ToUserName"`
	FromUserName string `xml:"FromUserName"`
	CreateTime   int64  `xml:"CreateTime"`
	MsgType      string `xml:"MsgType"`
	Content      string `xml:"Content"`
	MsgID        int64  `xml:"MsgId"`
	ChatID       string `xml:"ChatId"`
}

// imWecomCallback 处理企业微信回调的 GET（URL 验证）与 POST（消息）。
func (s *Server) imWecomCallback(w http.ResponseWriter, r *http.Request) {
	cfg := s.imBotLoad()
	if !cfg.Wecom.Enabled || cfg.Wecom.CallbackToken == "" || cfg.Wecom.EncodingAESKey == "" {
		writeErr(w, 404, "企业微信接入未启用")
		return
	}
	q := r.URL.Query()
	msgSig, ts, nonce := q.Get("msg_signature"), q.Get("timestamp"), q.Get("nonce")

	if r.Method == http.MethodGet { // URL 验证：解密 echostr 原样返回
		echostr := q.Get("echostr")
		plain, err := imWecomDecrypt(cfg.Wecom.EncodingAESKey, msgSig, cfg.Wecom.CallbackToken, ts, nonce, echostr)
		if err != nil {
			log.Printf("[im wecom] URL 验证失败: %v", err)
			writeErr(w, 400, "验证失败")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(plain)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, 400, "读取失败")
		return
	}
	var env imWecomCallbackEnvelope
	if err := xml.Unmarshal(body, &env); err != nil || env.Encrypt == "" {
		writeErr(w, 400, "报文格式错误")
		return
	}
	plain, err := imWecomDecrypt(cfg.Wecom.EncodingAESKey, msgSig, cfg.Wecom.CallbackToken, ts, nonce, env.Encrypt)
	if err != nil {
		log.Printf("[im wecom] 解密失败: %v", err)
		writeErr(w, 400, "解密失败")
		return
	}
	var msg imWecomPlainMessage
	if err := xml.Unmarshal(plain, &msg); err != nil {
		writeErr(w, 400, "消息格式错误")
		return
	}
	// 5s 回执窗口：业务异步派发，立即回 success 制止重推。
	if msg.MsgType == "text" && strings.TrimSpace(msg.Content) != "" {
		go s.imHandleText("wecom", msg.FromUserName, msg.FromUserName, strconv.FormatInt(msg.MsgID, 10), strings.TrimSpace(msg.Content))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("success"))
}

// ---- 加解密与签名（可单测的纯函数）----

// imWecomSignature 计算回调签名：sha1(字典序拼接)。
func imWecomSignature(token, timestamp, nonce, encrypt string) string {
	parts := []string{token, timestamp, nonce, encrypt}
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	return fmt.Sprintf("%x", sum)
}

// imWecomDecrypt 校验签名并解密回调密文，返回消息明文 XML。
func imWecomDecrypt(aesKeyB64, msgSig, token, timestamp, nonce, encrypt string) ([]byte, error) {
	if msgSig == "" || encrypt == "" {
		return nil, fmt.Errorf("缺少签名或密文")
	}
	if imWecomSignature(token, timestamp, nonce, encrypt) != msgSig {
		return nil, fmt.Errorf("签名不匹配")
	}
	key, err := base64.StdEncoding.DecodeString(aesKeyB64 + "=")
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("EncodingAESKey 非法")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipherText, err := base64.StdEncoding.DecodeString(encrypt)
	if err != nil {
		return nil, fmt.Errorf("密文 base64 非法: %w", err)
	}
	if len(cipherText) == 0 || len(cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("密文长度非法")
	}
	plain := make([]byte, len(cipherText))
	cipher.NewCBCDecrypter(block, key[:16]).CryptBlocks(plain, cipherText)
	// 官方 PKCS7 按 32 字节块填充（即便 AES 块是 16），上限校验必须用 32。
	plain, err = imPKCS7Unpad(plain, 32)
	if err != nil {
		return nil, err
	}
	if len(plain) < 20 {
		return nil, fmt.Errorf("明文过短")
	}
	msgLen := binary.BigEndian.Uint32(plain[16:20])
	if int(msgLen)+20 > len(plain) {
		return nil, fmt.Errorf("消息长度越界")
	}
	return plain[20 : 20+msgLen], nil
}

func imPKCS7Unpad(data []byte, maxPad int) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("PKCS7: 长度非法")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > maxPad || pad > len(data) {
		return nil, fmt.Errorf("PKCS7: 填充非法")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("PKCS7: 填充不一致")
		}
	}
	return data[:len(data)-pad], nil
}

// ---- 发送（自建应用 message/send）----

var (
	imWecomTokenMu sync.Mutex
	imWecomToken   string
	imWecomKey     string // corpID+secret 指纹，配置换绑时强制刷新
	imWecomTokenAt time.Time
)

func imWecomAccessToken(ctx context.Context, corpID, corpSecret string, force bool) (string, error) {
	imWecomTokenMu.Lock()
	defer imWecomTokenMu.Unlock()
	key := corpID + "|" + corpSecret
	if !force && imWecomToken != "" && imWecomKey == key && time.Now().Before(imWecomTokenAt) {
		return imWecomToken, nil
	}
	u := fmt.Sprintf("%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s", imWecomHost, corpID, corpSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
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
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", err
	}
	if res.ErrCode != 0 || res.AccessToken == "" {
		return "", fmt.Errorf("企微 token 错误 %d: %s", res.ErrCode, res.ErrMsg)
	}
	imWecomToken = res.AccessToken
	imWecomKey = key
	ttl := time.Duration(res.ExpiresIn) * time.Second
	if ttl <= 0 || ttl > imWecomTokenTTL {
		ttl = imWecomTokenTTL
	}
	imWecomTokenAt = time.Now().Add(ttl - 5*time.Minute)
	return imWecomToken, nil
}

// imWecomSend 回发文本到指定成员的应用单聊（chatID 即企微 userid）。
func (s *Server) imWecomSend(ctx context.Context, cfg imBotConfig, chatID, text string) error {
	if cfg.Wecom.CorpID == "" || cfg.Wecom.CorpSecret == "" || cfg.Wecom.AgentID <= 0 {
		return fmt.Errorf("企微应用配置不完整")
	}
	token, err := imWecomAccessToken(ctx, cfg.Wecom.CorpID, cfg.Wecom.CorpSecret, false)
	if err != nil {
		return err
	}
	// markdown 类型：加粗/引用/链接可渲染。content 上限 2048 字节，按最坏 CJK 取 650 符。
	body, _ := json.Marshal(map[string]any{
		"touser":  chatID,
		"msgtype": "markdown",
		"agentid": cfg.Wecom.AgentID,
		"markdown": map[string]string{"content": imTruncateRunes(text, 650)},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		imWecomHost+"/cgi-bin/message/send?access_token="+token, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	_ = json.Unmarshal(raw, &res)
	if res.ErrCode != 0 {
		return fmt.Errorf("企微发送错误 %d: %s", res.ErrCode, res.ErrMsg)
	}
	return nil
}
