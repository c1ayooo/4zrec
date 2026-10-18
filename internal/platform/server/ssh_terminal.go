// ssh_terminal.go 全交互 SSH 终端:WebSocket ↔ SSH PTY 桥(移植自 4zreco
// ssh_terminal.go,协议原样——二进制帧=stdin 字节,文本帧={"type":"resize",
// "cols":N,"rows":M})。前端 xterm.js 直连;鉴权走同源 cookie(浏览器 WS 自动
// 携带,reqs 经既有 requireAuth);30 分钟硬超时。
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// sameOriginRequest rejects cross-origin WebSocket handshakes. Cookies
// authenticate but do not assert origin; browsers always send Origin for WS, so
// an empty Origin is only seen by non-browser clients.
func sameOriginRequest(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

type wsWriter struct {
	mu     sync.Mutex
	socket *websocket.Conn
}

func (w *wsWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := w.socket.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// connSSHTerminal GET /api/connections/{id}/terminal(WebSocket 升级)。
func (s *Server) connSSHTerminal(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := parsePathID(r)
	if id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	c, err := s.connByID(r.Context(), id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if c.Kind != "ssh" {
		writeErr(w, 400, "该连接不是 SSH 类型")
		return
	}
	s.serveSSHTerminal(w, r, c)
}

// serveSSHTerminal 终端核心(与台账解耦,测试可注入连接行)。
func (s *Server) serveSSHTerminal(w http.ResponseWriter, r *http.Request, c *db.Connection) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	client, err := dialSSHClient(ctx, c)
	if err != nil {
		if s.m != nil && s.m.pg != nil {
			_ = s.m.pg.UpdateConnectionStatus(r.Context(), c.ID, "dead")
		}
		writeErr(w, 502, err.Error())
		return
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		writeErr(w, 502, "会话创建失败: "+err.Error())
		return
	}
	defer session.Close()
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		writeErr(w, 502, "PTY 申请失败: "+err.Error())
		return
	}
	input, err := session.StdinPipe()
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	if err := session.Shell(); err != nil {
		writeErr(w, 502, "Shell 启动失败: "+err.Error())
		return
	}
	upgrader := websocket.Upgrader{
		ReadBufferSize: 4096, WriteBufferSize: 4096, HandshakeTimeout: 10 * time.Second,
		CheckOrigin: sameOriginRequest,
	}
	socket, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer socket.Close()
	if s.m != nil && s.m.pg != nil {
		_ = s.m.pg.UpdateConnectionStatus(r.Context(), c.ID, "alive")
	}
	stop := context.AfterFunc(ctx, func() { socket.Close() })
	defer stop()

	writer := &wsWriter{socket: socket}
	var copies sync.WaitGroup
	copies.Add(2)
	for _, reader := range []io.Reader{stdout, stderr} {
		go func(rd io.Reader) {
			defer copies.Done()
			if _, err := io.Copy(writer, rd); err != nil {
				socket.Close()
			}
		}(reader)
	}
	defer func() { socket.Close(); client.Close(); copies.Wait() }()
	go func() { copies.Wait(); socket.Close() }()

	// 保活:客户端 ping 每次刷新读期限。
	socket.SetReadLimit(64 << 10)
	_ = socket.SetReadDeadline(time.Now().Add(90 * time.Second))
	socket.SetPongHandler(func(string) error { return socket.SetReadDeadline(time.Now().Add(90 * time.Second)) })
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := socket.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					return
				}
			}
		}
	}()

	for {
		kind, data, err := socket.ReadMessage()
		if err != nil {
			return
		}
		switch kind {
		case websocket.BinaryMessage:
			if _, err := input.Write(data); err != nil {
				return
			}
		case websocket.TextMessage:
			var resize struct {
				Type string `json:"type"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
			}
			if json.Unmarshal(data, &resize) != nil || resize.Type != "resize" ||
				resize.Cols < 1 || resize.Cols > 500 || resize.Rows < 1 || resize.Rows > 300 {
				continue
			}
			_ = session.WindowChange(resize.Rows, resize.Cols)
		}
	}
}

// parsePathID 取 {id} 路径参数。
func parsePathID(r *http.Request) (int64, error) {
	var id int64
	v := r.PathValue("id")
	for _, ch := range v {
		if ch < '0' || ch > '9' {
			return 0, nil
		}
		id = id*10 + int64(ch-'0')
	}
	return id, nil
}
