package server

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/c1ayooo/4zrec/db"
)

// TestSSHTerminalWebSocket 终端协议端到端:内嵌 SSH 服务端回显 shell,
// WS 二进制帧=stdin、文本帧=resize(协议与 4zreco 一致)。
func TestSSHTerminalWebSocket(t *testing.T) {
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) == "pw" {
			return nil, nil
		}
		return nil, fmt.Errorf("bad")
	}}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := ssh.NewSignerFromKey(k)
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleEchoSSH(c, cfg)
		}
	}()
	sshPort := ln.Addr().(*net.TCPAddr).Port

	// 直连被测 handler(不走 requireAuth——鉴权层已有既有测试覆盖)。
	s := &Server{}
	_ = s
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/connections/{id}/terminal", func(w http.ResponseWriter, r *http.Request) {
		// 注入台账行直调核心:用查询参数传连接参数(测试桩)。
		c := &db.Connection{Kind: "ssh", Host: "127.0.0.1", Port: sshPort, Username: "root", Secret: "pw"}
		serveSSHTerminalForTest(w, r, c)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/connections/1/terminal"
	header := http.Header{}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("ws 连接失败(%d): %v", status, err)
	}
	defer conn.Close()

	// resize 文本帧应被接受(不导致连接关闭)。
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","cols":100,"rows":30}`)); err != nil {
		t.Fatal(err)
	}
	// 二进制帧=stdin:回显服务把收到的字节原样回写。
	payload := []byte("echo-hello\n")
	if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 0, 256)
	for len(got) < len(payload) {
		_, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("读回显失败: %v(已收 %q)", err, got)
		}
		got = append(got, data...)
	}
	if !strings.Contains(string(got), "echo-hello") {
		t.Fatalf("回显不符: %q", got)
	}
}

// handleEchoSSH 最小回显 shell:shell 请求后把 stdin 原样写回 stdout。
func handleEchoSSH(c net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "")
			continue
		}
		chanConn, chReqs, _ := ch.Accept()
		go func(cc ssh.Channel, cr <-chan *ssh.Request) {
			for req := range cr {
				switch req.Type {
				case "pty-req", "shell":
					_ = req.Reply(true, nil)
				default:
					_ = req.Reply(true, nil)
				}
			}
		}(chanConn, chReqs)
		go func(cc ssh.Channel) {
			buf := make([]byte, 4096)
			for {
				n, err := cc.Read(buf)
				if n > 0 {
					_, _ = cc.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		}(chanConn)
	}
}

// serveSSHTerminalForTest 与生产 handler 同核心(注入台账行,省去 DB)。
func serveSSHTerminalForTest(w http.ResponseWriter, r *http.Request, c *db.Connection) {
	s := &Server{}
	s.serveSSHTerminal(w, r, c)
}
