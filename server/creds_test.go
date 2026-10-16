package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/c1ayooo/4zrec/creds"
)

// TestCloudVerifyAliyunStub 阿里云验证(端点注入桩):成功路径与无效密钥路径。
func TestCloudVerifyAliyunStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "Credential=good-key") {
			_, _ = w.Write([]byte(`{"AccountId":"1234567890","Arn":"acs:ram::1234567890:user/test"}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"Code":"InvalidAccessKeyId.NotFound","Message":"指定的 AccessKey 不存在"}`))
	}))
	defer srv.Close()
	orig := creds.BaseURLOverride
	creds.BaseURLOverride = srv.URL
	defer func() { creds.BaseURLOverride = orig }()

	res, err := creds.Verify(context.Background(), nil, "aliyun", "good-key", "whatever")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || res.Status != "valid" || res.AccountID != "1234567890" {
		t.Fatalf("有效凭据判定错误: %+v", res)
	}
	res2, _ := creds.Verify(context.Background(), nil, "aliyun", "bad-key", "x")
	if res2.Valid || res2.Status == "valid" {
		t.Fatalf("无效凭据应判 invalid: %+v", res2)
	}
}

// TestDBProbePostgres 真 PG 实连(测试库 DSN 解析;无库跳过)。
func TestDBProbePostgres(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("no test DSN")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Skipf("dsn parse: %v", err)
	}
	port, _ := strconvAtoi(u.Port())
	host := hostnameOf(u)
	q := u.Query()
	if v := q.Get("host"); v != "" {
		host = v
	}
	if v := q.Get("port"); v != "" {
		if p, err2 := strconvAtoi(v); err2 == nil {
			port = p
		}
	}
	if port == 0 {
		port = 5432
	}
	// socket 目录作为 host 时,pgx 走 peer 认证(无用户密码段)。
	in := creds.DBProbeInput{
		Type: "postgres", Host: host, Port: port,
		Username: u.User.Username(), Database: strings.TrimPrefix(u.Path, "/"),
	}
	if u.User != nil {
		if pw, ok := u.User.Password(); ok {
			in.Password = pw
		}
	}
	_ = strings.TrimSpace("")
	res, err := creds.VerifyDB(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Alive || !res.Authed {
		t.Fatalf("真库实连应成功: %+v", res)
	}
	if res.User == "" || res.Version == "" {
		t.Fatalf("权限面结论缺失: %+v", res)
	}
}

// TestDBProbeRedisStub 裸 RESP 桩:无密码未授权访问判定。
func TestDBProbeRedisStub(t *testing.T) {
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
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					cmd := string(buf[:n])
					switch {
					case strings.Contains(cmd, "PING"):
						_, _ = c.Write([]byte("+PONG\r\n"))
					case strings.Contains(cmd, "INFO"):
						_, _ = c.Write([]byte("$60\r\n# Server\r\nredis_version:7.2.4\r\n\r\n"))
					default:
						_, _ = c.Write([]byte("+OK\r\n"))
					}
				}
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	res, err := creds.VerifyDB(context.Background(), creds.DBProbeInput{Type: "redis", Host: "127.0.0.1", Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Alive || !res.Authed {
		t.Fatalf("无密码 redis 应判未授权访问: %+v", res)
	}
	if !strings.Contains(res.Detail, "无密码") || res.Version == "" {
		t.Fatalf("结论应含未授权提示与版本: %+v", res)
	}
}

// TestSSHProbeStub 内嵌 SSH 服务:密码认证成功+id 输出+sudo 探测。
func TestSSHProbeStub(t *testing.T) {
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "root" && string(pw) == "s3cret" {
			return nil, nil
		}
		return nil, fmt.Errorf("auth failed")
	}}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatalf("签名器构造失败: %v", err)
	}
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
			go handleSSHConn(c, cfg)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	res, err := creds.VerifySSH(context.Background(), creds.SSHProbeInput{
		Host: "127.0.0.1", Port: port, Username: "root", Password: "s3cret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Alive || !res.Authed {
		t.Fatalf("正确凭据应通过: %+v", res)
	}
	if !strings.Contains(res.Groups, "uid=0") || !res.SudoNOPW {
		t.Fatalf("权限面结论不符(root+sudo): %+v", res)
	}
	res2, _ := creds.VerifySSH(context.Background(), creds.SSHProbeInput{
		Host: "127.0.0.1", Port: port, Username: "root", Password: "wrong",
	})
	if res2.Authed {
		t.Fatalf("错误凭据不应通过: %+v", res2)
	}
}

// handleSSHConn 最小 SSH 服务:执行请求的 exec,模拟 id/sudo 行为。
func handleSSHConn(c net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		conn, reqs, _ := ch.Accept()
		go func(chann ssh.Channel) {
			for req := range reqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				_ = req.Reply(true, nil)
				var payload struct{ Command string }
				_ = ssh.Unmarshal(req.Payload, &payload)
				switch {
				case strings.Contains(payload.Command, "sudo"):
					_, _ = chann.Write([]byte("SUDO_OK\n"))
				case strings.Contains(payload.Command, "id"):
					_, _ = chann.Write([]byte("uid=0(root) gid=0(root) groups=0(root)\n"))
				}
				_, _ = chann.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				_ = chann.Close()
			}
		}(conn)
	}
}

// TestGithubDorkStub dork 搜索(stub API + token 注入)。
func TestGithubDorkStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"total_count":1,"items":[{"repository":{"full_name":"org/leak","html_url":"https://github.com/org/leak"},"path":"config/db.py","html_url":"https://github.com/org/leak/blob/main/config/db.py","text_matches":[{"fragment":"PASSWORD = \"admin123\""}]}]}`))
	}))
	defer srv.Close()
	c := creds.NewClient(func() string { return "test-token" })
	c.BaseURL = srv.URL
	res, err := c.Search(context.Background(), "PASSWORD org:leak", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalCount != 1 || len(res.Items) != 1 || res.Items[0].Repo != "org/leak" {
		t.Fatalf("dork 结果解析错误: %+v", res)
	}
	if len(res.Items[0].Fragments) == 0 || !strings.Contains(res.Items[0].Fragments[0], "admin123") {
		t.Fatalf("片段缺失: %+v", res.Items[0])
	}
	// 工具层:模板清单自描述。
	s := &Server{}
	in, _ := json.Marshal(map[string]any{})
	out, err := s.toolGithubDork().Call(context.Background(), in, nil)
	if err != nil || !strings.Contains(out.Flatten(), "dork 模板") {
		t.Fatalf("模板清单应可列出: %v %s", err, out.Flatten())
	}
}

// 工具密码字段不回显:验证工具的只读放行(凭据经参数传入,不落盘不回显)。
func TestCredToolsReadOnly(t *testing.T) {
	s := &Server{}
	for _, name := range []string{"credential_verify_cloud", "credential_verify_db", "credential_verify_ssh", "github_dork"} {
		for _, t2 := range s.credTools() {
			if t2.Name() == name && !t2.IsReadOnly(nil) {
				t.Fatalf("%s 应为只读工具", name)
			}
		}
	}
}

func hostnameOf(u *url.URL) string {
	h := u.Hostname()
	if h == "" {
		return "127.0.0.1"
	}
	return h
}

func strconvAtoi(s string) (int, error) {
	if s == "" {
		return 5432, nil
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	return n, nil
}
