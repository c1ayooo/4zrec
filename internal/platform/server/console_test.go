package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// TestConnSSHExecConsole SSH 制台:内嵌 SSH 服务端,台账行一次 exec 返回输出。
func TestConnSSHExecConsole(t *testing.T) {
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
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
			go handleSSHConn(c, cfg)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	out, err := sshExecOnce(context.Background(), &db.Connection{
		Kind: "ssh", Host: "127.0.0.1", Port: port, Username: "root", Secret: "pw",
	}, "id", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if out == "" {
		t.Fatal("应返回命令输出")
	}
	// 错误口令 → 认证失败。
	if _, err := sshExecOnce(context.Background(), &db.Connection{
		Kind: "ssh", Host: "127.0.0.1", Port: port, Username: "root", Secret: "wrong",
	}, "id", 5*time.Second); err == nil {
		t.Fatal("错误口令应失败")
	}
}

// TestConnDBConsolePostgres 真 PG 制台:SELECT 返回列/行;建表/插入返回影响行数。
func TestConnDBConsolePostgres(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	// 从测试 DSN 取连接参数(socket peer 认证:user/password 留空)。
	c := &db.Connection{Kind: "postgres", Host: "/var/run/postgresql", Port: 5433, Username: "c1ay",
		Extra: json.RawMessage(`{"database":"artex_eino_migration"}`)}
	cols, rows, err := pgQueryConsole(context.Background(), c, "SELECT 1 AS one, 'x' AS two")
	if err != nil {
		t.Fatalf("制台查询失败: %v", err)
	}
	if len(cols) != 2 || len(rows) != 1 || rows[0][0] != "1" || rows[0][1] != "x" {
		t.Fatalf("结果不符: %v %v", cols, rows)
	}
	// 非查询语句 → 影响行数。
	cols2, rows2, err := pgQueryConsole(context.Background(), c, "CREATE TEMP TABLE console_t (id int)")
	if err != nil || cols2[0] != "affected_rows" {
		t.Fatalf("非查询应返回影响行数: %v %v", cols2, err)
	}
	_ = rows2
}
