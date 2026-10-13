package main

// 透明转发器:接收 iptables REDIRECT 来的连接,取 SO_ORIGINAL_DST 原始目标,
// 向上游 HTTP 代理发 CONNECT(443)或绝对形式请求(80),双向泵字节。
// 仅用于已授权的 SRC 测试抓包链路。

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	upstream   = "192.168.31.20:8899" // traffic-agent
	listenAddr = "127.0.0.1:18999"
)

func originalDst(c *net.TCPConn) (string, string, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return "", "", err
	}
	var addr [16]byte
	var slen uint32 = 16
	var ferr error
	err = rc.Control(func(fd uintptr) {
		// getsockopt(fd, SOL_IP=0, SO_ORIGINAL_DST=80, ...)
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, 0, 80,
			uintptr(unsafe.Pointer(&addr[0])), uintptr(unsafe.Pointer(&slen)), 0)
		if e != 0 {
			ferr = e
			return
		}
	})
	if err != nil {
		return "", "", err
	}
	if ferr != nil {
		return "", "", fmt.Errorf("getsockopt SO_ORIGINAL_DST: %v", ferr)
	}
	family := binary.LittleEndian.Uint16(addr[0:2])
	port := binary.BigEndian.Uint16(addr[2:4])
	ip := net.IP(addr[4:8])
	_ = family
	return ip.String(), fmt.Sprintf("%d", port), nil
}

func pipe(a, b net.Conn, tag string) {
	go func() {
		n, _ := io.Copy(a, b)
		log.Printf("[%s] ->upstream %d bytes", tag, n)
		a.Close()
		b.Close()
	}()
	n, _ := io.Copy(b, a)
	log.Printf("[%s] <-upstream %d bytes", tag, n)
	b.Close()
	a.Close()
}

func handle(client net.Conn) {
	tc, ok := client.(*net.TCPConn)
	if !ok {
		client.Close()
		return
	}
	ip, port, err := originalDst(tc)
	if err != nil {
		log.Printf("original-dst fail: %v", err)
		client.Close()
		return
	}
	hostPort := net.JoinHostPort(ip, port)
	log.Printf("conn original dst: %s", hostPort)

	up, err := net.Dial("tcp", upstream)
	if err != nil {
		log.Printf("upstream dial fail: %v", err)
		client.Close()
		return
	}

	if port == "443" {
		// TLS:CONNECT 隧道
		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort)
		if _, err := up.Write([]byte(req)); err != nil {
			log.Printf("connect write fail: %v", err)
			client.Close()
			up.Close()
			return
		}
		buf := make([]byte, 4096)
		n, err := up.Read(buf)
		if err != nil {
			log.Printf("connect read fail: %v", err)
			client.Close()
			up.Close()
			return
		}
		head := string(buf[:n])
		if len(head) < 12 || head[9:12] != "200" {
			log.Printf("connect refused: %q", head[:min(len(head), 120)])
			client.Close()
			up.Close()
			return
		}
		log.Printf("tunnel ok: %s", hostPort)
		pipe(tc, up, hostPort)
		return
	}

	// 明文 HTTP(80):改写为绝对形式发给代理
	// 简化:直接透传首请求由代理按相对 URI 处理会失败,这里读首行改写。
	buf := make([]byte, 8192)
	n, err := tc.Read(buf)
	if err != nil {
		client.Close()
		up.Close()
		return
	}
	head := string(buf[:n])
	if i := indexOf(head, "\r\n"); i > 0 {
		line := head[:i]
		// GET /path HTTP/1.1 -> GET http://hostPort/path HTTP/1.1
		sp1 := indexOf(line, " ")
		sp2 := lastIndexOf(line, " ")
		if sp1 > 0 && sp2 > sp1 {
			method := line[:sp1]
			path := line[sp1+1 : sp2]
			version := line[sp2+1:]
			if len(path) > 0 && path[0] == '/' {
				newline := fmt.Sprintf("%s http://%s%s %s", method, hostPort, path, version)
				head = newline + head[i:]
			}
		}
	}
	if _, err := up.Write([]byte(head)); err != nil {
		client.Close()
		up.Close()
		return
	}
	log.Printf("http relay: %s", hostPort)
	pipe(tc, up, hostPort)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func lastIndexOf(s, sub string) int {
	for i := len(s) - len(sub); i >= 0; i-- {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	log.SetOutput(os.Stderr)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("tfwd listening %s -> %s", listenAddr, upstream)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(c)
	}
}
