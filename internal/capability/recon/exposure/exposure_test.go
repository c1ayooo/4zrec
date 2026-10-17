package exposure

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// fakeTCPServer 起一个按脚本应答的临时 TCP 服务。
func fakeTCPServer(t *testing.T, handler func(c net.Conn)) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return host, p
}

func TestRedisUnauthorized(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		c.Write([]byte("+PONG\r\n")) // 无需认证即响应
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "redis"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Redis 未授权访问" {
		t.Fatalf("Redis 未授权未识别: %+v", r)
	}
}

func TestRedisRenameCommandNotConfigured(t *testing.T) {
	// INFO 应答 + CONFIG GET rename-command 返回 *0(未配置 rename=危险)
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf) // INFO
		c.Write([]byte("$50\r\nredis_version:7.0.1\r\n"))
		buf2 := make([]byte, 256)
		_, _ = c.Read(buf2)       // CONFIG GET rename-command
		c.Write([]byte("*0\r\n")) // 空数组:未配置 rename
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "redis"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Redis 未授权访问(危险命令未 rename)" {
		t.Fatalf("rename 未配置应高危判定: %+v", r)
	}
}

func TestRedisRenameCommandConfigured(t *testing.T) {
	// CONFIG GET rename-command 返回非空数组(已配置 rename=命令已改名)
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf) // INFO
		c.Write([]byte("$50\r\nredis_version:7.0.1\r\n"))
		buf2 := make([]byte, 256)
		_, _ = c.Read(buf2) // CONFIG GET rename-command
		c.Write([]byte("*2\r\n$11\r\nrename-command\r\n$9\r\nxrenamecmd\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "redis"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Redis 未授权访问" {
		t.Fatalf("rename 已配置应基础判定: %+v", r)
	}
}

func TestRedisWithAuthNotFlagged(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		c.Write([]byte("-NOAUTH Authentication required.\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "redis"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需要认证的 Redis 不应被标记: %+v", r)
	}
}

func TestMemcachedUnauthorized(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		c.Write([]byte("VERSION 1.6.14\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "memcached"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Memcached 未授权访问" {
		t.Fatalf("Memcached 未授权未识别: %+v", r)
	}
}

func TestFTPAnonymous(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		c.Write([]byte("220 FTP Server ready\r\n"))
		buf := make([]byte, 128)
		_, _ = c.Read(buf) // USER anonymous
		c.Write([]byte("331 Anonymous access allowed\r\n"))
		buf2 := make([]byte, 128)
		_, _ = c.Read(buf2) // PASS
		c.Write([]byte("230 Login successful\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "ftp"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "FTP 匿名登录可用" {
		t.Fatalf("FTP 匿名未识别: %+v", r)
	}
}

func TestElasticsearchNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"name":"node1","cluster_name":"es-prod","version":{"number":"8.11.0"}}`))
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "elasticsearch"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Elasticsearch 无认证访问" {
		t.Fatalf("ES 无认证未识别: %+v", r)
	}
}

func TestUnsupportedServiceSkipped(t *testing.T) {
	r := Scan(t.Context(), []Target{{Host: "127.0.0.1", Port: 1, Service: "ssh"}}, Options{Timeout: time.Second})
	if len(r) != 0 {
		t.Fatalf("不支持的服务不应有结果: %+v", r)
	}
}

func TestMongoDBNoAuth(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		// OP_REPLY(1) + responseFlags=0:cursorID(8)+startingFrom(4)+numberReturned(4)
		reply := make([]byte, 0, 36+15)
		reply = append(reply, byte(0x33), 0, 0, 0)                                        // messageLength=51
		reply = append(reply, byte(2), 0, 0, 0)                                           // requestID
		reply = append(reply, 0, 0, 0, 0)                                                 // responseTo
		reply = append(reply, 1, 0, 0, 0)                                                 // opCode=OP_REPLY
		reply = append(reply, 0, 0, 0, 0)                                                 // responseFlags=0(无认证门槛)
		reply = append(reply, make([]byte, 16)...)                                        // cursorID+startingFrom+numberReturned
		reply = append(reply, []byte{0x0f, 0, 0, 0, 0x08, 'o', 'k', 0, 1, 0, 0, 0, 0}...) // {"ok":1}
		c.Write(reply)
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "mongodb"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "MongoDB 无需认证访问" {
		t.Fatalf("MongoDB 无认证未识别: %+v", r)
	}
}

func TestMongoDBAuthRequiredNotFlagged(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		// responseFlags 0x01(QueryFailure)=需要认证,应为扫描器跳过
		reply := make([]byte, 0, 36)
		reply = append(reply, byte(0x24), 0, 0, 0) // messageLength=36
		reply = append(reply, byte(2), 0, 0, 0)    // requestID
		reply = append(reply, 0, 0, 0, 0)          // responseTo
		reply = append(reply, 1, 0, 0, 0)          // opCode=OP_REPLY
		reply = append(reply, 1, 0, 0, 0)          // responseFlags=QueryFailure
		reply = append(reply, make([]byte, 16)...)
		c.Write(reply)
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "mongodb"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需要认证的 MongoDB 不应被标记: %+v", r)
	}
}

func TestDockerAPIUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"Platform":{"Name":"Docker Engine"},"ApiVersion":"1.45","Version":"27.0.0"}`))
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "docker"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Docker API 未授权访问" {
		t.Fatalf("Docker API 未授权未识别: %+v", r)
	}
}

func TestDockerAPIAuthRequiredNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"message":"unauthorized"}`))
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "docker"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需认证的 Docker API 不应被标记: %+v", r)
	}
}

func TestSMBSigningNotRequired(t *testing.T) {
	host, port := smbTestServer(t, smbNegotiateResponse(0x01), nil)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "smb"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "SMB 签名未强制(可中继)" {
		t.Fatalf("SMB 签名未强制未识别: %+v", r)
	}
}

func TestSMBSigningRequiredNotFlagged(t *testing.T) {
	// 签名强制且无 NTLM 应答:不标记
	host, port := smbTestServer(t, smbNegotiateResponse(0x03), nil)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "smb"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("签名强制的 SMB 不应被标记: %+v", r)
	}
}

func TestSMBNTLMInfoUnauthenticated(t *testing.T) {
	// 签名强制(0x03)但 NTLMSSP challenge 可读:主机身份信息泄露仍成立
	// (域控正是这个形态——签名恒强制,域信息照样要提取)。
	host, port := smbTestServer(t, smbNegotiateResponse(0x03), smbSessionSetupResponse(testNTLMChallenge()))
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "smb"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "SMB NTLMSSP 主机信息未认证可读" {
		t.Fatalf("NTLMSSP 主机信息未识别: %+v", r)
	}
	for _, want := range []string{"corp.local", "win-abc.corp.local", "CORP", "WIN-ABC", "build 19041"} {
		if !strings.Contains(r[0].Detail, want) {
			t.Fatalf("Detail 缺 %q: %+v", want, r[0].Detail)
		}
	}
}

func TestSMBSigningWeakWithNTLMDetail(t *testing.T) {
	// 签名未强制 + NTLM 可读:中继风险为主判定,域信息并入 Detail
	host, port := smbTestServer(t, smbNegotiateResponse(0x01), smbSessionSetupResponse(testNTLMChallenge()))
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "smb"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "SMB 签名未强制(可中继)" {
		t.Fatalf("中继判定丢失: %+v", r)
	}
	if !strings.Contains(r[0].Detail, "SecurityMode=0x01") || !strings.Contains(r[0].Detail, "corp.local") {
		t.Fatalf("Detail 应含签名位与域信息: %+v", r[0].Detail)
	}
}

func TestSMBNTLMNegotiateBlobShape(t *testing.T) {
	blob := spnegoNTLMNegotiate()
	if blob == nil {
		t.Fatal("SPNEGO blob 为 nil")
	}
	if blob[0] != 0x60 {
		t.Fatalf("应为 [APPLICATION 0] 起始: 0x%02x", blob[0])
	}
	idx := bytes.Index(blob, []byte("NTLMSSP\x00"))
	if idx < 0 {
		t.Fatal("blob 缺 NTLMSSP 签名")
	}
	if binary.LittleEndian.Uint32(blob[idx+8:idx+12]) != 1 {
		t.Fatal("NTLM 消息类型应为 NEGOTIATE(1)")
	}
	if got := binary.LittleEndian.Uint32(blob[idx+12 : idx+16]); got != 0x02880205 {
		t.Fatalf("能力位不符: 0x%08x", got)
	}
	msg := smb2SessionSetupNTLMSSP()
	if binary.LittleEndian.Uint16(msg[12:14]) != 0x0001 {
		t.Fatal("命令应为 SESSION_SETUP")
	}
	if binary.LittleEndian.Uint64(msg[24:32]) != 1 {
		t.Fatal("MessageId 应为 1(NEGOTIATE 已用 0)")
	}
	if binary.LittleEndian.Uint16(msg[76:78]) != 88 {
		t.Fatal("SecurityBufferOffset 应为 88")
	}
	if binary.LittleEndian.Uint16(msg[78:80]) != uint16(len(blob)) {
		t.Fatal("SecurityBufferLength 与 blob 不符")
	}
	if !bytes.Equal(msg[88:88+len(blob)], blob) {
		t.Fatal("SecurityBuffer 未落在 88 偏移")
	}
}

func TestSMBParseNTLMSSPChallengeFields(t *testing.T) {
	// 应答外层是 SPNEGO/HTTP 噪声:签名扫描定位应不受影响
	noise := []byte{0xa1, 0x30, 0xff, 0x00}
	info, ok := parseNTLMSSPChallenge(append(noise, testNTLMChallenge()...))
	if !ok {
		t.Fatal("challenge 未解析")
	}
	if info.targetName != "CORP" || info.nbComputer != "WIN-ABC" {
		t.Fatalf("TargetName/NbComputer 不符: %+v", info)
	}
	if info.dnsComputer != "win-abc.corp.local" || info.dnsDomain != "corp.local" {
		t.Fatalf("DNS 字段不符: %+v", info)
	}
	if !strings.Contains(info.version, "10.0") || !strings.Contains(info.version, "19041") {
		t.Fatalf("Version 不符: %q", info.version)
	}
}

// ── SMB 测试工具 ──

// writeNBSS 以 direct TCP 帧头回写 SMB2 应答。
func writeNBSS(c net.Conn, msg []byte) {
	f := make([]byte, 4+len(msg))
	n := len(msg)
	f[1], f[2], f[3] = byte(n>>16), byte(n>>8), byte(n)
	copy(f[4:], msg)
	_, _ = c.Write(f)
}

// smbTestServer 按命令回放 SMB2 应答(NEGOTIATE→negotiateReply,
// SESSION_SETUP→setupReply 后断开)。
func smbTestServer(t *testing.T, negotiateReply, setupReply []byte) (string, int) {
	t.Helper()
	return fakeTCPServer(t, func(c net.Conn) {
		hdr := make([]byte, 4)
		for {
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
			body := make([]byte, n)
			if _, err := io.ReadFull(c, body); err != nil {
				return
			}
			switch binary.LittleEndian.Uint16(body[12:14]) {
			case 0x0000: // NEGOTIATE
				if negotiateReply != nil {
					writeNBSS(c, negotiateReply)
				}
			case 0x0001: // SESSION_SETUP
				if setupReply != nil {
					writeNBSS(c, setupReply)
				}
				return
			}
		}
	})
}

// smbNegotiateResponse 构造 NEGOTIATE 应答(头 64 + 体前 4 字节,
// SecurityMode 在 offset 66)。
func smbNegotiateResponse(secMode byte) []byte {
	msg := make([]byte, 68)
	copy(msg[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(msg[4:6], 64)
	binary.LittleEndian.PutUint16(msg[12:14], 0x0000)
	msg[66] = secMode
	return msg
}

// smbSessionSetupResponse 构造 SESSION_SETUP 应答(MORE_PROCESSING_REQUIRED
// + SecurityBuffer 内嵌 challenge)。
func smbSessionSetupResponse(blob []byte) []byte {
	msg := make([]byte, 72, 72+len(blob))
	copy(msg[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(msg[4:6], 64)
	binary.LittleEndian.PutUint32(msg[8:12], 0xC0000016) // STATUS_MORE_PROCESSING_REQUIRED
	binary.LittleEndian.PutUint16(msg[12:14], 0x0001)
	binary.LittleEndian.PutUint16(msg[64:66], 9) // StructureSize
	binary.LittleEndian.PutUint16(msg[68:70], 72)
	binary.LittleEndian.PutUint16(msg[70:72], uint16(len(blob)))
	return append(msg, blob...)
}

// testNTLMChallenge 构造 NTLMSSP CHALLENGE:TargetName=CORP,AV 含
// NbComputer=WIN-ABC / NbDomain=CORP / DnsComputer=win-abc.corp.local /
// DnsDomain=corp.local,Version=Win10 19041。
func testNTLMChallenge() []byte {
	av := func(id uint16, s string) []byte {
		u := utf16.Encode([]rune(s))
		b := []byte{byte(id), 0, byte(len(u) * 2), 0}
		for _, c := range u {
			b = binary.LittleEndian.AppendUint16(b, c)
		}
		return b
	}
	tn := utf16.Encode([]rune("CORP"))
	var targetName []byte
	for _, c := range tn {
		targetName = binary.LittleEndian.AppendUint16(targetName, c)
	}
	info := append(av(1, "WIN-ABC"), av(2, "CORP")...)
	info = append(info, av(3, "win-abc.corp.local")...)
	info = append(info, av(4, "corp.local")...)
	info = append(info, 0, 0, 0, 0) // EOL

	m := make([]byte, 56, 56+len(targetName)+len(info))
	copy(m, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(m[8:12], 2) // CHALLENGE
	binary.LittleEndian.PutUint16(m[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(m[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(m[16:20], 56)
	binary.LittleEndian.PutUint32(m[20:24], 0x02880205) // UNICODE|TARGET_INFO|VERSION 等
	binary.LittleEndian.PutUint16(m[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint32(m[44:48], uint32(56+len(targetName)))
	copy(m[48:56], []byte{10, 0, 0x61, 0x4a, 0, 0, 0, 15}) // Win10 19041
	m = append(m, targetName...)
	return append(m, info...)
}

func TestWinRMNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.WriteHeader(404) // 无认证网关:不接受 GET 但非 401
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "winrm"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "WinRM 无需认证访问" {
		t.Fatalf("WinRM 无认证未识别: %+v", r)
	}
}

func TestWinRMAuthRequiredNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.WriteHeader(401)
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "winrm"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需认证的 WinRM 不应被标记: %+v", r)
	}
}

func TestRSYNCAnonymousList(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf) // 客户端横幅
		c.Write([]byte("@RSYNCD: 31.0\n"))
		_, _ = c.Read(buf) // #list
		c.Write([]byte("public\tPublic Share\nbackup\tBackup Data\n@RSYNCD: EXIT\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "rsync"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "rsync 匿名可列模块" {
		t.Fatalf("rsync 匿名未识别: %+v", r)
	}
	if !strings.Contains(r[0].Detail, "public") {
		t.Fatalf("模块列表未提取: %+v", r[0].Detail)
	}
}

func TestRSYNCAuthRequiredNotFlagged(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf)
		c.Write([]byte("@RSYNCD: 31.0\n"))
		_, _ = c.Read(buf) // #list
		c.Write([]byte("@RSYNCD: EXIT\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "rsync"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需认证的 rsync 不应被标记: %+v", r)
	}
}

func TestK8sAPIAnonymous(t *testing.T) {
	// K8s API 6443 是 HTTPS,用 httptest.NewTLSServer 模拟
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/namespaces" {
			w.Write([]byte(`{"kind":"NamespaceList","items":[{"metadata":{"name":"default"}}]}`))
			return
		}
		w.Write([]byte(`{"major":"1","minor":"29","gitVersion":"v1.29.0"}`))
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portS)
	// Service 显式为 k8s-api 走 https+/version;namespaces 匿名可列 → 更高判定
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "k8s-api"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Kubernetes API 匿名可达(可列 namespace)" {
		t.Fatalf("K8s API 匿名未识别: %+v", r)
	}
}

func TestK8sAPINamespacesBlockedStillVersionFlagged(t *testing.T) {
	// /version 匿名但 /api/v1/namespaces 被 RBAC 拦截(403):降级为基础判定
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/namespaces" {
			w.WriteHeader(403)
			return
		}
		w.Write([]byte(`{"major":"1","minor":"29","gitVersion":"v1.29.0"}`))
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "k8s-api"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Kubernetes API 匿名可达" {
		t.Fatalf("namespace 拦截时应降级基础判定: %+v", r)
	}
}

func TestK8sAPIAuthRequiredNotFlagged(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "k8s-api"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需认证的 K8s API 不应被标记: %+v", r)
	}
}

func TestKubeletAnonymousPods(t *testing.T) {
	// Kubelet 10255 只读端口,GET /pods 匿名返回 pod 清单
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"kind":"PodList","items":[{"metadata":{"name":"nginx"}}]}`))
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "kubelet-ro"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Kubelet 匿名可达" {
		t.Fatalf("Kubelet 匿名未识别: %+v", r)
	}
}

func TestVNCNoAuth(t *testing.T) {
	// VNC 服务端:RFB 003.008 → 客户端回版本 → 服务端回安全类型 [None]
	host, port := fakeTCPServer(t, func(c net.Conn) {
		c.Write([]byte("RFB 003.008\n"))
		buf := make([]byte, 12)
		_, _ = c.Read(buf)    // 客户端版本
		c.Write([]byte{0x01}) // 安全类型数 = 1
		c.Write([]byte{0x01}) // None
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "vnc"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "VNC 无认证可连接" {
		t.Fatalf("VNC 无认证未识别: %+v", r)
	}
}

func TestVNCNoAuthAmongMultipleTypes(t *testing.T) {
	// 安全类型列表 [None, VNC Auth]:客户端可选择 None,仍属无认证可达
	host, port := fakeTCPServer(t, func(c net.Conn) {
		c.Write([]byte("RFB 003.008\n"))
		buf := make([]byte, 12)
		_, _ = c.Read(buf)
		c.Write([]byte{0x02})       // 安全类型数 = 2
		c.Write([]byte{0x01, 0x02}) // None / VNC Auth
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "vnc"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 {
		t.Fatalf("含 None 的安全类型应判定无认证: %+v", r)
	}
}

func TestVNCRequiredAuthNotFlagged(t *testing.T) {
	// 安全类型仅 [VNC Auth]:无 None,需认证
	host, port := fakeTCPServer(t, func(c net.Conn) {
		c.Write([]byte("RFB 003.008\n"))
		buf := make([]byte, 12)
		_, _ = c.Read(buf)
		c.Write([]byte{0x01}) // 安全类型数 = 1
		c.Write([]byte{0x02}) // VNC Auth
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "vnc"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需认证的 VNC 不应被标记: %+v", r)
	}
}

func TestLDAPAnonymousBindAllowed(t *testing.T) {
	// 服务端回 BindResponse resultCode=0(success)
	// LDAPMessage: 30 0c;BindResponse: 61 07 0a 01 00 04 00 04 00
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		c.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "ldap"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "LDAP 匿名 bind 允许" {
		t.Fatalf("LDAP 匿名 bind 未识别: %+v", r)
	}
}

func TestLDAPBindAuthRequiredNotFlagged(t *testing.T) {
	// BindResponse resultCode=49(invalidCredentials)
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		c.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00})
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "ldap"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需认证的 LDAP 不应被标记: %+v", r)
	}
}

func TestLDAPNonLDAPResponseNotFlagged(t *testing.T) {
	// 非 LDAP 应答(无 BindResponse 0x61):不标记
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		c.Write([]byte("HTTP/1.1 200 OK\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "ldap"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("非 LDAP 应答不应被标记: %+v", r)
	}
}

func TestLDAPAnonymousBindRequestShape(t *testing.T) {
	// 验证 BindRequest 字节形状:SEQUENCE + messageID + BindRequest + version + name + simple
	got := ldapAnonymousBindRequest()
	want := []byte{0x30, 0x0a, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	if len(got) != len(want) {
		t.Fatalf("长度不符: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("字节 %d 不符: got 0x%02x want 0x%02x", i, got[i], want[i])
		}
	}
}

func TestZooKeeperNoAuth(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 8)
		_, _ = c.Read(buf)
		c.Write([]byte("imok"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "zookeeper"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "ZooKeeper 无认证可访问" {
		t.Fatalf("ZooKeeper 无认证未识别: %+v", r)
	}
}

func TestZooKeeperNotZKNotFlagged(t *testing.T) {
	// 非 ZooKeeper 应答(不响应 ruok):不标记
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 8)
		_, _ = c.Read(buf)
		c.Write([]byte("HTTP/1.1"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "zookeeper"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("非 ZooKeeper 不应被标记: %+v", r)
	}
}

func TestKafkaNoAuth(t *testing.T) {
	// Kafka MetadataResponse v0: size + correlation_id + brokers 数组计数(=2)
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		reply := make([]byte, 12)
		binary.BigEndian.PutUint32(reply[0:4], 8)  // size(字段之后的长度)
		binary.BigEndian.PutUint32(reply[4:8], 1)  // correlation_id
		binary.BigEndian.PutUint32(reply[8:12], 2) // brokers 数量
		c.Write(reply)
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "kafka"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Kafka 无认证可访问" {
		t.Fatalf("Kafka 无认证未识别: %+v", r)
	}
}

func TestKafkaEmptyBrokersNotFlagged(t *testing.T) {
	// brokers 数组为空(0):无 broker 返回,判定需认证/无暴露
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		reply := make([]byte, 12)
		binary.BigEndian.PutUint32(reply[0:4], 8)
		binary.BigEndian.PutUint32(reply[4:8], 1)
		binary.BigEndian.PutUint32(reply[8:12], 0) // brokers = 0
		c.Write(reply)
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "kafka"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("空 broker 列表不应被标记: %+v", r)
	}
}

func TestKafkaMetadataRequestShape(t *testing.T) {
	got := kafkaMetadataV0Request()
	want := []byte{0x00, 0x00, 0x00, 0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	if len(got) != len(want) {
		t.Fatalf("长度不符: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("字节 %d 不符: got 0x%02x want 0x%02x", i, got[i], want[i])
		}
	}
}

func TestRabbitMQServiceExposed(t *testing.T) {
	// 服务端:收 AMQP 头后回 Connection.Start 方法帧
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 8)
		_, _ = c.Read(buf)
		// 帧:type=1 channel=0 size=12 class=0x000a method=0x000a(Start) + 帧尾
		frame := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x00}
		c.Write(frame)
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "amqp"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "RabbitMQ 服务暴露(默认 guest 通道)" {
		t.Fatalf("RabbitMQ 暴露未识别: %+v", r)
	}
}

func TestRabbitMQNonAMQPNotFlagged(t *testing.T) {
	// 非 AMQP 应答(非 method 帧):不标记
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 8)
		_, _ = c.Read(buf)
		c.Write([]byte("HTTP/1.1 200 OK\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "amqp"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("非 AMQP 不应被标记: %+v", r)
	}
}

func TestMSSQLServiceExposed(t *testing.T) {
	// 服务端:回 PRELOGIN 响应(type=0x12, length=16)
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf)
		reply := []byte{0x12, 0x01, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		c.Write(reply)
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "mssql"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "MSSQL 服务暴露(无凭据 prelogin 应答)" {
		t.Fatalf("MSSQL 暴露未识别: %+v", r)
	}
}

func TestMSSQLNotMSSQLNotFlagged(t *testing.T) {
	// 非 TDS 应答:不标记
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf)
		reply := []byte{0x03, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
		c.Write(reply)
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "mssql"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("非 MSSQL 不应被标记: %+v", r)
	}
}

func TestConsulAnonymous(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"Config":{"Revision":"123"},"Member":{"Name":"node1"}}`))
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "consul"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Consul 未授权访问" {
		t.Fatalf("Consul 未授权未识别: %+v", r)
	}
}

func TestNacosAnonymous(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"code":200,"success":true,"data":[]}`))
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "nacos"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Nacos 未授权访问" {
		t.Fatalf("Nacos 未授权未识别: %+v", r)
	}
}

func TestKibanaAnonymous(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"name":"kibana","status":{"overall":{"level":"available"}}}`))
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "kibana"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Kibana 未授权访问" {
		t.Fatalf("Kibana 未授权未识别: %+v", r)
	}
}

func TestSolrAnonymous(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"responseHeader":{"status":0},"core":[{"name":"collection1"}]}`))
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "solr"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Solr 未授权访问" {
		t.Fatalf("Solr 未授权未识别: %+v", r)
	}
}

func TestConsulAuthRequiredNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portS)
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "consul"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需认证的 Consul 不应被标记: %+v", r)
	}
}

func TestSquidAnonymousProxy(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf) // CONNECT
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "squid"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Squid 匿名代理可用" {
		t.Fatalf("Squid 匿名代理未识别: %+v", r)
	}
}

func TestSquidAuthRequiredNotFlagged(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf)
		c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "squid"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需认证的 Squid 不应被标记: %+v", r)
	}
}

func TestSMTPSAnonymous(t *testing.T) {
	// 隐式 TLS SMTP:自签证书 + 220 横幅
	cert := makeSelfSignedTLS(t)
	host, port := fakeTCPServer(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		tc.Write([]byte("220 mail.example.com ESMTP\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "smtps"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "SMTPS 服务暴露(匿名横幅)" {
		t.Fatalf("SMTPS 匿名未识别: %+v", r)
	}
}

// makeSelfSignedTLS 生成本地自签证书(与 svcid 测试同款)。
func makeSelfSignedTLS(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ── Oracle：TNS 版本未认证泄露 ──

func TestOracleVersionLeak(t *testing.T) {
	// REFUSE/ERROR 应答体内含 (VSNNUM=186647552) → 11.2.0.4.0
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf)
		c.Write([]byte("(ERROR_STACK=(ERROR=(CODE=12514))(VSNNUM=186647552)))"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "oracle"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Oracle TNS 版本未认证泄露" {
		t.Fatalf("Oracle 版本泄露未识别: %+v", r)
	}
	if !strings.Contains(r[0].Detail, "11.2.0.4.0") {
		t.Fatalf("版本解码不符: %+v", r[0].Detail)
	}
}

func TestOracleNoVSNNUMNotFlagged(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf)
		c.Write([]byte("(DESCRIPTION=(some tns echo))"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "oracle"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("无 VSNNUM 应答不应标记: %+v", r)
	}
}

func TestOracleVSNNUMDecode(t *testing.T) {
	if got := oracleVSNNUMVersion([]byte("(VSNNUM=186647552)")); !strings.Contains(got, "11.2.0.4.0") {
		t.Fatalf("186647552 应解码 11.2.0.4.0: %q", got)
	}
	if oracleVSNNUMVersion([]byte("(VSNNUM=abc)")) != "" {
		t.Fatal("非数字 VSNNUM 应返回空")
	}
}

func TestTNSVersionRequestShape(t *testing.T) {
	pkt := tnsVersionRequest()
	if int(binary.BigEndian.Uint16(pkt[0:2])) != len(pkt) {
		t.Fatalf("长度头与实际不符: %d vs %d", binary.BigEndian.Uint16(pkt[0:2]), len(pkt))
	}
	if !bytes.HasSuffix(pkt, []byte("(CONNECT_DATA=(COMMAND=VERSION))")) {
		t.Fatal("缺版本命令串")
	}
	if len(pkt) != 90 {
		t.Fatalf("报文总长应 90: %d", len(pkt))
	}
}

// ── Java RMI：JRMP ──

func TestRMIServiceExposed(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 16)
		_, _ = c.Read(buf) // JRMI 握手
		c.Write([]byte{0x4e, 0x00, 0x0d, 'j', 'a', 'v', 'a', '.', 'r', 'm', 'i'})
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "java-rmi"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Java RMI 服务暴露(JRMP)" {
		t.Fatalf("RMI 暴露未识别: %+v", r)
	}
}

func TestRMINotRMINotFlagged(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 16)
		_, _ = c.Read(buf)
		c.Write([]byte("HTTP/1.1 200 OK\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "java-rmi"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("非 JRMP 不应标记: %+v", r)
	}
}

// ── DCERPC：端点映射器 ──

func TestDCERPCAnonymousEnumerate(t *testing.T) {
	// bind_ack + EPM 查询应答(UTF-16LE 注释串)→ 匿名可枚举
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf) // bind
		ack := append([]byte{0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00}, make([]byte, 24)...)
		c.Write(ack)
		_, _ = c.Read(buf) // EPM 查询
		var resp []byte
		for _, s := range []string{"epmapper", "LRPC"} {
			for _, ch := range s {
				resp = append(resp, byte(ch), 0x00)
			}
			resp = append(resp, 0x00, 0x09)
		}
		c.Write(resp)
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "msrpc"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "DCERPC 端点映射器匿名可枚举" {
		t.Fatalf("EPM 匿名枚举未识别: %+v", r)
	}
	if !strings.Contains(r[0].Detail, "epmapper") {
		t.Fatalf("注释串未提取: %+v", r[0].Detail)
	}
}

func TestDCERPCBindAckOnlyAccessible(t *testing.T) {
	// bind_ack 但查询无应答:降级为可访问
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf)
		ack := append([]byte{0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00}, make([]byte, 24)...)
		c.Write(ack)
		_, _ = c.Read(buf)
		c.Close()
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "msrpc"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "DCERPC 端点映射器匿名可访问" {
		t.Fatalf("bind_ack 应判定可访问: %+v", r)
	}
}

func TestDCERPCBindRejectedNotFlagged(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 128)
		_, _ = c.Read(buf)
		c.Write(append([]byte{0x05, 0x00, 0x0d, 0x03, 0x10, 0x00, 0x00, 0x00}, make([]byte, 24)...)) // bind_nak
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "msrpc"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("bind_nak 不应标记: %+v", r)
	}
}

func TestDCERPCBindShape(t *testing.T) {
	pkt := dcerpcEPMBind()
	if len(pkt) != 72 {
		t.Fatalf("分片长度应 72: %d", len(pkt))
	}
	if !bytes.HasPrefix(pkt, []byte{0x05, 0x00, 0x0b, 0x03}) {
		t.Fatal("应为 bind PDU")
	}
	if binary.LittleEndian.Uint16(pkt[8:10]) != 72 {
		t.Fatal("frag_length 字段应 72")
	}
}

// ── SOCKS5：匿名开放代理 ──

func TestSOCKS5OpenProxy(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf) // 方法协商
		c.Write([]byte{0x05, 0x00})
		_, _ = c.Read(buf) // CONNECT
		c.Write([]byte{0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50})
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "socks5"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "SOCKS5 匿名开放代理可用" {
		t.Fatalf("SOCKS5 开放代理未识别: %+v", r)
	}
}

func TestSOCKS5AuthRequiredNotFlagged(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		c.Write([]byte{0x05, 0x02}) // 选中用户名/密码认证
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "socks5"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需认证的 SOCKS5 不应标记: %+v", r)
	}
}

// ── frp：隧道入口 ──

func TestFRPPortExposed(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 32)
		_, _ = c.Read(buf)
		c.Write([]byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "frp"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "frp 穿透服务端口暴露(隧道入口)" {
		t.Fatalf("frp 入口未识别: %+v", r)
	}
}

func TestFRPWrongMagicNotFlagged(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 32)
		_, _ = c.Read(buf)
		c.Write([]byte("HTTP/1.1 200 OK\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "frp"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("非 frp 魔数不应标记: %+v", r)
	}
}

// ── GIOP：CORBA/IIOP ──

func TestGIOPServiceExposed(t *testing.T) {
	host, port := fakeTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		c.Write([]byte{'G', 'I', 'O', 'P', 0x01, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "giop"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "CORBA/IIOP 服务暴露(命名服务应答)" {
		t.Fatalf("GIOP 未识别: %+v", r)
	}
	if !strings.Contains(r[0].Detail, "LocateReply") {
		t.Fatalf("应答类型未标注: %+v", r[0].Detail)
	}
}

func TestGIOPRequestShape(t *testing.T) {
	pkt := giopLocateNameService()
	if !bytes.HasPrefix(pkt, []byte("GIOP")) || pkt[4] != 1 || pkt[5] != 2 {
		t.Fatal("应为 GIOP 1.2 LocateRequest")
	}
	if pkt[6] != 0x00 || pkt[7] != 0x03 {
		t.Fatalf("标志/消息类型应 00/03: %02x/%02x", pkt[6], pkt[7])
	}
	if binary.LittleEndian.Uint32(pkt[8:12]) != uint32(len(pkt)-12) {
		t.Fatalf("消息体长度不符: %d vs %d", binary.LittleEndian.Uint32(pkt[8:12]), len(pkt)-12)
	}
	if !bytes.HasSuffix(pkt, []byte("NameService")) {
		t.Fatal("缺 object key")
	}
}

// ── NetBIOS：NBSTAT 解析 ──

func TestNBNSParseNodeStatus(t *testing.T) {
	computer, domain, isDC := parseNBNSNodeStatus(testNBNSResponse())
	if computer != "WIN-ABC" || domain != "WORKGROUP" {
		t.Fatalf("主机/域不符: computer=%q domain=%q", computer, domain)
	}
	if isDC {
		t.Fatal("无 DC 记录不应置位")
	}
}

func TestNBNSParseWithDCRecord(t *testing.T) {
	b := testNBNSResponse()
	// 追加域控制器组记录:CORP + 后缀 0x1C + 组名标志(0x84xx)
	entry := make([]byte, 18)
	copy(entry, "CORP")
	entry[15] = 0x1c
	entry[16] = 0x84
	// 名字计数 +1(原应答 RDATA 首字节为计数)
	b = append(b, entry...)
	b[63]++
	computer, domain, isDC := parseNBNSNodeStatus(b)
	if !isDC || domain != "CORP" || computer != "WIN-ABC" {
		t.Fatalf("DC 记录未解析: %+v", []any{computer, domain, isDC})
	}
}

func TestNBNSQueryShape(t *testing.T) {
	q := nbnsNodeStatusQuery()
	if len(q) != 50 {
		t.Fatalf("查询长度应 50: %d", len(q))
	}
	if q[12] != 0x20 || q[13] != 'C' || q[14] != 'K' {
		t.Fatal("通配名编码不符")
	}
	if !bytes.Equal(q[46:50], []byte{0x00, 0x21, 0x00, 0x01}) {
		t.Fatal("QTYPE/QCLASS 不符")
	}
}

// testNBNSResponse 构造 NBSTAT 应答:压缩指针应答 RR + 两个名字条目
// (WORKGROUP 组名 0x00 / WIN-ABC 唯一名 0x20)。名字计数位于 offset 63。
func testNBNSResponse() []byte {
	b := make([]byte, 64, 64+36)
	binary.BigEndian.PutUint16(b[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(b[6:8], 1) // ANCOUNT
	// 问题区:编码名(1+32+1) + QTYPE/QCLASS(4)
	b[12] = 0x20
	copy(b[13:45], bytes.Repeat([]byte{'A'}, 32))
	// 应答 RR:压缩指针 c0 0c + TYPE(NBSTAT)/CLASS/TTL/RDLENGTH 占位
	copy(b[51:], []byte{0xc0, 0x0c, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c})
	b[63] = 2 // 名字计数(RDATA 首 byte)
	// 名字条目 1:WORKGROUP 组名
	e1 := make([]byte, 18)
	copy(e1, "WORKGROUP")
	e1[15] = 0x00
	e1[16] = 0x84 // 组名(最高位)
	// 名字条目 2:WIN-ABC 文件服务唯一名
	e2 := make([]byte, 18)
	copy(e2, "WIN-ABC")
	e2[15] = 0x20
	e2[16] = 0x04 // 唯一名
	return append(append(b, e1...), e2...)
}

// ── Redis-TLS：隐式 TLS 未授权 ──

func TestRedisTLSUnauthorized(t *testing.T) {
	cert := makeSelfSignedTLS(t)
	host, port := fakeTCPServer(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		buf := make([]byte, 64)
		_, _ = tc.Read(buf) // INFO
		tc.Write([]byte("+PONG\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "redis-tls"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 1 || r[0].Finding != "Redis(TLS) 未授权访问" {
		t.Fatalf("TLS Redis 未授权未识别: %+v", r)
	}
	if r[0].Service != "redis-tls" {
		t.Fatalf("Service 应为 redis-tls: %+v", r[0].Service)
	}
}

func TestRedisTLSAuthRequiredNotFlagged(t *testing.T) {
	cert := makeSelfSignedTLS(t)
	host, port := fakeTCPServer(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		buf := make([]byte, 64)
		_, _ = tc.Read(buf)
		tc.Write([]byte("-NOAUTH Authentication required.\r\n"))
	})
	r := Scan(t.Context(), []Target{{Host: host, Port: port, Service: "redis-tls"}}, Options{Timeout: 2 * time.Second})
	if len(r) != 0 {
		t.Fatalf("需认证的 TLS Redis 不应标记: %+v", r)
	}
}
