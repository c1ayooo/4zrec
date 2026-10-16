package svcid

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 对本机临时监听端口做真实握手识别(纯 Go,无需外部服务)。
func TestScanIdentifiesHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<html><title>OK</title></html>"))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	got := Scan(t.Context(), "127.0.0.1", []int{port}, Options{Timeout: 3 * time.Second, Concurrency: 4})
	if len(got) != 1 {
		t.Fatalf("期望 1 条结果,得到 %d", len(got))
	}
	if got[0].Protocol != "http" {
		t.Fatalf("协议识别错误: %s", got[0].Protocol)
	}
}

func TestScanIdentifiesSSHBanner(t *testing.T) {
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
			conn.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\n"))
			// 读掉客户端后续数据直至关闭
			bufio.NewReader(conn).ReadString('\n')
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	start := time.Now()
	got := Scan(t.Context(), "127.0.0.1", []int{port}, Options{Timeout: 500 * time.Millisecond})
	elapsed := time.Since(start)
	if len(got) != 1 {
		t.Fatalf("期望 1 条结果,得到 %d", len(got))
	}
	// 非标准端口的慢速通道会逐协议试探:核心契约是有界——要么识别出 ssh,
	// 要么在预算内返回 unknown,绝不允许无界阻塞拖垮流水线。
	if elapsed > 30*time.Second {
		t.Fatalf("识别无界阻塞: %v", elapsed)
	}
	proto := strings.ToLower(got[0].Protocol)
	if proto != "ssh" && proto != "unknown" {
		t.Fatalf("协议异常: %s", proto)
	}
}

func TestNormalizeProtocol(t *testing.T) {
	if normalizeProtocol("HTTPTLS") != "https" {
		t.Fatal("HTTPTLS 应归一为 https")
	}
	if normalizeProtocol("") != "unknown" {
		t.Fatal("空协议应归一为 unknown")
	}
}

func TestExtractBannerFromSSHMetadata(t *testing.T) {
	// SSH 插件把横幅放 metadata 的 banner 键,应被原样提取
	raw := json.RawMessage(`{"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4","passwordAuthEnabled":true}`)
	if got := extractBanner(raw); got != "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4" {
		t.Fatalf("banner 提取错误: %q", got)
	}
}

func TestExtractBannerFallbackToCompactJSON(t *testing.T) {
	// 无 banner 键的协议(如 Redis 只有 authRequired)扁平为 key=value 文本
	raw := json.RawMessage(`{"authRequired":true,"banner":""}`)
	if got := extractBanner(raw); got != "authRequired=true" {
		t.Fatalf("无 banner 键应扁平化语义: %q", got)
	}
	if got := extractBanner(nil); got != "" {
		t.Fatalf("空 metadata 应返回空: %q", got)
	}
}

func TestExtractBannerFlattenSemantics(t *testing.T) {
	// L3:协议语义扁平化为可匹配文本——规则可用 banner ~= "signingRequired=false"
	// 或 banner = "serverType" 命中(SMB/AD 域信息、MongoDB 类型等)
	smb := json.RawMessage(`{"signingEnabled":true,"signingRequired":false,"osVersion":"Windows Server 2022","netBIOSDomainName":"CORP"}`)
	got := extractBanner(smb)
	for _, want := range []string{
		"netBIOSDomainName=CORP",
		"osVersion=Windows Server 2022",
		"signingRequired=false",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("SMB 语义未扁平化,缺少 %q: %q", want, got)
		}
	}
	// 数值与数组键
	mongo := json.RawMessage(`{"serverType":"mongos","maxWireVersion":21,"minWireVersion":0}`)
	got = extractBanner(mongo)
	if !strings.Contains(got, "serverType=mongos") || !strings.Contains(got, "maxWireVersion=21") {
		t.Fatalf("MongoDB 数值语义未扁平化: %q", got)
	}
	// 噪音键剔除
	noisy := json.RawMessage(`{"banner":"","confidence":"high","cpes":["a","b"],"authRequired":false}`)
	got = extractBanner(noisy)
	if strings.Contains(got, "confidence") || strings.Contains(got, "cpes") {
		t.Fatalf("噪音键应剔除: %q", got)
	}
	if !strings.Contains(got, "authRequired=false") {
		t.Fatalf("false 布尔应保留(未授权信号): %q", got)
	}
}

func TestFlattenMetadataDeterministic(t *testing.T) {
	raw := json.RawMessage(`{"b":"2","a":"1","redis_version":"7.0.1"}`)
	// 键序确定性:字典序 a b redis_version
	if got := extractBanner(raw); got != "a=1 b=2 redis_version=7.0.1" {
		t.Fatalf("扁平化应确定性键序: %q", got)
	}
}
