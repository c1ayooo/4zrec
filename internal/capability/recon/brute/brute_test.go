package brute

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/c1ayooo/4zrec/internal/capability/recon/dnsres"
)

// startStubDNS 起一个进程内 DNS 服务器(仅 A 记录):
// known 里的名字精确命中回其 IP;wildcardSuffix 非空时该后缀的一切名字回
// 泛解析 IP;其余 NXDOMAIN。
func startStubDNS(t *testing.T, known map[string]string, wildcardSuffix, wildcardIP string) (*dnsres.Pool, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub dns listen: %v", err)
	}
	server := &dns.Server{
		PacketConn: pc,
		UDPSize:    65535,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			q := req.Question[0]
			name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
			var ip string
			if v, ok := known[name]; ok {
				ip = v
			} else if wildcardSuffix != "" && strings.HasSuffix(name, "."+wildcardSuffix) && name != wildcardSuffix {
				ip = wildcardIP
			}
			if ip != "" && q.Qtype == dns.TypeA {
				rr, _ := dns.NewRR(name + ". 60 IN A " + ip)
				resp.Answer = append(resp.Answer, rr)
			} else {
				resp.Rcode = dns.RcodeNameError
			}
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	cleanup := func() { _ = server.Shutdown() }
	pool := dnsres.NewPool([]string{pc.LocalAddr().String()}, 32, time.Second, 2)
	return pool, cleanup
}

// TestBruteSelectiveDomain 选择性解析域:只命中真实存在的 api/www,其余 NXDOMAIN。
func TestBruteSelectiveDomain(t *testing.T) {
	pool, cleanup := startStubDNS(t, map[string]string{
		"api.sel.example": "10.1.1.1",
		"www.sel.example": "10.1.1.2",
	}, "", "")
	defer cleanup()
	hits, stats, err := Brute(context.Background(), "sel.example", Options{Pool: pool, Words: []string{"api", "www", "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("应命中 api/www 两个: %+v (stats %+v)", hits, stats)
	}
	byName := map[string]Hit{}
	for _, h := range hits {
		byName[h.Name] = h
	}
	if byName["api.sel.example"].IPs[0] != "10.1.1.1" || byName["www.sel.example"].IPs[0] != "10.1.1.2" {
		t.Fatalf("命中 IP 不符: %+v", byName)
	}
	if stats.Wildcard {
		t.Fatal("非泛解析域不应误判")
	}
	if stats.Probed < 3 {
		t.Fatalf("探测数异常: %d", stats.Probed)
	}
}

// TestBruteWildcardFiltered 泛解析域:整字典判活被基线过滤,零命中。
func TestBruteWildcardFiltered(t *testing.T) {
	pool, cleanup := startStubDNS(t, nil, "wild.example", "192.0.2.99")
	defer cleanup()
	hits, stats, err := Brute(context.Background(), "wild.example", Options{Pool: pool, Words: []string{"api", "www", "admin", "oa"}})
	if err != nil {
		t.Fatal(err)
	}
	if !stats.Wildcard {
		t.Fatal("泛解析未检出")
	}
	// 内置字典整体被泛解析应答滤掉;追加的 4 词必须在被滤之列。
	if len(hits) != 0 || stats.WildcardFiltered < 4 {
		t.Fatalf("泛解析域命中应全部被滤: hits=%d filtered=%d", len(hits), stats.WildcardFiltered)
	}
}

// TestBruteWildcardMixed 泛解析域上挂在【非基线 IP】的真实子域保留
// (与泛解析同 IP 的会被滤掉——puredns/shuffledns 同款已知代价)。
func TestBruteWildcardMixed(t *testing.T) {
	pool, cleanup := startStubDNS(t, map[string]string{
		"real.wild2.example": "10.9.9.9", // 非基线 IP
	}, "wild2.example", "192.0.2.99")
	defer cleanup()
	hits, stats, err := Brute(context.Background(), "wild2.example", Options{Pool: pool, Words: []string{"real", "fake"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Name != "real.wild2.example" {
		t.Fatalf("非基线 IP 的真实命中应保留: %+v", hits)
	}
	if stats.WildcardFiltered < 1 {
		t.Fatalf("基线命中应被滤: %+v", stats)
	}
}

// TestBruteInvalidDomain 非法主域直接报错。
func TestBruteInvalidDomain(t *testing.T) {
	if _, _, err := Brute(context.Background(), "nodot", Options{}); err == nil {
		t.Fatal("无点主域应报错")
	}
}

// TestBuiltinWords 内置字典:非空、全小写、含中文 SRC 高频词。
func TestBuiltinWords(t *testing.T) {
	words := BuiltinWords()
	if len(words) < 300 {
		t.Fatalf("内置字典过小: %d", len(words))
	}
	has := map[string]bool{}
	for _, w := range words {
		if w != strings.ToLower(w) {
			t.Fatalf("字典应全小写: %s", w)
		}
		has[w] = true
	}
	for _, want := range []string{"api", "oa", "erp", "uat", "admin", "pay", "vpn", "jenkins", "nacos", "sso"} {
		if !has[want] {
			t.Fatalf("高频词缺失: %s", want)
		}
	}
}
