package server

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// stubCNAMECNDNS cname.test.example → x.cdn.cloudflare.net(CNAME)→A 192.0.2.53;
// dead.test.example NXDOMAIN。
func stubCNAMECNDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub dns listen: %v", err)
	}
	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			q := req.Question[0]
			name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
			switch {
			case name == "cname.test.example" && q.Qtype == dns.TypeCNAME:
				rr, _ := dns.NewRR("cname.test.example. 60 IN CNAME x.cdn.cloudflare.net.")
				resp.Answer = append(resp.Answer, rr)
			case name == "cname.test.example" && q.Qtype == dns.TypeA:
				// CNAME + A 同答(真实解析器行为,Go resolver 顺链取 A)。
				cn, _ := dns.NewRR("cname.test.example. 60 IN CNAME x.cdn.cloudflare.net.")
				rr, _ := dns.NewRR("cname.test.example. 60 IN A 192.0.2.53")
				resp.Answer = append(resp.Answer, cn, rr)
			case name == "x.cdn.cloudflare.net" && q.Qtype == dns.TypeA:
				rr, _ := dns.NewRR("x.cdn.cloudflare.net. 60 IN A 192.0.2.53")
				resp.Answer = append(resp.Answer, rr)
			}
			if len(resp.Answer) == 0 {
				resp.Rcode = dns.RcodeNameError
			}
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	// Wait until the read loop is live; otherwise the tool's first query can race
	// startup and intermittently resolve NXDOMAIN.
	probe := &dns.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for {
		m := new(dns.Msg)
		m.SetQuestion("cname.test.example.", dns.TypeCNAME)
		if _, _, err := probe.Exchange(m, pc.LocalAddr().String()); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stub DNS server did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return pc.LocalAddr().String()
}

// TestEdgeClassifyTool CDN 边缘判定:经 CDN 的目标给出「找源站」结论(无库可跑,
// 解析池注入桩 DNS)。
func TestEdgeClassifyTool(t *testing.T) {
	s := &Server{}
	orig := newPoolAddr
	newPoolAddr = stubCNAMECNDNS(t)
	defer func() { newPoolAddr = orig }()

	in, _ := json.Marshal(map[string]any{"domains": []string{"cname.test.example"}})
	res, err := s.toolEdgeClassify().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("edge_classify 失败: %v %s", err, res.Flatten())
	}
	out := res.Flatten()
	if !strings.Contains(out, "cdn/") || !strings.Contains(out, "cdn_origin") {
		t.Fatalf("CDN 边缘应给出找源站结论:\n%s", out)
	}
}

// TestTakeoverCheckTool 死域给出接管方向线索。
func TestTakeoverCheckTool(t *testing.T) {
	s := &Server{}
	orig := newPoolAddr
	newPoolAddr = stubCNAMECNDNS(t)
	defer func() { newPoolAddr = orig }()

	in, _ := json.Marshal(map[string]any{"domains": []string{"dead.test.example"}})
	res, err := s.toolTakeoverCheck().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("takeover_check 失败: %v %s", err, res.Flatten())
	}
	if !strings.Contains(res.Flatten(), "dead.test.example") {
		t.Fatalf("死域应出现接管线索:\n%s", res.Flatten())
	}
}
