package dnsres

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestCommonSRVNamesWellFormed(t *testing.T) {
	if len(CommonSRVNames) > 40 {
		t.Fatalf("SRV 清单应 ≤40，当前 %d（LookupSRV 内部截断语义应保持显式）", len(CommonSRVNames))
	}
	seen := map[string]bool{}
	for _, svc := range CommonSRVNames {
		if seen[svc] {
			t.Fatalf("重复条目: %s", svc)
		}
		seen[svc] = true
		if !hasSRVForm(svc) {
			t.Fatalf("形态非法（应为 _service._tcp/_udp）: %s", svc)
		}
	}
	// AD 域定位记录必须在列（域环境发现的关键入口）
	for _, key := range []string{"_ldap._tcp", "_kerberos._tcp", "_gc._tcp"} {
		if !seen[key] {
			t.Fatalf("关键 AD SRV 记录缺失: %s", key)
		}
	}
}

// hasSRVForm 校验 _service._tcp/_udp[.子域…] 形态（AD 的 dc._msdcs 系
// 记录是三段：_ldap._tcp.dc._msdcs，合法）。
func hasSRVForm(svc string) bool {
	if len(svc) == 0 || svc[0] != '_' {
		return false
	}
	rest := svc[1:]
	dot := strings.IndexByte(rest, '.')
	if dot < 0 || dot == len(rest)-1 {
		return false
	}
	proto := rest[dot+1:]
	if end := strings.IndexByte(proto, '.'); end >= 0 {
		proto = proto[:end] // _tcp 后还有段（.dc._msdcs）时只校验 _tcp 段
	}
	if len(proto) < 2 || proto[0] != '_' {
		return false
	}
	switch proto[1:] {
	case "tcp", "udp", "tls", "sips": // _sip._tls / _sips._tcp 为微软等历史约定
		return true
	}
	return false
}

func TestRRString(t *testing.T) {
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: "a.example.com."}, Target: "b.example.com."}
	if got := rrString(cname); got != "b.example.com" {
		t.Fatalf("CNAME 取值应去尾点: %q", got)
	}
	mx := &dns.MX{Hdr: dns.RR_Header{Name: "example.com."}, Preference: 10, Mx: "mail.example.com."}
	if got := rrString(mx); got != "10 mail.example.com" {
		t.Fatalf("MX 取值: %q", got)
	}
	srv := &dns.SRV{Hdr: dns.RR_Header{Name: "_ldap._tcp.example.com."}, Target: "dc01.corp.example.com.", Port: 389}
	if got := rrString(srv); got != "dc01.corp.example.com:389" {
		t.Fatalf("SRV 取值: %q", got)
	}
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: "example.com."}, Txt: []string{"v=spf1 ", "include:_spf.example.com"}}
	if got := rrString(txt); got != "v=spf1 include:_spf.example.com" {
		t.Fatalf("TXT 分段应拼接: %q", got)
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "a.example.com."}, A: net.ParseIP("1.2.3.4")}
	if got := rrString(a); got != "1.2.3.4" {
		t.Fatalf("A 取值: %q", got)
	}
}
