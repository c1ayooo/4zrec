package server

import "testing"

func TestValidateProxyProfileInput(t *testing.T) {
	cases := []struct {
		name, url string
		ok        bool
	}{
		{"mihomo", "http://127.0.0.1:7890", true},
		{"intranet", "socks5://user:pass@10.0.0.2:1080", true},
		{"tls", "https://proxy.example.com:8443", true},
		{"", "http://127.0.0.1:7890", false},
		{"bad", "127.0.0.1:7890", false},
		{"bad", "ftp://127.0.0.1:21", false},
		{"bad", "http://", false},
	}
	for _, c := range cases {
		_, _, err := validateProxyProfileInput(c.name, c.url)
		if (err == nil) != c.ok {
			t.Fatalf("%q/%q: ok=%v err=%v", c.name, c.url, c.ok, err)
		}
	}
}

func TestFindProxyProfile(t *testing.T) {
	profiles := []ProxyProfile{
		{ID: "p1", Name: "mihomo", URL: "http://127.0.0.1:7890"},
		{ID: "p2", Name: "intranet", URL: "socks5://127.0.0.1:1080"},
	}
	if p, ok := findProxyProfile(profiles, "p2"); !ok || p.Name != "intranet" {
		t.Fatalf("find p2 = %+v %v", p, ok)
	}
	if _, ok := findProxyProfile(profiles, "missing"); ok {
		t.Fatal("missing profile should not resolve")
	}
	if got := proxyProfileURL(profiles, "p1"); got != "http://127.0.0.1:7890" {
		t.Fatalf("url = %q", got)
	}
	if got := proxyProfileURL(profiles, "missing"); got != "" {
		t.Fatalf("missing url = %q", got)
	}
}
