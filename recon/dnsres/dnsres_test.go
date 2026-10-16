package dnsres

import (
	"strings"
	"testing"
	"time"
)

func TestNewPoolDefaultsAndCleanup(t *testing.T) {
	p := NewPool(nil, 0, 0, 0)
	if len(p.servers) == 0 {
		t.Fatal("空配置应回退内置解析器")
	}
	for _, s := range p.servers {
		if !strings.Contains(s, ":53") {
			t.Fatalf("服务器应补默认端口: %s", s)
		}
	}
	if cap(p.concurrency) != 32 {
		t.Fatalf("并发应按 32 兜底: %d", cap(p.concurrency))
	}
	if p.timeout != 3*time.Second || p.retries != 2 {
		t.Fatalf("超时/重试兜底不符: %v %d", p.timeout, p.retries)
	}
}

func TestNewPoolServerNormalize(t *testing.T) {
	p := NewPool([]string{"223.5.5.5", " 1.1.1.1:5353 ", "", "bad host with space"}, 4, time.Second, 1)
	if len(p.servers) != 2 {
		t.Fatalf("应丢弃非法条目: %v", p.servers)
	}
	if p.servers[0] != "223.5.5.5:53" || p.servers[1] != "1.1.1.1:5353" {
		t.Fatalf("服务器规范化不符: %v", p.servers)
	}
}

func TestRandomLabel(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		label := randomLabel()
		if len(label) != 12 {
			t.Fatalf("随机 label 长度应为 12: %s", label)
		}
		seen[label] = true
	}
	if len(seen) < 15 {
		t.Fatal("随机 label 重复率异常")
	}
}

func TestResolveEmptyHost(t *testing.T) {
	p := NewPool([]string{"127.0.0.1:1"}, 1, 100*time.Millisecond, 1)
	if _, err := p.Resolve(t.Context(), "  "); err == nil {
		t.Fatal("空主机名应报错")
	}
}
