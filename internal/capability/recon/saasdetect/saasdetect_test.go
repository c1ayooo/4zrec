package saasdetect

import (
	"strings"
	"testing"
)

// builtinPath 内置表相对项目根路径（测试运行在包目录，逐级上溯）。
const builtinPath = "../../../../configs/saas-domains.yaml"

// TestMatchBuiltin 内置 YAML 表：加载 + 正反匹配样例（覆盖文档 §5.3 的服务清单）。
func TestMatchBuiltin(t *testing.T) {
	m, err := LoadFromFile(builtinPath)
	if err != nil {
		t.Fatalf("内置 SaaS 表加载失败（数据文件损坏）: %v", err)
	}
	cases := []struct {
		host string
		want string // 期望命中的服务 id
		hit  bool
	}{
		{"support.example.com", "", false},
		{"acme.zendesk.com", "zendesk", true},
		{"example.atlassian.net", "atlassian", true},
		{"status.acme.statuspage.io", "statuspage", true},
		{"docs.helpscoutdocs.com", "helpscout", true},
		{"help.intercom.io", "intercom", true},
		{"acme.slack.com", "slack", true},
		{"api.readme.io", "readme", true},
		{"myorg.github.io", "github_pages", true},
		{"app.vercel.app", "vercel", true},
		{"site.netlify.app", "netlify", true},
		{"api.stripe.com", "stripe", true},
		{"shop.myshopify.com", "shopify", true},
		{"cognito-idp.us-east-1.amazoncognito.com", "", false},
		{"myapp.auth.us-east-1.amazoncognito.com", "cognito", true},
		{"notion.site", "notion", true},
		// 大小写/尾部点/协议前缀容忍
		{"ACME.ZENDESK.COM.", "zendesk", true},
		{"https://acme.zendesk.com", "zendesk", true},
		// 反向：普通域名/边界不命中
		{"zendesk.com.example.com", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, hit := m.Match(c.host)
		if hit != c.hit {
			t.Errorf("Match(%q) hit=%v, want %v", c.host, hit, c.hit)
			continue
		}
		if !hit {
			continue
		}
		if got.ID != c.want {
			t.Errorf("Match(%q) = %s, want %s", c.host, got.ID, c.want)
		}
	}
}

// TestBuiltinSaaSConfigValid 内置表数据完整性守门：
// 1) 全部正则可编译（不合法 = 表数据 bug → 测试失败）；
// 2) 服务 id 唯一、非空；
// 3) 至少 10 条服务（防误删整段）。
func TestBuiltinSaaSConfigValid(t *testing.T) {
	m, err := LoadFromFile(builtinPath)
	if err != nil {
		t.Fatalf("内置 SaaS 表加载失败: %v", err)
	}
	svcs := m.Services()
	if len(svcs) < 10 {
		t.Errorf("SaaS 表服务数过少: %d < 10", len(svcs))
	}
	seen := map[string]bool{}
	for _, s := range svcs {
		if strings.TrimSpace(s.ID) == "" {
			t.Errorf("存在空 id 服务: %+v", s)
		}
		if seen[s.ID] {
			t.Errorf("服务 id 重复: %s", s.ID)
		}
		seen[s.ID] = true
		if len(s.Patterns) == 0 {
			t.Errorf("服务 %s 无匹配正则", s.ID)
		}
	}
}

// TestMatcherNilInput 空/畸形输入不 panic。
func TestMatcherNilInput(t *testing.T) {
	m, err := LoadFromFile(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{"", ".", "localhost", "192.168.1.1", "http://", " "}
	for _, in := range inputs {
		if _, hit := m.Match(in); hit {
			t.Errorf("Match(%q) 不应命中", in)
		}
	}
}
