package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestReporterPromptSeverityRubric 钉住报告定级口径:提示词与 report_finding 的
// severity 说明必须包含按证据深度定级、部分验证最高 medium、为什么不是上一级、
// 数据泄露抽样范围等硬约束,防止后续编辑把标尺改丢。
func TestReporterPromptSeverityRubric(t *testing.T) {
	for _, want := range []string{
		"定级标尺（按证据深度定级，不按想象后果）",
		"取「影响范围」与「证据深度」两者中较低的一档",
		"最高 medium",
		"（未端到端验证）",
		"为什么不是上一级",
		"已确认字段范围",
		"已抽样确认正文为公开内容",
		"推断：基于框架行为或同类接口的推测",
		"━━ 截断证据的处理 ━━",
		"已截断，原长 N 字节",
		"交付前自检",
	} {
		if !strings.Contains(ReporterDefaultPrompt, want) {
			t.Errorf("reporter prompt missing %q", want)
		}
	}
	b, _ := json.Marshal(NewToolSet(nil, "").addFinding().InputSchema())
	for _, want := range []string{"较低一档", "未端到端验证", "数据落地", "完整实体样本", "已截断，原长 N 字节"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("report_finding severity schema missing %q", want)
		}
	}
}

func TestRenderSystemOverrideAndFallback(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })

	// no override → built-in default
	PromptOverride = nil
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "g"}); got != "DEFAULT" {
		t.Fatalf("no override should give default, got %q", got)
	}

	// override → rendered with vars
	PromptOverride = func(k string) (string, bool) {
		if k == "planner" {
			return "目标:{{.Goal}} 范围:{{.Scope}}", true
		}
		return "", false
	}
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "拿下X", Scope: "*.x.com"}); got != "目标:拿下X 范围:*.x.com" {
		t.Fatalf("override render: %q", got)
	}

	// override referencing a non-catalog var → execution error → fallback to default
	PromptOverride = func(k string) (string, bool) { return "{{.NotInCatalog}}", true }
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "x"}); got != "DEFAULT" {
		t.Fatalf("bad var should fall back to default, got %q", got)
	}

	// full plannerSystem path: DB body [A] is honored, then the code-owned tail
	// [C] (中间产物输出规约) is ALWAYS appended — editing the body can't drop it.
	PromptOverride = func(k string) (string, bool) { return "PLANNER {{.Goal}}", true }
	got := plannerSystem("拿下X", "/data", "/data", "")
	if !strings.HasPrefix(got, "PLANNER 拿下X") {
		t.Fatalf("plannerSystem body not honored: %q", got)
	}
	if !strings.Contains(got, "中间产物输出规约") || !strings.Contains(got, "/data") {
		t.Fatalf("plannerSystem missing code-owned artifact tail: %q", got)
	}

	// worker dual-text via {{if .ProxyAddr}} in a user template, plus the code tail:
	// [B] trafficTool present only when RECORDING (caCert set — the MITM is on, so
	// the traffic_* tools exist), [C] artifact spec always present. The trafficTool
	// block is gated on the CA (arg 2), NOT on ProxyAddr — a global egress proxy
	// with capture off routes traffic but records nothing.
	PromptOverride = func(k string) (string, bool) {
		return "{{if .ProxyAddr}}走代理 {{.ProxyAddr}}{{else}}手动{{end}}", true
	}
	recording := workerSystem("127.0.0.1:8080", "/ca.pem", "/data", "/data")
	if !strings.HasPrefix(recording, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker proxy branch body: %q", recording)
	}
	if !strings.Contains(recording, "traffic_search") {
		t.Fatalf("worker while recording should inject trafficTool: %q", recording)
	}
	if strings.Contains(recording, "traffic_refs") {
		t.Fatalf("worker bypassed shared optional evidence policy: %q", recording)
	}
	if !strings.Contains(recording, "中间产物输出规约") {
		t.Fatalf("worker missing artifact tail: %q", recording)
	}
	// Egress proxy set but capture OFF (no CA): the ProxyAddr template branch still
	// renders, but the trafficTool block must NOT — those tools are not registered.
	egressOnly := workerSystem("127.0.0.1:8080", "", "/data", "/data")
	if !strings.HasPrefix(egressOnly, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker egress-only branch body: %q", egressOnly)
	}
	if strings.Contains(egressOnly, "traffic_search") {
		t.Fatalf("worker without recording must NOT inject trafficTool: %q", egressOnly)
	}
	noProxy := workerSystem("", "", "/data", "/data")
	if !strings.HasPrefix(noProxy, "手动") {
		t.Fatalf("worker no-proxy branch body: %q", noProxy)
	}
	if strings.Contains(noProxy, "traffic_search") {
		t.Fatalf("worker without proxy must NOT inject trafficTool: %q", noProxy)
	}

	// HTTP 工具优先级是代码固定尾巴:改 DB body 删不掉;渗透类 chat agent 同样注入,
	// 非渗透类(reporter)不注入。
	if !strings.Contains(got, "先走 http_probe") {
		t.Fatalf("plannerSystem missing code-owned HTTP tool policy: %q", got)
	}
	if !strings.Contains(recording, "先走 http_probe") || !strings.Contains(recording, "写明原因") {
		t.Fatalf("workerSystem missing code-owned HTTP tool policy: %q", recording)
	}
	if !strings.Contains(chatSystem("pentest", "/data", "/work"), "先走 http_probe") {
		t.Fatal("pentest chat prompt should carry the HTTP tool policy")
	}
	if strings.Contains(chatSystem("reporter", "/data", "/work"), "先走 http_probe") {
		t.Fatal("reporter chat prompt should not carry the HTTP tool policy")
	}
}
