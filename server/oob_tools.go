// oob_tools.go 带外验证与被动补充工具:dnslog(带外回连验证)、vt_subdomains
// (VirusTotal 被动子域)、ai_protocol_scan(AI 端点暴露面)。VT key 与 dnslog
// 自建地址走 settings + 环境变量。AI 扫描是主动探测:RoE 门控同 webrecon。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/oob"
	actool "github.com/c1ayooo/4zrec/tools"
)

// vtKey VT API Key(env 优先)。
func (s *Server) vtKey() string {
	if v := strings.TrimSpace(os.Getenv("VT_API_KEY")); v != "" {
		return v
	}
	if s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting("virustotal.key"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// toolDnslog DNSLog 带外验证。
func (s *Server) toolDnslog() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "dnslog",
		Description: "DNSLog 带外验证(盲注/SSRF/XXE 无回显场景):get_domain 拿临时域名拼进 payload," +
			"目标触发 DNS 查询后 get_records 查记录(可 wait_time 等待,建议 3-10s)。默认 dnslog.cn,可自建服务覆盖 base_url。" +
			"会话 cookie 持久化在系统临时目录,跨调用有效。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"operation": map[string]any{"type": "string", "enum": []string{"get_domain", "get_records"}, "description": "操作"},
				"domain":    map[string]any{"type": "string", "description": "get_records 时必填"},
				"wait_time": map[string]any{"type": "integer", "description": "get_records 前等待秒数(默认 0)"},
				"base_url":  map[string]any{"type": "string", "description": "DNSLog 服务地址(默认 http://dnslog.cn)"},
			},
			"required": []string{"operation"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Operation string `json:"operation"`
				Domain    string `json:"domain"`
				WaitTime  int    `json:"wait_time"`
				BaseURL   string `json:"base_url"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			switch strings.ToLower(strings.TrimSpace(in.Operation)) {
			case "get_domain":
				domain, err := oob.DnslogGetDomain(ctx, in.BaseURL)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return actool.Text(fmt.Sprintf(
					"临时域名: %s\n拼入 payload(如 DNS 带外: curl http://xx.%s)触发目标查询后,用 get_records(domain=%s) 查记录。",
					domain, domain, domain)), nil
			case "get_records":
				records, err := oob.DnslogGetRecords(ctx, in.BaseURL, in.Domain, in.WaitTime)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if len(records) == 0 {
					return actool.Text("暂无记录(目标未触发查询或需再等;必要时加大 wait_time 重试)"), nil
				}
				var b strings.Builder
				fmt.Fprintf(&b, "记录 %d 条:\n", len(records))
				for _, r := range records {
					fmt.Fprintf(&b, "- %s\n", r)
				}
				b.WriteString("有记录=带外通道打通,漏洞成立证据;登记 finding 时附记录原文。")
				return actool.Text(b.String()), nil
			}
			return actool.Errorf("operation 须为 get_domain|get_records"), nil
		},
	})
}

// toolVTSubdomains VT 被动子域。
func (s *Server) toolVTSubdomains() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "vt_subdomains",
		Description: "VirusTotal 被动子域枚举(不触达目标):聚合历史 DNS 数据发现子域,超过 40 条自动分页(页间限速)。" +
			"include_ips=true 时对前 40 个反查解析(注意免费 Key 4 次/分钟限额)。适合被动源交叉后的子域盲区补充。" +
			"需 VT_API_KEY 环境变量或系统设置。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"domain":      map[string]any{"type": "string"},
				"limit":       map[string]any{"type": "integer", "description": "上限(默认 40,最大 1000)"},
				"include_ips": map[string]any{"type": "boolean"},
			},
			"required": []string{"domain"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Domain     string `json:"domain"`
				Limit      int    `json:"limit"`
				IncludeIPs bool   `json:"include_ips"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			key := s.vtKey()
			if key == "" {
				return actool.Errorf("未配置 VirusTotal API Key(VT_API_KEY 环境变量或系统设置)"), nil
			}
			subs, ips, err := oob.VTSubdomains(ctx, key, in.Domain, in.Limit, in.IncludeIPs, nil, "")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "VT 被动子域 %d 条:\n", len(subs))
			for _, sub := range subs {
				if l, ok := ips[sub]; ok && len(l) > 0 {
					fmt.Fprintf(&b, "- %s [%s]\n", sub, strings.Join(l, ","))
				} else {
					fmt.Fprintf(&b, "- %s\n", sub)
				}
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolAIProtocolScan AI 端点暴露面探测。
func (s *Server) toolAIProtocolScan() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "ai_protocol_scan",
		Description: "AI 协议暴露面探测(主动 HTTP):对目标探测 LLM/OpenAI 兼容端点(/v1/models 可枚举=暴露)、" +
			"MCP 端点(JSON-RPC initialize 应答)、A2A agent 清单。命中即「AI 面裸奔」线索(未鉴权模型枚举/工具面)。" +
			"挂项目上下文时目标必须在授权范围内。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":        map[string]any{"type": "string", "description": "目标基 URL(http://host:port)"},
				"project_id": map[string]any{"type": "integer"},
			},
			"required": []string{"url"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(input, &in)
			return actool.AskUser("AI 端点探测(主动 HTTP)目标: " + in.URL)
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				URL       string `json:"url"`
				ProjectID int64  `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if msg := s.webreconRoE(ctx, in.ProjectID, in.URL); msg != "" {
				return actool.Errorf(msg), nil
			}
			results, err := oob.AIProtocolScan(ctx, in.URL, 8*time.Second)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var (
				b       strings.Builder
				exposed int
			)
			for _, r := range results {
				if r.Exposed {
					exposed++
					fmt.Fprintf(&b, "- [%s] %s %s\n", r.Kind, r.Path, r.Detail)
				}
			}
			if exposed == 0 {
				return actool.Text(fmt.Sprintf("探测 %d 个端点路径:未发现 AI 面暴露", len(results))), nil
			}
			fmt.Fprintf(&b, "\n命中 %d 处 AI 暴露面——未鉴权的模型/工具面,建议登记 finding 并评估越权调用面。", exposed)
			return actool.Text(b.String()), nil
		},
	})
}

// oobTools 带外/被动工具族。
func (s *Server) oobTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolDnslog(),
		s.toolVTSubdomains(),
		s.toolAIProtocolScan(),
	}
}
