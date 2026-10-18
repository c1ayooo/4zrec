// webrecon_tools.go Web 侦察增强工具:未授权访问探测(unauth_probe,字典+bypass
// 变体)与 JS 侦察(js_recon,接口清单+硬编码泄露+云 AK 嗅探)。核心逻辑自 4zreco
// 直接抽取(见 webrecon 包注释)。两者都是主动 HTTP 探测:权限层人工确认 + 挂项目
// 上下文时目标主机必须命中授权范围(RoE 同 port_scan 语义)。page_walk/browser_diff
// 依赖 go-rod 渲染服务,按规格未迁移(浏览器面走既有 Playwright MCP)。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capability/web/webrecon"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// webreconRoE 主动 Web 探测的 RoE:目标主机过项目授权(范围 ∪ approved 资产)。
// 返回拒绝说明(空=通过)。
func (s *Server) webreconRoE(ctx context.Context, explicitProject int64, targetURL string) string {
	u, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || u.Hostname() == "" {
		return "目标 URL 无效"
	}
	projectID := s.roeProjectID(ctx, explicitProject)
	if projectID <= 0 {
		return "" // 无项目上下文:人工确认为门(权限层)
	}
	host := u.Hostname()
	// 与资产围栏共用同一套授权判定:项目范围 ∪ 本项目 approved 资产。
	// 此前这里只查范围条目,目标自身解析出的 IP(approved 资产)会被拒,
	// 平台自带的 http_probe/port_scan 反而比 raw curl 更不宽容,agent 只能
	// 退回 Bash 手写脚本(2026-10-17 实测)。
	var domains, ips []string
	if net.ParseIP(host) != nil {
		ips = []string{host}
	} else {
		domains = []string{host}
	}
	if !s.m.pg.AuthorizedTarget(projectID, domains, ips) {
		return fmt.Sprintf("【RoE 拒绝】目标 %s 不在项目 %d 授权范围内", host, projectID)
	}
	return ""
}

// toolUnauthProbe 未授权访问探测。
func (s *Server) toolUnauthProbe() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "unauth_probe",
		Description: "未授权访问探测(主动 HTTP):对目标基 URL 扫标准敏感端点字典(actuator/debug pp druid/nacos/swagger/.git 等)," +
			"403/401 自动尝试惯用绕过变体(X-Original-URL/xff-127.0.0.1/路径归一化等,预算封顶);命中返回可读业务数据判据与片段。" +
			"挂项目上下文时目标必须在授权范围内。命中建议登记 finding。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":         map[string]any{"type": "string", "description": "目标基 URL(http://host:port)"},
				"extra_paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "追加路径"},
				"headers":     map[string]any{"type": "object", "description": "附加请求头(凭据态探测)"},
				"bypass":      map[string]any{"type": "boolean", "description": "403/401 绕过变体(默认 true)"},
				"project_id":  map[string]any{"type": "integer", "description": "项目上下文(挂项目任务自动取)"},
			},
			"required": []string{"url"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(input, &in)
			return actool.AskUser("未授权探测(主动 HTTP)目标: " + in.URL)
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				URL        string            `json:"url"`
				ExtraPaths []string          `json:"extra_paths"`
				Headers    map[string]string `json:"headers"`
				Bypass     *bool             `json:"bypass"`
				ProjectID  int64             `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if msg := s.webreconRoE(ctx, in.ProjectID, in.URL); msg != "" {
				return actool.Errorf(msg), nil
			}
			bypass := in.Bypass == nil || *in.Bypass
			paths := append([]string{}, webrecon.Dict()...)
			paths = append(paths, in.ExtraPaths...)
			hits, truncated := webrecon.UnauthSweep(ctx, in.URL, paths, in.Headers, bypass)
			var b strings.Builder
			fmt.Fprintf(&b, "未授权字典探测:命中 %d / 字典 %d 条", len(hits), len(paths))
			if truncated {
				b.WriteString("(bypass 预算耗尽,部分 403/401 未试完)")
			}
			b.WriteString("\n")
			for _, h := range hits {
				if h.Variant != "" {
					fmt.Fprintf(&b, "- %s [%d,经 %s 绕过] %s\n", h.Path, h.Status, h.Variant, h.Snippet)
				} else {
					fmt.Fprintf(&b, "- %s [%d] %s\n", h.Path, h.Status, h.Snippet)
				}
			}
			if len(hits) > 0 {
				b.WriteString("\n命中即未授权访问面,建议逐条登记 finding 并评估影响。")
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolJSRecon JS 侦察:接口清单 + 泄露提取。
func (s *Server) toolJSRecon() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "js_recon",
		Description: "JS 侦察(主动 HTTP,只读):抓目标页与同域 bundle(webpack 懒加载 chunk 递归,上限 40 个)," +
			"提取 API 接口清单(去噪后)、前端路由、硬编码泄露(JWT/数据库连接串/私钥/口令赋值/云 AK 形态)。" +
			"接口清单是后续越权/未授权测试的弹药;泄露凭据可用凭据验证工具族核实。挂项目上下文时目标必须在授权范围内。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":        map[string]any{"type": "string", "description": "目标页面 URL"},
				"headers":    map[string]any{"type": "object", "description": "附加请求头"},
				"project_id": map[string]any{"type": "integer"},
			},
			"required": []string{"url"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(input, &in)
			return actool.AskUser("JS 侦察(抓取页面与 bundle)目标: " + in.URL)
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				URL       string            `json:"url"`
				Headers   map[string]string `json:"headers"`
				ProjectID int64             `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if msg := s.webreconRoE(ctx, in.ProjectID, in.URL); msg != "" {
				return actool.Errorf(msg), nil
			}
			res := webrecon.JSReconFetch(in.URL, in.Headers)
			var b strings.Builder
			fmt.Fprintf(&b, "JS 侦察 %s:bundle %d 个,接口 %d 条,泄露 %d 条\n", in.URL, len(res.Bundles), len(res.Endpoints), len(res.Leaks))
			b.WriteString("接口清单:\n")
			for _, ep := range res.Endpoints {
				fmt.Fprintf(&b, "- /%s\n", strings.TrimPrefix(ep, "/"))
			}
			if len(res.EndpointGroups) > 0 {
				fmt.Fprintf(&b, "接口分组(top40): %s\n", strings.Join(res.EndpointGroups, " "))
			}
			if len(res.Routes) > 0 {
				fmt.Fprintf(&b, "前端路由: %s\n", strings.Join(res.Routes, " "))
			}
			if len(res.Leaks) > 0 {
				b.WriteString("硬编码泄露:\n")
				for _, l := range res.Leaks {
					fmt.Fprintf(&b, "- %s = %s\n", l.Key, l.Val)
				}
				b.WriteString("\n云 AK 形态可用 credential_verify_cloud 核实;连接串可用 credential_verify_db 实连验证。")
			}
			return actool.Text(b.String()), nil
		},
	})
}

// webreconTools Web 侦察工具族。
func (s *Server) webreconTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolUnauthProbe(),
		s.toolJSRecon(),
	}
}
