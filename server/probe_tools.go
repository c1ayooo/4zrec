// probe_tools.go 结构化 HTTP 请求与指纹扫描工具:http_probe(httpprobe 包直接搬——
// 完整报文捕获/30x 逐跳守卫/UA 指纹随机化/multipart,替代"发请求写 curl 脚本"),
// fingerprint_scan(平台指纹规则库探测+匹配,结果回写服务资产)。
// 两者都是主动探测:权限层人工确认 + 项目上下文 RoE 门控(同 webrecon 语义)。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/db"
	"github.com/c1ayooo/4zrec/fingerprint"
	"github.com/c1ayooo/4zrec/httpprobe"
	actool "github.com/c1ayooo/4zrec/tools"
)

// toolHTTPProbe 结构化 HTTP 请求(单发,默认不跟跳转)。
func (s *Server) toolHTTPProbe() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "http_probe",
		Description: "结构化 HTTP 请求(主动探测,替代手写 curl 脚本):完整请求/响应报文捕获、30x 默认不跟随" +
			"(跳转链带目标/跨域分析返回,不丢证据)、UA 指纹随机化防 WAF 画像、multipart 上传。" +
			"对比验证(同 group 换 id/去凭据/改 Host)用多次调用自行对比。挂项目上下文时目标必须在授权范围内。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":             map[string]any{"type": "string", "description": "完整 URL(http://host:port/path)"},
				"method":          map[string]any{"type": "string", "description": "HTTP 方法(默认 GET)"},
				"headers":         map[string]any{"type": "object", "description": "请求头(显式 UA 覆盖随机化)"},
				"body":            map[string]any{"type": "string", "description": "请求体"},
				"proxy":           map[string]any{"type": "string", "description": "出站代理(http/socks5;空=直连)"},
				"timeout_seconds": map[string]any{"type": "integer", "description": "整体超时秒(默认 20)"},
				"snapshot_max":    map[string]any{"type": "integer", "description": "响应体快照上限 KB(默认 64)"},
				"project_id":      map[string]any{"type": "integer", "description": "项目上下文(挂项目任务自动取)"},
			},
			"required": []string{"url"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				URL    string `json:"url"`
				Method string `json:"method"`
			}
			_ = json.Unmarshal(input, &in)
			method := strings.ToUpper(strings.TrimSpace(in.Method))
			if method == "" {
				method = "GET"
			}
			return actool.AskUser("HTTP 请求(" + method + ")目标: " + in.URL)
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				URL            string            `json:"url"`
				Method         string            `json:"method"`
				Headers        map[string]string `json:"headers"`
				Body           string            `json:"body"`
				Proxy          string            `json:"proxy"`
				TimeoutSeconds int               `json:"timeout_seconds"`
				SnapshotMax    int               `json:"snapshot_max"`
				ProjectID      int64             `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if msg := s.webreconRoE(ctx, in.ProjectID, in.URL); msg != "" {
				return actool.Errorf(msg), nil
			}
			res, err := httpprobe.DoRequest(ctx, httpprobe.Request{
				Method: in.Method, URL: in.URL, Headers: in.Headers, Body: in.Body,
				Proxy: in.Proxy, TimeoutSeconds: in.TimeoutSeconds,
			})
			if err != nil {
				return actool.Errorf("请求失败: " + err.Error()), nil
			}
			// 响应体快照截断(MaxOutputChars 之上再收一层,报文头部 transcript 保全)。
			snap := in.SnapshotMax
			if snap <= 0 {
				snap = 64
			}
			body := res.RespBody
			if len(body) > snap*1024 {
				body = body[:snap*1024] + fmt.Sprintf("\n…[截断,全量 %d 字节]", len(res.RespBody))
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s → %d %s(%dms,UA %s)\n", in.URL,
				res.StatusCode, res.StatusText, res.DurationMS, res.UserAgent)
			if len(res.Redirects) > 0 {
				b.WriteString("跳转链(未跟随):\n")
				for _, h := range res.Redirects {
					fmt.Fprintf(&b, "- #%d %s → %s [%d]%s\n", h.Index, h.FromURL, h.ToURL, h.Status, crossTag(h.CrossDomain))
				}
			}
			if res.FinalURL != "" && res.FinalURL != in.URL {
				fmt.Fprintf(&b, "最终 URL: %s\n", res.FinalURL)
			}
			b.WriteString("\n" + strings.TrimSpace(body))
			return actool.Text(b.String()), nil
		},
	})
}

// toolFingerprintScan 指纹扫描:探测 + 规则匹配 + 服务资产回写。
func (s *Server) toolFingerprintScan() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "fingerprint_scan",
		Description: "Web 指纹扫描(主动探测):对目标 URL 探测并用平台指纹规则库匹配(webanalyze/wappalyzergo/dddd " +
			"三源规则,24h 自动同步),返回组件/版本结论并回写服务资产(technologies,联动 1day 漏洞库线索)。" +
			"挂项目上下文时目标必须在授权范围内。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"targets":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "目标 URL 列表"},
				"project_id": map[string]any{"type": "integer"},
			},
			"required": []string{"targets"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				Targets []string `json:"targets"`
			}
			_ = json.Unmarshal(input, &in)
			return actool.AskUser("指纹扫描(主动探测)目标: " + strings.Join(in.Targets, ", "))
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Targets   []string `json:"targets"`
				ProjectID int64    `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if len(in.Targets) == 0 {
				return actool.Errorf("targets 必填"), nil
			}
			if len(in.Targets) > 50 {
				in.Targets = in.Targets[:50]
			}
			// RoE:逐目标过项目范围。
			for _, tgt := range in.Targets {
				if msg := s.webreconRoE(ctx, in.ProjectID, tgt); msg != "" {
					return actool.Errorf(msg), nil
				}
			}
			client := &http.Client{Timeout: 15 * time.Second}
			var (
				b                strings.Builder
				scanned, matched int
			)
			as := s.m.Assets()
			for _, tgt := range in.Targets {
				if ctx.Err() != nil {
					break
				}
				obs, err := fingerprint.ProbeHTTPObservation(ctx, strings.TrimSpace(tgt), client)
				if err != nil {
					fmt.Fprintf(&b, "- %s: 探测失败(%v)\n", tgt, err)
					continue
				}
				scanned++
				techs := s.fingerprintMatch(obs)
				matched += len(techs)
				if len(techs) > 0 {
					fmt.Fprintf(&b, "- %s [%d] 组件: %s\n", tgt, obs.Status, strings.Join(techs, ", "))
				} else {
					fmt.Fprintf(&b, "- %s [%d] %s(无规则命中)\n", tgt, obs.Status, obs.Title)
				}
				// 回写 http 服务资产(存在则合并 technologies)。
				if id, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{
					URL: strings.TrimSpace(tgt), StatusCode: &obs.Status, PageTitle: obs.Title,
					FaviconMMH3: obs.IconHash, Technologies: techs,
				}); err == nil {
					projectID := s.roeProjectID(ctx, in.ProjectID)
					if projectID > 0 {
						_, _ = as.StampDiscoveredAsset(id, projectID)
					}
				}
			}
			if scanned == 0 {
				return actool.Text("全部目标探测失败"), nil
			}
			fmt.Fprintf(&b, "\n扫描 %d 目标,规则命中 %d 条;组件结论已回写服务资产,可 search_vuln_kb 查已知漏洞。", scanned, matched)
			return actool.Text(b.String()), nil
		},
	})
}

// fingerprintMatch 规则匹配薄封装(规则库按需加载)。
func (s *Server) fingerprintMatch(obs fingerprint.Observation) []string {
	var out []string
	if fp, err := fingerprint.NewStore(s.m.pg.DB); err == nil {
		if rules, err := fp.EnabledRules(context.Background()); err == nil {
			for _, m := range fingerprint.MatchObservation(rules, obs) {
				if m.Product != "" {
					out = append(out, m.Product)
				}
			}
		}
	}
	return out
}

// probeTools 探测工具族。
func (s *Server) probeTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolHTTPProbe(),
		s.toolFingerprintScan(),
	}
}

func crossTag(cross bool) string {
	if cross {
		return " [跨域]"
	}
	return ""
}
