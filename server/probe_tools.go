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
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/db"
	"github.com/c1ayooo/4zrec/fingerprint"
	"github.com/c1ayooo/4zrec/httpprobe"
	actool "github.com/c1ayooo/4zrec/tools"
)

// toolHTTPProbe 结构化 HTTP 请求(单发+批量/矩阵差分;替代手写 curl 脚本)。
func (s *Server) toolHTTPProbe() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "http_probe",
		Description: "结构化 HTTP 请求(主动探测,替代手写 curl 脚本):完整请求/响应报文捕获、30x 默认不跟随" +
			"(跳转链带目标/跨域分析返回,不丢证据)、UA 指纹随机化防 WAF 画像、multipart 上传。" +
			"越权/遍历/A-B 差分用批量模式:requests 数组或 template+matrix/range 一次发多包(上限 50,别写脚本逐发)。" +
			"挂项目上下文时目标必须在授权范围内。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":                map[string]any{"type": "string", "description": "完整 URL(http://host:port/path)"},
				"method":             map[string]any{"type": "string", "description": "HTTP 方法(默认 GET)"},
				"headers":            map[string]any{"type": "object", "description": "请求头键值对(任意数量;Authorization/Cookie 等)"},
				"cookie":             map[string]any{"type": "string", "description": "Cookie 头便捷字段(headers 里的同名键优先)"},
				"user_agent":         map[string]any{"type": "string", "description": "User-Agent 便捷字段(显式设定即关闭随机化)"},
				"content_type":       map[string]any{"type": "string", "description": "Content-Type 便捷字段"},
				"body":               map[string]any{"type": "string", "description": "请求体"},
				"proxy":              map[string]any{"type": "string", "description": "出站代理(http/socks5;空=直连)"},
				"random_fingerprint": map[string]any{"type": "string", "description": "指纹随机化:默认开(UA 池随机+补 Accept 系头);传 off 关闭"},
				"upload_file":        map[string]any{"type": "string", "description": "multipart 文件上传(curl -F 等价):本地文件路径"},
				"upload_field":       map[string]any{"type": "string", "description": "multipart 文件字段名(默认 file)"},
				"form_fields":        map[string]any{"type": "object", "description": "multipart 附加表单字段"},
				"timeout_seconds":    map[string]any{"type": "integer", "description": "整体超时秒(默认 20)"},
				"snapshot_max":       map[string]any{"type": "integer", "description": "响应体快照上限 KB(默认 64;批量模式自动收紧)"},
				"requests": map[string]any{
					"type":        "array",
					"description": "批量模式①:完整请求数组,每项 {method,url,headers,body,label,upload_file,upload_field,form_fields}(上限 50)。",
				},
				"template":   map[string]any{"type": "object", "description": "批量模式②:请求模板(同 requests 单项结构),字段里用 {var} 占位"},
				"matrix":     map[string]any{"type": "array", "description": "template 变量行数组(zip 语义):如 [{id:\"1\"},{id:\"2\"}];A/B 差分放两行(身份放 headers)"},
				"range":      map[string]any{"type": "object", "description": "template 数值边界 {var,from,to,step}(如遍历 id 1..20;总请求上限 50)"},
				"project_id": map[string]any{"type": "integer", "description": "项目上下文(挂项目任务自动取)"},
			},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				URL      string `json:"url"`
				Method   string `json:"method"`
				Requests []struct {
					URL string `json:"url"`
				} `json:"requests"`
			}
			_ = json.Unmarshal(input, &in)
			target := in.URL
			if len(in.Requests) > 0 {
				target = fmt.Sprintf("%d 个请求(首个 %s)", len(in.Requests), in.Requests[0].URL)
			}
			method := strings.ToUpper(strings.TrimSpace(in.Method))
			if method == "" {
				method = "GET"
			}
			return actool.AskUser("HTTP 请求(" + method + ")目标: " + target)
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in httpProbeInput
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			specs, errMsg := expandProbeSpecs(&in)
			if errMsg != "" {
				return actool.Errorf(errMsg), nil
			}
			// RoE:逐个目标过项目范围。
			for _, sp := range specs {
				if msg := s.webreconRoE(ctx, in.ProjectID, sp.URL); msg != "" {
					return actool.Errorf(msg), nil
				}
			}
			batch := len(specs) > 1
			snapKB := in.SnapshotMax
			if snapKB <= 0 {
				snapKB = 64
			}
			if batch && snapKB > 8 {
				snapKB = 8 // 批量收紧,逐包摘要为主
			}
			var b strings.Builder
			if batch {
				fmt.Fprintf(&b, "批量请求 %d 包(30x 不跟随;逐包摘要):\n\n", len(specs))
			}
			for i, sp := range specs {
				if ctx.Err() != nil {
					break
				}
				if i > 0 {
					select {
					case <-ctx.Done():
					case <-time.After(300 * time.Millisecond):
					}
				}
				res, err := httpprobe.DoRequest(ctx, httpprobe.Request{
					Method: sp.Method, URL: sp.URL, Headers: sp.Headers, Body: sp.Body,
					Proxy: in.Proxy, TimeoutSeconds: in.TimeoutSeconds,
					RandomFingerprint: in.RandomFingerprint,
					UploadFile:        sp.UploadFile, UploadField: sp.UploadField, FormFields: sp.FormFields,
				})
				if err != nil {
					fmt.Fprintf(&b, "【%s】%s %s → 失败: %v\n", sp.Label, sp.Method, sp.URL, err)
					continue
				}
				fmt.Fprintf(&b, "【%s】%s %s → %d %s(%dms,UA %s)\n", sp.Label, sp.Method, sp.URL,
					res.StatusCode, res.StatusText, res.DurationMS, res.UserAgent)
				if len(res.Redirects) > 0 {
					for _, h := range res.Redirects {
						fmt.Fprintf(&b, "  ↳ #%d %s → %s [%d]%s\n", h.Index, h.FromURL, h.ToURL, h.Status, crossTag(h.CrossDomain))
					}
				}
				body := res.RespBody
				if len(body) > snapKB*1024 {
					body = body[:snapKB*1024] + fmt.Sprintf("\n…[截断,全量 %d 字节]", len(res.RespBody))
				}
				if batch {
					b.WriteString("  " + strings.TrimSpace(strings.SplitN(body, "\n", 2)[0]))
					if idx := strings.IndexByte(body, '\n'); idx >= 0 {
						b.WriteString(" …")
					}
					b.WriteString("\n\n")
				} else {
					b.WriteString("\n" + strings.TrimSpace(body))
				}
			}
			if batch {
				b.WriteString("对比建议:同控变量前后逐包核对状态码/长度/关键字段差异;差异点即证据片段。")
			}
			return actool.Text(b.String()), nil
		},
	})
}

// httpProbeInput http_probe 入参(单发与批量共用)。
type httpProbeInput struct {
	URL               string              `json:"url"`
	Method            string              `json:"method"`
	Headers           map[string]string   `json:"headers"`
	Cookie            string              `json:"cookie"`
	UserAgent         string              `json:"user_agent"`
	ContentType       string              `json:"content_type"`
	Body              string              `json:"body"`
	Proxy             string              `json:"proxy"`
	RandomFingerprint string              `json:"random_fingerprint"`
	UploadFile        string              `json:"upload_file"`
	UploadField       string              `json:"upload_field"`
	FormFields        map[string]string   `json:"form_fields"`
	TimeoutSeconds    int                 `json:"timeout_seconds"`
	SnapshotMax       int                 `json:"snapshot_max"`
	Requests          []httpProbeSpec     `json:"requests"`
	Template          *httpProbeSpec      `json:"template"`
	Matrix            []map[string]string `json:"matrix"`
	Range             *struct {
		Var  string `json:"var"`
		From int    `json:"from"`
		To   int    `json:"to"`
		Step int    `json:"step"`
	} `json:"range"`
	ProjectID int64 `json:"project_id"`
}

// httpProbeSpec 单个请求规格(批量数组/模板通用)。
type httpProbeSpec struct {
	Label       string            `json:"label"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	UploadFile  string            `json:"upload_file"`
	UploadField string            `json:"upload_field"`
	FormFields  map[string]string `json:"form_fields"`
}

// expandProbeSpecs 归一请求清单:requests 直用;template+matrix/range 展开
// (zip 语义);单发回退。上限 50(防轰炸,超限报错)。便捷头字段合并。
func expandProbeSpecs(in *httpProbeInput) ([]httpProbeSpec, string) {
	norm := func(sp httpProbeSpec) httpProbeSpec {
		if sp.Method == "" {
			sp.Method = in.Method
		}
		if sp.Method == "" {
			sp.Method = "GET"
		}
		sp.Method = strings.ToUpper(sp.Method)
		if sp.Headers == nil {
			sp.Headers = map[string]string{}
		}
		// 便捷头:仅当 headers 未显式给出同名键时注入(显式优先)。
		if in.Cookie != "" {
			if _, ok := headerLookup(sp.Headers, "Cookie"); !ok {
				sp.Headers["Cookie"] = in.Cookie
			}
		}
		if in.UserAgent != "" {
			if _, ok := headerLookup(sp.Headers, "User-Agent"); !ok {
				sp.Headers["User-Agent"] = in.UserAgent
			}
		}
		if in.ContentType != "" {
			if _, ok := headerLookup(sp.Headers, "Content-Type"); !ok {
				sp.Headers["Content-Type"] = in.ContentType
			}
		}
		if sp.Label == "" {
			sp.Label = sp.URL
		}
		return sp
	}
	if len(in.Requests) > 0 {
		if len(in.Requests) > 50 {
			return nil, fmt.Sprintf("requests 上限 50,当前 %d", len(in.Requests))
		}
		out := make([]httpProbeSpec, 0, len(in.Requests))
		for _, sp := range in.Requests {
			if strings.TrimSpace(sp.URL) == "" {
				return nil, "requests 每项必须带 url"
			}
			out = append(out, norm(sp))
		}
		return out, ""
	}
	if in.Template != nil {
		tmpl := *in.Template
		if strings.TrimSpace(tmpl.URL) == "" {
			return nil, "template 必须带 url"
		}
		var rows []map[string]string
		if in.Range != nil && in.Range.Var != "" {
			from, to, step := in.Range.From, in.Range.To, in.Range.Step
			if step <= 0 {
				step = 1
			}
			for v := from; v <= to && len(rows) < 50; v += step {
				rows = append(rows, map[string]string{in.Range.Var: strconv.Itoa(v)})
			}
		} else {
			rows = in.Matrix
		}
		if len(rows) == 0 {
			return nil, "template 需要 matrix 或 range 提供变量"
		}
		if len(rows) > 50 {
			rows = rows[:50]
		}
		out := make([]httpProbeSpec, 0, len(rows))
		for i, row := range rows {
			sp := substituteSpec(tmpl, row)
			if sp.Label == tmpl.Label || sp.Label == "" {
				sp.Label = fmt.Sprintf("%s#%d", orDefaultLabel(tmpl.Label, "req"), i+1)
			}
			out = append(out, norm(sp))
		}
		return out, ""
	}
	if strings.TrimSpace(in.URL) == "" {
		return nil, "url 必填(或 requests/template)"
	}
	return []httpProbeSpec{norm(httpProbeSpec{
		Method: in.Method, URL: in.URL, Headers: in.Headers, Body: in.Body,
		UploadFile: in.UploadFile, UploadField: in.UploadField, FormFields: in.FormFields,
	})}, ""
}

// substituteSpec 模板 {var} 代入(URL/headers/body 全覆盖)。
func substituteSpec(tmpl httpProbeSpec, row map[string]string) httpProbeSpec {
	sub := func(s string) string {
		for k, v := range row {
			s = strings.ReplaceAll(s, "{"+k+"}", v)
		}
		return s
	}
	tmpl.URL = sub(tmpl.URL)
	tmpl.Body = sub(tmpl.Body)
	tmpl.Label = sub(tmpl.Label)
	if tmpl.Headers != nil {
		nh := make(map[string]string, len(tmpl.Headers))
		for k, v := range tmpl.Headers {
			nh[sub(k)] = sub(v)
		}
		tmpl.Headers = nh
	}
	return tmpl
}

func headerLookup(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func orDefaultLabel(label, fallback string) string {
	if strings.TrimSpace(label) == "" {
		return fallback
	}
	return label
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
