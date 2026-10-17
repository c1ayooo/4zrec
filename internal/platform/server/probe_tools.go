// probe_tools.go 结构化 HTTP 请求与指纹扫描工具:http_probe(httpprobe 包直接搬——
// 完整报文捕获/30x 逐跳守卫/UA 指纹随机化/multipart,替代"发请求写 curl 脚本"),
// fingerprint_scan(平台指纹规则库探测+匹配,结果回写服务资产)。
// 两者都是主动探测:权限层人工确认 + 项目上下文 RoE 门控(同 webrecon 语义)。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/capability/recon/fingerprint"
	"github.com/c1ayooo/4zrec/internal/capability/web/httpprobe"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
	"github.com/c1ayooo/4zrec/internal/domain/traffic"
)

// toolHTTPProbe 结构化 HTTP 请求(单发+批量/矩阵差分;替代手写 curl 脚本)。
func (s *Server) toolHTTPProbe() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "http_probe",
		Description: "结构化 HTTP 请求(**HTTP/HTTPS 请求的首选工具**,替代手写 curl 脚本):完整请求/响应报文捕获、30x 默认不跟随" +
			"(跳转链带目标/跨域分析返回,不丢证据)、UA 指纹随机化防 WAF 画像、multipart 上传。" +
			"每次请求的完整报文会自动写入平台证据库(即使流量捕获关闭),输出中的 traffic_id 可直接用于 bind_finding_traffic 或报告引用;save_to_file 下载的大文件按完整正文落库,不受内存快照截断影响。" +
			"越权/遍历/A-B 差分用批量模式:requests 数组或 template+matrix/range 一次发多包(上限 50,别写脚本逐发)。" +
			"串行链用 extract 从响应提取变量(如登录 token/Set-Cookie),后续请求用 {变量名} 回填;cookie_jar 在批量内自动传递 Cookie。" +
			"大响应/二进制用 save_to_file 落盘(工作目录内相对路径)。" +
			"只有流式/原始报文/需要任意本地脚本处理等本工具明确覆盖不了的场景才退回 curl,并在 fact 里写明原因。" +
			"挂项目上下文时目标必须在授权范围内(逐请求校验,含变量回填后的 URL)。",
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
					"description": "批量模式①:完整请求数组,每项 {method,url,headers,body,label,upload_file,upload_field,form_fields,extract,save_to_file}(上限 50)。extract 提取的变量可在后续请求里用 {变量名} 回填。",
				},
				"template":     map[string]any{"type": "object", "description": "批量模式②:请求模板(同 requests 单项结构),字段里用 {var} 占位;extract 提取的变量同样可回填"},
				"matrix":       map[string]any{"type": "array", "description": "template 变量行数组(zip 语义):如 [{id:\"1\"},{id:\"2\"}];A/B 差分放两行(身份放 headers)"},
				"range":        map[string]any{"type": "object", "description": "template 数值边界 {var,from,to,step}(如遍历 id 1..20;总请求上限 50)"},
				"project_id":   map[string]any{"type": "integer", "description": "项目上下文(挂项目任务自动取)"},
				"cookie_jar":   map[string]any{"type": "boolean", "description": "批量内自动传递 Cookie(Set-Cookie → 后续请求);默认关。显式 Cookie 头优先"},
				"save_to_file": map[string]any{"type": "string", "description": "单发模式便捷字段:响应体完整写入工作目录内的相对路径(大文件/二进制)"},
				"extract":      extractSchema(),
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
		Run: func(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var in httpProbeInput
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			specs, errMsg := expandProbeSpecs(&in)
			if errMsg != "" {
				return actool.Errorf(errMsg), nil
			}
			batch := len(specs) > 1
			snapKB := in.SnapshotMax
			if snapKB <= 0 {
				snapKB = 64
			}
			if batch && snapKB > 8 {
				snapKB = 8 // 批量收紧,逐包摘要为主
			}
			workDir := ""
			if tc != nil {
				workDir = tc.WorkingDir
			}
			// 串行链状态:vars 由 extract 填充,后续请求 {var} 回填;jar 是批量内
			// 的 Cookie 罐(cookie_jar=true 且显式 Cookie 头缺席时注入)。
			vars := map[string]string{}
			jar := map[string]string{}
			var b strings.Builder
			if batch {
				fmt.Fprintf(&b, "批量请求 %d 包(30x 不跟随;逐包摘要):\n\n", len(specs))
			}
			for i, base := range specs {
				if ctx.Err() != nil {
					break
				}
				if i > 0 {
					select {
					case <-ctx.Done():
					case <-time.After(300 * time.Millisecond):
					}
				}
				sp := applyProbeVars(base, vars)
				// RoE 逐请求校验(变量回填后):extract 可能把后续目标换到范围外,
				// 不能只在展开阶段检查一次。
				if msg := s.webreconRoE(ctx, in.ProjectID, sp.URL); msg != "" {
					return actool.Errorf(strings.TrimSpace(b.String() + "\n" + msg)), nil
				}
				if in.CookieJar && len(jar) > 0 {
					if _, ok := headerLookup(sp.Headers, "Cookie"); !ok {
						sp.Headers["Cookie"] = cookieHeaderValue(jar)
					}
				}
				var sink *os.File
				var bodySink io.Writer // 避免 nil *os.File 装进非 nil interface
				bodyPath := ""
				if strings.TrimSpace(sp.SaveToFile) != "" {
					path, perr := resolveProbeSavePath(workDir, sp.SaveToFile)
					if perr != nil {
						fmt.Fprintf(&b, "【%s】落盘失败: %v\n", sp.Label, perr)
						continue
					}
					if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
						fmt.Fprintf(&b, "【%s】落盘失败: %v\n", sp.Label, mkErr)
						continue
					}
					f, oerr := os.Create(path)
					if oerr != nil {
						fmt.Fprintf(&b, "【%s】落盘失败: %v\n", sp.Label, oerr)
						continue
					}
					sink = f
					bodySink = f
					bodyPath = path
				}
				res, err := httpprobe.DoRequest(ctx, httpprobe.Request{
					Method: sp.Method, URL: sp.URL, Headers: sp.Headers, Body: sp.Body,
					Proxy: in.Proxy, TimeoutSeconds: in.TimeoutSeconds,
					RandomFingerprint: in.RandomFingerprint,
					UploadFile:        sp.UploadFile, UploadField: sp.UploadField, FormFields: sp.FormFields,
					BodySink: bodySink,
				})
				if sink != nil {
					if cerr := sink.Close(); err == nil && cerr != nil {
						err = cerr
					}
				}
				if err != nil {
					fmt.Fprintf(&b, "【%s】%s %s → 失败: %v\n", sp.Label, sp.Method, sp.URL, err)
					continue
				}
				trafficID := s.recordProbeEvidence(res, sp.Method, sp.URL, bodyPath)
				fmt.Fprintf(&b, "【%s】%s %s → %d %s(%dms,UA %s)\n", sp.Label, sp.Method, sp.URL,
					res.StatusCode, res.StatusText, res.DurationMS, res.UserAgent)
				if trafficID != "" {
					fmt.Fprintf(&b, "  ↳ 完整报文已存证 traffic_id=%s（可 bind_finding_traffic 绑定）\n", trafficID)
				}
				if len(res.Redirects) > 0 {
					for _, h := range res.Redirects {
						fmt.Fprintf(&b, "  ↳ #%d %s → %s [%d]%s\n", h.Index, h.FromURL, h.ToURL, h.Status, crossTag(h.CrossDomain))
					}
				}
				if in.CookieJar {
					mergeSetCookies(jar, res.RespHeaders)
				}
				if len(sp.Extract) > 0 {
					for _, note := range applyProbeExtracts(sp.Extract, res, vars) {
						fmt.Fprintf(&b, "  ↳ %s\n", note)
					}
				}
				if strings.TrimSpace(sp.SaveToFile) != "" {
					fmt.Fprintf(&b, "  ↳ 已保存 %s(%d 字节)\n", sp.SaveToFile, res.BodyBytes)
				}
				body := res.RespBody
				if len(body) > snapKB*1024 {
					body = body[:snapKB*1024] + fmt.Sprintf("\n…[截断,全量 %d 字节]", res.BodyBytes)
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

// recordProbeEvidence persists the complete request/response of one http_probe
// call. httpprobe already builds the transcript; before this hook the tool only
// returned a status line and body snippet, so findings ended up with no packet
// evidence. Recorded exchanges are searchable/bindable exactly like proxied
// traffic, even when passive capture is off.
func (s *Server) recordProbeEvidence(res *httpprobe.Result, method, requestedURL, fullBodyPath string) string {
	if s == nil || s.m == nil || res == nil {
		return ""
	}
	tr := s.m.Traffic()
	if tr == nil {
		return ""
	}
	reqHead, reqBody := splitHTTPHeadBody(res.RequestText)
	respHead, respBody := splitHTTPHeadBody(res.ResponseText)
	// save_to_file 已把完整正文流式落盘；用文件内容替换内存里的截断快照，
	// 让大 PDF/大文件也能整包存证（正文由 blob store 承载）。
	if fullBodyPath != "" {
		if b, err := os.ReadFile(fullBodyPath); err == nil {
			respBody = b
		} else {
			log.Printf("[http_probe] 读取落盘正文失败 %s: %v", fullBodyPath, err)
		}
	}
	contentType := ""
	if res.RespHeaders != nil {
		contentType = res.RespHeaders.Get("Content-Type")
	}
	u := strings.TrimSpace(res.FinalURL)
	if u == "" {
		u = requestedURL
	}
	id, err := tr.RecordEvidence(traffic.EvidenceRecord{
		URL: u, Method: method, Status: res.StatusCode, ContentType: contentType,
		ReqHead: reqHead, ReqBody: reqBody, RespHead: respHead, RespBody: respBody,
	})
	if err != nil {
		log.Printf("[http_probe] 完整报文存证失败 %s: %v", u, err)
		return ""
	}
	return id
}

// splitHTTPHeadBody splits a raw HTTP message at the first blank line. Heads are
// returned without the trailing CRLF; the export layer adds that back.
func splitHTTPHeadBody(raw string) (string, []byte) {
	if raw == "" {
		return "", nil
	}
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return strings.TrimRight(raw[:i], "\r\n"), []byte(raw[i+4:])
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return strings.TrimRight(raw[:i], "\r\n"), []byte(raw[i+2:])
	}
	return strings.TrimRight(raw, "\r\n"), nil
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
	// CookieJar 批量内自动传递 Cookie(Set-Cookie → 后续请求);显式 Cookie 头优先。
	CookieJar bool `json:"cookie_jar"`
	// SaveToFile / Extract 是单发模式的便捷字段(等价于写进该请求 spec)。
	SaveToFile string                      `json:"save_to_file"`
	Extract    map[string]httpProbeExtract `json:"extract"`
}

// httpProbeExtract 从响应提取一个变量,供后续请求用 {变量名} 回填(串行链)。
//   - from=body:在 RespBody 上跑 regex;
//   - from=header:在响应头(可用 name 限定单个头,典型 Set-Cookie)上跑 regex;
//   - from=status:直接取状态码(忽略 regex)。
//
// regex 有捕获组时默认取第 1 组(group 可改);无捕获组取整个匹配。
type httpProbeExtract struct {
	From  string `json:"from"`
	Name  string `json:"name"`
	Regex string `json:"regex"`
	Group int    `json:"group"`
}

// extractSchema 是 extract 字段的 JSON-Schema(变量名 → 提取规则)。
func extractSchema() map[string]any {
	rule := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"from":  map[string]any{"type": "string", "description": "body|header|status"},
			"name":  map[string]any{"type": "string", "description": "from=header 时的头名(如 Set-Cookie)"},
			"regex": map[string]any{"type": "string", "description": "提取正则;有捕获组取第 1 组"},
			"group": map[string]any{"type": "integer", "description": "捕获组序号(默认 1;填 0 取整个匹配)"},
		},
		"required": []string{"from"},
	}
	return map[string]any{
		"type":                 "object",
		"description":          "变量名 → 提取规则;提取到的变量可在后续请求 URL/headers/body 里用 {变量名} 回填",
		"additionalProperties": rule,
	}
}

// httpProbeSpec 单个请求规格(批量数组/模板通用)。
type httpProbeSpec struct {
	Label       string                      `json:"label"`
	Method      string                      `json:"method"`
	URL         string                      `json:"url"`
	Headers     map[string]string           `json:"headers"`
	Body        string                      `json:"body"`
	UploadFile  string                      `json:"upload_file"`
	UploadField string                      `json:"upload_field"`
	FormFields  map[string]string           `json:"form_fields"`
	Extract     map[string]httpProbeExtract `json:"extract"`
	SaveToFile  string                      `json:"save_to_file"`
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
		Extract: in.Extract, SaveToFile: in.SaveToFile,
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
	tmpl.SaveToFile = sub(tmpl.SaveToFile)
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

// applyProbeVars 把 extract 提取到的变量代入后续请求(URL/headers/body/label)。
// 只替换 {已知变量名};普通 JSON 花括号不会命中。
func applyProbeVars(sp httpProbeSpec, vars map[string]string) httpProbeSpec {
	if len(vars) == 0 {
		return sp
	}
	sub := func(s string) string {
		for k, v := range vars {
			s = strings.ReplaceAll(s, "{"+k+"}", v)
		}
		return s
	}
	sp.URL = sub(sp.URL)
	sp.Body = sub(sp.Body)
	sp.Label = sub(sp.Label)
	sp.SaveToFile = sub(sp.SaveToFile)
	if sp.Headers != nil {
		nh := make(map[string]string, len(sp.Headers))
		for k, v := range sp.Headers {
			nh[sub(k)] = sub(v)
		}
		sp.Headers = nh
	}
	return sp
}

// cookieHeaderValue 把批量 Cookie 罐渲染成 Cookie 头(名字排序保证稳定输出)。
func cookieHeaderValue(jar map[string]string) string {
	keys := make([]string, 0, len(jar))
	for k := range jar {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+jar[k])
	}
	return strings.Join(parts, "; ")
}

// mergeSetCookies 把响应里的 Set-Cookie 收进批量 Cookie 罐(忽略 Domain/Path/
// 过期,批量内通常同 host;显式 Cookie 头仍优先)。
func mergeSetCookies(jar map[string]string, h http.Header) {
	for _, line := range h.Values("Set-Cookie") {
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) != "" {
			jar[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
}

// applyProbeExtracts 按规则从响应提取变量写入 vars,返回可读的结果备注。
// from=body/header 用 regex(默认第 1 捕获组);from=status 直接取状态码。
func applyProbeExtracts(rules map[string]httpProbeExtract, res *httpprobe.Result, vars map[string]string) []string {
	names := make([]string, 0, len(rules))
	for name := range rules {
		names = append(names, name)
	}
	sort.Strings(names)
	notes := make([]string, 0, len(names))
	for _, name := range names {
		rule := rules[name]
		from := strings.ToLower(strings.TrimSpace(rule.From))
		if from == "status" {
			vars[name] = strconv.Itoa(res.StatusCode)
			notes = append(notes, fmt.Sprintf("提取 %s = %d", name, res.StatusCode))
			continue
		}
		var subject string
		switch from {
		case "body":
			subject = res.RespBody
		case "header":
			if rule.Name != "" {
				subject = strings.Join(res.RespHeaders.Values(rule.Name), "\n")
			} else {
				keys := make([]string, 0, len(res.RespHeaders))
				for k := range res.RespHeaders {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				var sb strings.Builder
				for _, k := range keys {
					for _, v := range res.RespHeaders[k] {
						fmt.Fprintf(&sb, "%s: %s\n", k, v)
					}
				}
				subject = sb.String()
			}
		default:
			notes = append(notes, fmt.Sprintf("提取 %s 失败: from 必须是 body/header/status", name))
			continue
		}
		if strings.TrimSpace(rule.Regex) == "" {
			notes = append(notes, fmt.Sprintf("提取 %s 失败: regex 不能为空", name))
			continue
		}
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			notes = append(notes, fmt.Sprintf("提取 %s 失败: 正则无效: %v", name, err))
			continue
		}
		m := re.FindStringSubmatch(subject)
		if len(m) == 0 {
			notes = append(notes, fmt.Sprintf("提取 %s 失败: 未匹配到内容", name))
			continue
		}
		group := rule.Group
		if group <= 0 && len(m) > 1 {
			group = 1 // 默认取第一个捕获组
		}
		if group >= len(m) {
			group = 0
		}
		val := m[group]
		vars[name] = val
		shown := val
		if len(shown) > 120 {
			shown = shown[:120] + "…"
		}
		notes = append(notes, fmt.Sprintf("提取 %s = %s", name, shown))
	}
	return notes
}

// resolveProbeSavePath 把 save_to_file 解析到 agent 工作目录内:拒绝绝对路径
// 与 ../ 越界(中间产物必须落在工作目录,和提示词里的输出规约一致)。
func resolveProbeSavePath(workDir, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("save_to_file 为空")
	}
	if filepath.IsAbs(raw) {
		return "", fmt.Errorf("save_to_file 必须是工作目录内的相对路径: %s", raw)
	}
	clean := filepath.Clean(raw)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("save_to_file 不能越出工作目录: %s", raw)
	}
	if strings.TrimSpace(workDir) == "" {
		workDir = "."
	}
	return filepath.Join(workDir, clean), nil
}
