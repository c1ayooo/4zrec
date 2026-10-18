// nuclei_tools.go 把项目内 nuclei 外部二进制接成 agent 工具：
//   - nuclei_scan            选模板/标签跑扫描，JSONL 结构化返回并落盘
//   - nuclei_template_search 在项目内模板目录检索模板
//   - nuclei_update          手动更新二进制/模板
//   - nuclei_status          查看安装、版本、模板数量和上次更新时间
//
// 二进制和模板都在 <dataDir>/nuclei/ 下，不是系统 PATH；首次扫描会按设置
// 自动下载固定版本并更新模板。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/nuclei"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// getNucleiStatus 是系统设置页用的只读状态接口。
func (s *Server) getNucleiStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.nucleiManager().Status(r.Context()))
}

func (s *Server) nucleiManager() *nuclei.Manager {
	if s.nucleiMgr == nil {
		var settings nuclei.Settings
		if s.m != nil && s.m.pg != nil {
			settings = s.m.pg
		}
		s.nucleiMgr = nuclei.New(filepath.Join(s.dataDir, "nuclei"), settings)
	}
	return s.nucleiMgr
}

func (s *Server) nucleiTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolNucleiScan(),
		s.toolNucleiTemplateSearch(),
		s.toolNucleiUpdate(),
		s.toolNucleiStatus(),
	}
}

func (s *Server) toolNucleiScan() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "nuclei_scan",
		Description: "用项目内 nuclei 跑模板扫描（外部二进制，不依赖系统 PATH）。" +
			"二进制与模板位于数据目录的 nuclei/ 下；首次使用会自动下载固定版本并更新模板，之后按间隔自动更新。" +
			"必须指定 templates / tags / severity / type / automatic 至少一个选择器，避免全量扫描。" +
			"未指定 templates 时，tags/severity/type 会同时作用于官方模板和自定义模板目录。" +
			"输出按 JSONL 解析为结构化命中（模板、等级、matched-at、matcher、extracted、curl 命令），" +
			"完整 JSONL 落盘并返回路径。默认关闭 interactsh（避免目标流量进公共 OAST）；需要带外验证时显式开启。" +
			"挂项目上下文时 targets 必须全部命中项目授权范围（逐目标 RoE 校验）。" +
			"注意：nuclei 命中是扫描器结论，不等于已验证漏洞；请按证据门槛复核后再 report_finding。",
		Schema: objSchema(map[string]any{
			"targets": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "目标 URL / host:port / IP（http(s) 优先；单次最多 500 个）",
			},
			"templates": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "模板 ID 或模板目录内的相对路径（先用 nuclei_template_search 检索）",
			},
			"tags": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "按模板标签筛选（如 cve,rce,exposure）",
			},
			"severity": map[string]any{
				"type": "array", "items": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info", "unknown"}},
				"description": "按严重等级筛选",
			},
			"exclude_tags": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "排除的模板标签",
			},
			"type": map[string]any{
				"type":        "string",
				"enum":        []string{"http", "dns", "tcp", "file", "headless", "code", "javascript", "ssl", "websocket", "whois", "workflow"},
				"description": "只跑某一协议类型的模板",
			},
			"automatic": map[string]any{
				"type":        "boolean",
				"description": "nuclei -as 自动扫描（仍建议同时给 tags/severity 收敛范围）",
			},
			"headers": map[string]any{
				"type":        "object",
				"description": "附加请求头（Cookie/Authorization 等）",
			},
			"proxy":           map[string]any{"type": "string", "description": "出站代理（http/socks5；空=直连）"},
			"rate_limit":      map[string]any{"type": "integer", "description": "全局请求速率（默认 50 req/s）"},
			"bulk_size":       map[string]any{"type": "integer", "description": "模板并发主机数（默认 25）"},
			"concurrency":     map[string]any{"type": "integer", "description": "模板并发数（默认 25）"},
			"request_timeout": map[string]any{"type": "integer", "description": "单请求超时秒（默认 10）"},
			"retries":         map[string]any{"type": "integer", "description": "单请求重试次数（默认 1）"},
			"interactsh":      map[string]any{"type": "boolean", "description": "启用 interactsh 带外验证（默认关，避免目标流量进公共 OAST）"},
			"timeout_seconds": map[string]any{"type": "integer", "description": "整次扫描超时秒（默认 600，最大 1800）"},
			"project_id":      map[string]any{"type": "integer", "description": "项目上下文（挂项目任务自动取）"},
		}, "targets"),
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				Targets []string `json:"targets"`
				Tags    []string `json:"tags"`
			}
			_ = json.Unmarshal(input, &in)
			return actool.AskUser(fmt.Sprintf("nuclei 模板扫描：%d 个目标，标签 %s",
				len(in.Targets), strings.Join(in.Tags, ",")))
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Targets        []string          `json:"targets"`
				Templates      []string          `json:"templates"`
				Tags           []string          `json:"tags"`
				Severity       []string          `json:"severity"`
				ExcludeTags    []string          `json:"exclude_tags"`
				Type           string            `json:"type"`
				Automatic      bool              `json:"automatic"`
				Headers        map[string]string `json:"headers"`
				Proxy          string            `json:"proxy"`
				RateLimit      int               `json:"rate_limit"`
				BulkSize       int               `json:"bulk_size"`
				Concurrency    int               `json:"concurrency"`
				RequestTimeout int               `json:"request_timeout"`
				Retries        int               `json:"retries"`
				Interactsh     bool              `json:"interactsh"`
				TimeoutSeconds int               `json:"timeout_seconds"`
				ProjectID      int64             `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if len(in.Targets) == 0 {
				return actool.Errorf("targets 不能为空"), nil
			}
			// RoE 先全部校验完再启动扫描，避免打到一半才发现越界。
			for _, target := range in.Targets {
				u, err := nucleiTargetURL(target)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if msg := s.webreconRoE(ctx, in.ProjectID, u); msg != "" {
					return actool.Errorf(strings.TrimSpace(msg)), nil
				}
			}

			mgr := s.nucleiManager()
			ensure, err := mgr.Ensure(ctx, mgr.AutoUpdate())
			if err != nil {
				return actool.Errorf("nuclei 未就绪: " + err.Error()), nil
			}
			maxDur := time.Duration(in.TimeoutSeconds) * time.Second
			if in.TimeoutSeconds <= 0 {
				maxDur = 0
			} else if maxDur > 30*time.Minute {
				maxDur = 30 * time.Minute
			}
			res, err := mgr.Run(ctx, nuclei.RunOptions{
				Targets:        in.Targets,
				Templates:      in.Templates,
				Tags:           in.Tags,
				Severity:       in.Severity,
				ExcludeTags:    in.ExcludeTags,
				TemplateType:   in.Type,
				Automatic:      in.Automatic,
				Headers:        in.Headers,
				Proxy:          in.Proxy,
				RateLimit:      in.RateLimit,
				BulkSize:       in.BulkSize,
				Concurrency:    in.Concurrency,
				RequestTimeout: in.RequestTimeout,
				Retries:        in.Retries,
				Interactsh:     in.Interactsh,
				MaxDuration:    maxDur,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(formatNucleiRun(res, ensure)), nil
		},
	})
}

func formatNucleiRun(res *nuclei.RunResult, ensure *nuclei.EnsureResult) string {
	var b strings.Builder
	tmplDesc := fmt.Sprintf("%d 模板", res.Templates)
	if res.Templates == 0 {
		tmplDesc = "按 tags/severity/type 选择"
	}
	fmt.Fprintf(&b, "nuclei 扫描完成：%d 命中 / %d 目标 / %s，耗时 %s\n",
		res.Total, res.Targets, tmplDesc, res.Duration.Round(time.Millisecond))
	if ensure != nil {
		if ensure.BinaryVersion != "" {
			fmt.Fprintf(&b, "二进制: %s（%s）\n", ensure.BinaryPath, ensure.BinaryVersion)
		}
		fmt.Fprintf(&b, "模板目录: %s\n", ensure.TemplatesDir)
		for _, w := range ensure.Warnings {
			fmt.Fprintf(&b, "提示: %s\n", w)
		}
	}
	if len(res.Warnings) > 0 {
		for _, w := range res.Warnings {
			fmt.Fprintf(&b, "提示: %s\n", w)
		}
	}
	if res.Total == 0 {
		b.WriteString("\n0 命中。这不代表目标没有漏洞：检查模板选择、目标可达性与网络/代理设置。\n")
	} else {
		b.WriteString("\n")
		results := append([]nuclei.Result(nil), res.Results...)
		nuclei.SortResults(results)
		limit := len(results)
		if limit > 40 {
			limit = 40
		}
		for i := 0; i < limit; i++ {
			r := results[i]
			fmt.Fprintf(&b, "[%s] %s | %s\n", r.Severity, r.TemplateID, r.Name)
			if r.MatchedAt != "" {
				fmt.Fprintf(&b, "  命中: %s\n", r.MatchedAt)
			}
			if r.MatcherName != "" {
				fmt.Fprintf(&b, "  matcher: %s\n", r.MatcherName)
			}
			if len(r.Extracted) > 0 {
				fmt.Fprintf(&b, "  提取: %s\n", strings.Join(r.Extracted, " | "))
			}
			if r.CurlCommand != "" {
				fmt.Fprintf(&b, "  curl: %s\n", r.CurlCommand)
			}
		}
		if len(results) > limit {
			fmt.Fprintf(&b, "\n仅展示前 %d 条；完整结构化结果见文件。\n", limit)
		}
	}
	fmt.Fprintf(&b, "\n结果文件: %s\n", res.ResultFile)
	b.WriteString("\n注意：nuclei 命中是扫描器结论，不等于已验证漏洞；请按证据门槛复核后再 report_finding。\n")
	return b.String()
}

func (s *Server) toolNucleiTemplateSearch() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "nuclei_template_search",
		Description: "检索项目内 nuclei 模板（官方 + 自定义）。" +
			"按关键词（模板 ID/名称/标签/CVE/描述）、severity、tags、协议类型、来源过滤，" +
			"返回模板 ID、名称、等级、标签、CVE、类型、来源和相对路径。扫描前先用它选模板，避免无选择器全量扫描。",
		Schema: objSchema(map[string]any{
			"q":        map[string]any{"type": "string", "description": "关键词（可空格分隔多个词，全部命中）"},
			"severity": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "按等级过滤"},
			"tags":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "按标签过滤（任一命中）"},
			"type":     map[string]any{"type": "string", "description": "协议类型（http/dns/tcp/...）"},
			"source":   map[string]any{"type": "string", "enum": []string{"official", "custom"}, "description": "来源：official=官方只读，custom=自定义"},
			"limit":    map[string]any{"type": "integer", "description": "返回上限（默认 20，最大 200）"},
		}),
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision {
			return actool.Allowed()
		},
		Run: func(_ context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Q        string   `json:"q"`
				Severity []string `json:"severity"`
				Tags     []string `json:"tags"`
				Type     string   `json:"type"`
				Source   string   `json:"source"`
				Limit    int      `json:"limit"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			items, total, err := s.nucleiManager().Index().Search(in.Q, nuclei.Filters{
				Severity: in.Severity, Tags: in.Tags, Type: in.Type, Source: in.Source,
			}, in.Limit)
			if err != nil {
				return actool.Errorf("模板检索失败（模板未安装或索引失败；可调用 nuclei_scan 触发自动安装，或让有 nuclei_update 绑定的 agent 更新）: " + err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "命中 %d 条，展示 %d 条：\n", total, len(items))
			for _, t := range items {
				fmt.Fprintf(&b, "\n- %s | %s [%s/%s/%s]\n", t.ID, t.Name, t.Severity, t.Type, t.Source)
				if len(t.Tags) > 0 {
					fmt.Fprintf(&b, "  标签: %s\n", strings.Join(t.Tags, ","))
				}
				if len(t.CVE) > 0 {
					fmt.Fprintf(&b, "  CVE: %s\n", strings.Join(t.CVE, ","))
				}
				fmt.Fprintf(&b, "  路径: %s\n", t.Path)
			}
			if len(items) == 0 {
				b.WriteString("\n（无命中：换关键词/标签，或先运行 nuclei_update 更新模板）\n")
			}
			return actool.Text(b.String()), nil
		},
	})
}

func (s *Server) toolNucleiUpdate() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "nuclei_update",
		Description: "更新项目内 nuclei 二进制和/或模板（官方 GitHub release）。" +
			"二进制与模板都在 <dataDir>/nuclei/ 下，不会写系统目录或用户 HOME。" +
			"扫描前也会按 nuclei.auto_update 设置自动更新，本工具用于立即强制更新或排障。",
		Schema: objSchema(map[string]any{
			"binary_only":    map[string]any{"type": "boolean", "description": "只更新二进制"},
			"templates_only": map[string]any{"type": "boolean", "description": "只更新模板"},
			"force":          map[string]any{"type": "boolean", "description": "保留参数；更新命令本身幂等"},
		}),
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision {
			return actool.AskUser("更新项目内 nuclei 二进制与模板（会访问 GitHub release）")
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				BinaryOnly    bool `json:"binary_only"`
				TemplatesOnly bool `json:"templates_only"`
				Force         bool `json:"force"`
			}
			_ = json.Unmarshal(input, &in)
			res, err := s.nucleiManager().Update(ctx, in.Force, in.BinaryOnly, in.TemplatesOnly)
			if err != nil {
				return actool.Errorf("nuclei 更新失败: " + err.Error()), nil
			}
			var b strings.Builder
			b.WriteString("nuclei 更新完成\n")
			fmt.Fprintf(&b, "二进制: %s\n", res.BinaryPath)
			if res.BinaryVersion != "" {
				fmt.Fprintf(&b, "版本: %s\n", res.BinaryVersion)
			}
			fmt.Fprintf(&b, "模板目录: %s（%d 个模板）\n", res.TemplatesDir, res.TemplateCount)
			fmt.Fprintf(&b, "自定义模板: %s（%d 个模板）\n", s.nucleiManager().CustomTemplatesDir(), res.CustomTemplateCount)
			fmt.Fprintf(&b, "更新时间: %s\n", res.LastUpdate.Format(time.RFC3339))
			for _, w := range res.Warnings {
				fmt.Fprintf(&b, "提示: %s\n", w)
			}
			return actool.Text(b.String()), nil
		},
	})
}

func (s *Server) toolNucleiStatus() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "nuclei_status",
		Description: "查看项目内 nuclei 的安装状态：二进制路径/版本、模板目录/数量、上次更新时间、" +
			"自动更新开关与更新间隔、interactsh 开关。不会触发下载或更新。",
		Schema:     objSchema(map[string]any{}),
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision {
			return actool.Allowed()
		},
		Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			st := s.nucleiManager().Status(ctx)
			var b strings.Builder
			fmt.Fprintf(&b, "nuclei 根目录: %s\n", st.Root)
			fmt.Fprintf(&b, "二进制: %s（存在=%v）\n", st.BinaryPath, st.BinaryExists)
			if st.BinaryVersion != "" {
				fmt.Fprintf(&b, "版本: %s\n", st.BinaryVersion)
			}
			fmt.Fprintf(&b, "模板目录: %s（存在=%v，%d 个文件）\n", st.TemplatesDir, st.TemplatesExists, st.TemplateCount)
			fmt.Fprintf(&b, "自定义模板: %s（存在=%v，%d 个文件）\n", st.CustomTemplatesDir, st.CustomTemplatesExists, st.CustomTemplateCount)
			fmt.Fprintf(&b, "自动更新: %v（间隔 %d 小时）\n", st.AutoUpdate, st.UpdateIntervalHours)
			if st.LastUpdate != "" {
				fmt.Fprintf(&b, "上次更新: %s\n", st.LastUpdate)
			} else {
				b.WriteString("上次更新: 从未（下次扫描会触发）\n")
			}
			fmt.Fprintf(&b, "interactsh: %v\n", st.Interactsh)
			for _, w := range st.Warnings {
				fmt.Fprintf(&b, "提示: %s\n", w)
			}
			return actool.Text(b.String()), nil
		},
	})
}

// nucleiTargetURL 把 agent 给的裸 host/host:port 补成可解析 URL，供 RoE 校验。
func nucleiTargetURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("目标为空")
	}
	if strings.ContainsAny(raw, "\r\n\t ") {
		return "", fmt.Errorf("目标格式不合法: %q", raw)
	}
	candidate := raw
	if !strings.Contains(candidate, "://") {
		// 裸 IPv6 必须加方括号；host:port 形态（含 [v6]:port）直接补 scheme。
		if ip := net.ParseIP(candidate); ip != nil && ip.To4() == nil {
			candidate = "http://[" + candidate + "]"
		} else {
			candidate = "http://" + candidate
		}
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("目标 URL 无效: %q", raw)
	}
	if s := strings.ToLower(u.Scheme); s != "http" && s != "https" {
		return "", fmt.Errorf("nuclei 只接受 http/https 目标: %q", raw)
	}
	return candidate, nil
}

// seedNucleiTools 把工具播种进 tools 表并补绑存量库。host 工具没有
// BuiltinToolSeeds 的自动播种，需要和 traffic 工具一样显式处理。
func (s *Server) seedNucleiTools() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	bindings := map[string][]string{
		"nuclei_scan":            {"worker", "planner", "recon", "pentest", "auto"},
		"nuclei_template_search": {"worker", "planner", "recon", "pentest", "auto"},
		"nuclei_update":          {"auto", "recon", "pentest", "mainagent"},
		"nuclei_status":          {"auto", "recon", "pentest", "mainagent"},
	}
	for _, t := range s.nucleiTools() {
		schema, _ := json.Marshal(t.InputSchema())
		agents, _ := json.Marshal(bindings[t.Name()])
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[nuclei] seed tool %s: %v", t.Name(), err)
		}
	}
	const flag = "nuclei_tools_bind_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for tool, agents := range bindings {
		for _, key := range agents {
			if a, _ := s.m.pg.GetAgentByKey(key); a == nil {
				continue
			}
			if err := s.m.pg.AddAgentToToolBinding(key, []string{tool}); err != nil {
				log.Printf("[nuclei] 绑定 %s → %s 失败: %v", tool, key, err)
			}
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
