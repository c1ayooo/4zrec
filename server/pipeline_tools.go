// pipeline_tools.go 主动测绘流水线工具:recon_run 异步起跑(立即返回 run id,
// goroutine 执行,recon_runs 表为事实源)、recon_results 查询运行与统计。
// RoE:挂项目上下文时全部主域必须命中项目授权范围;无项目时权限层人工确认。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/db"
	"github.com/c1ayooo/4zrec/fingerprint"
	"github.com/c1ayooo/4zrec/recon/pipeline"
	actool "github.com/c1ayooo/4zrec/tools"
)

// startReconRun 起跑:建 running 行 → goroutine 跑流水线 → 逐阶段回写 → 终态。
// panic 兜底置 failed(异步 goroutine 的 recover 是唯一防线)。
func (s *Server) startReconRun(opts pipeline.Options) (int64, error) {
	cfg, _ := json.Marshal(map[string]any{
		"subdomain": opts.EnableSubdomain, "permute": opts.EnablePermute, "brute": opts.EnableBrute,
		"dns": opts.EnableDNS, "portscan": opts.EnablePortscan, "http": opts.EnableHTTP,
		"ports": opts.PortsSet, "qps": opts.QPS, "rate": opts.Rate,
	})
	id, err := s.m.pg.CreateReconRun(context.Background(), opts.ProjectID, opts.Domains, cfg)
	if err != nil {
		return 0, err
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				_ = s.m.pg.FinishReconRun(context.Background(), id, "", nil, fmt.Sprintf("panic: %v", r))
			}
		}()
		// 指纹规则预取一次(阶段4共用);失败不阻断——只是无 technologies。
		// Store 轻量按需建(Manager 不常驻持有),EnabledRules 走规则表。
		var rules []fingerprint.CompiledRule
		if fp, err := fingerprint.NewStore(s.m.pg.DB); err == nil {
			rules, _ = fp.EnabledRules(context.Background())
		}
		opts.FingerprintRules = rules
		stats, runErr := pipeline.Run(context.Background(), opts, s.m.pg, func(stage string, st pipeline.Stats) {
			_ = s.m.pg.UpdateReconRunProgress(context.Background(), id, stage, pipeline.MarshalStats(st))
		})
		var finalStats json.RawMessage
		if stats != nil {
			finalStats = pipeline.MarshalStats(*stats)
		}
		stage := lastStage(opts)
		if runErr != nil {
			stage = "interrupted"
		}
		_ = s.m.pg.FinishReconRun(context.Background(), id, stage, finalStats, errStr(runErr))
	}()
	return id, nil
}

func lastStage(opts pipeline.Options) string {
	if opts.EnableHTTP {
		return "http"
	}
	if opts.EnablePortscan {
		return "portscan"
	}
	if opts.EnableDNS || opts.EnableSubdomain || opts.EnableBrute || opts.EnablePermute {
		return "dns"
	}
	return "subdomain"
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// toolReconRun 四阶段主动测绘(异步)。
func (s *Server) toolReconRun() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "recon_run",
		Description: "主动测绘流水线(异步):对主域跑「子域枚举(被动/派生/爆破)→DNS 存活→端口扫描+服务识别→HTTP 指纹」" +
			"四阶段,各阶段独立开关。立即返回 run id,用 recon_results 查进度与结果(每阶段实时回写)。" +
			"结果全链入库:子域(带解析记录与 P0-P4 优先级)、IP(开放端口)、http 服务(标题/状态码/指纹技术栈)。" +
			"挂项目上下文时主域必须全部在授权范围内。大范围扫描耗时,不要在对话里同步等它。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"domains":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "目标主域列表"},
				"subdomain":  map[string]any{"type": "boolean", "description": "被动源枚举(默认 true)"},
				"permute":    map[string]any{"type": "boolean", "description": "候选派生(默认 false)"},
				"brute":      map[string]any{"type": "boolean", "description": "子域名爆破(默认 false,主动 DNS)"},
				"dns":        map[string]any{"type": "boolean", "description": "DNS 存活性解析(默认 true)"},
				"portscan":   map[string]any{"type": "boolean", "description": "端口扫描+服务识别(默认 true,主动探测)"},
				"http":       map[string]any{"type": "boolean", "description": "HTTP 指纹(默认 true,主动探测)"},
				"ports":      map[string]any{"type": "string", "description": "端口集:top100(默认)/web/自定义"},
				"qps":        map[string]any{"type": "integer", "description": "爆破 DNS 每秒上限(默认 300)"},
				"rate":       map[string]any{"type": "integer", "description": "端口扫描每秒连接上限(默认 500)"},
				"project_id": map[string]any{"type": "integer", "description": "入库认领项目(挂项目任务自动取上下文)"},
			},
			"required": []string{"domains"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in struct {
				Domains []string `json:"domains"`
			}
			_ = json.Unmarshal(input, &in)
			return actool.AskUser("主动测绘流水线(含主动探测)目标主域: " + strings.Join(in.Domains, ", "))
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Domains   []string `json:"domains"`
				Subdomain *bool    `json:"subdomain"`
				Permute   bool     `json:"permute"`
				Brute     bool     `json:"brute"`
				DNS       *bool    `json:"dns"`
				Portscan  *bool    `json:"portscan"`
				HTTP      *bool    `json:"http"`
				Ports     string   `json:"ports"`
				QPS       int      `json:"qps"`
				Rate      int      `json:"rate"`
				ProjectID int64    `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if len(in.Domains) == 0 {
				return actool.Errorf("domains 不能为空"), nil
			}

			// RoE:挂项目上下文时全部主域必须命中授权范围。
			projectID := s.roeProjectID(ctx, in.ProjectID)
			if projectID > 0 {
				rules, rerr := s.m.pg.ProjectScopeRules(projectID)
				if rerr != nil {
					return actool.Errorf("RoE 校验失败(读取项目范围): " + rerr.Error()), nil
				}
				var denied []string
				for _, d := range in.Domains {
					if _, ok := db.MatchProjectScope(rules, strings.TrimSpace(d), ""); !ok {
						denied = append(denied, d)
					}
				}
				if len(denied) > 0 {
					return actool.Errorf(fmt.Sprintf(
						"【RoE 拒绝】主域不在项目 %d 授权范围内: %s。请只测授权内主域。",
						projectID, strings.Join(denied, ", "))), nil
				}
			}

			boolOr := func(p *bool, def bool) bool {
				if p == nil {
					return def
				}
				return *p
			}
			id, err := s.startReconRun(pipeline.Options{
				Domains:         in.Domains,
				EnableSubdomain: boolOr(in.Subdomain, true), EnablePermute: in.Permute, EnableBrute: in.Brute,
				EnableDNS: boolOr(in.DNS, true), EnablePortscan: boolOr(in.Portscan, true), EnableHTTP: boolOr(in.HTTP, true),
				PortsSet: in.Ports, QPS: in.QPS, Rate: in.Rate, ProjectID: projectID,
			})
			if err != nil {
				return actool.Errorf("创建运行失败: " + err.Error()), nil
			}
			return actool.Text(fmt.Sprintf(
				"流水线已起跑:run #%d(主域 %s;子域枚举/解析/端口/指纹按配置执行)。用 recon_results(run_id=%d) 查进度与统计——异步执行,不要等待。",
				id, strings.Join(in.Domains, ", "), id)), nil
		},
	})
}

// toolReconResults 运行查询:list 或单行详情。
func (s *Server) toolReconResults() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "recon_results",
		Description: "查询主动测绘流水线运行:不传 run_id 返回最近运行列表(状态/阶段/统计摘要);" +
			"传 run_id 返回单次运行的完整统计(各阶段计数、P0-P4 分布、错误)。运行完成后再 list_assets 看落库资产。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"run_id":     map[string]any{"type": "integer", "description": "单次运行 id(缺省=列表)"},
				"project_id": map[string]any{"type": "integer", "description": "按项目过滤(可选)"},
				"limit":      map[string]any{"type": "integer", "description": "列表条数(默认 20)"},
			},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				RunID     int64 `json:"run_id"`
				ProjectID int64 `json:"project_id"`
				Limit     int   `json:"limit"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if in.RunID > 0 {
				r, err := s.m.pg.GetReconRun(ctx, in.RunID)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("运行 #%d 不存在: %v", in.RunID, err)), nil
				}
				return actool.Text(formatReconRun(r)), nil
			}
			runs, err := s.m.pg.ListReconRuns(ctx, in.ProjectID, in.Limit, 0)
			if err != nil {
				return actool.Errorf("查询失败: " + err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "最近 %d 次运行:\n", len(runs))
			for _, r := range runs {
				fmt.Fprintf(&b, "- #%d %s [%s] %s → %s\n", r.ID, strings.Join(r.Domains, ","),
					r.Status, r.Stage, statsSummary(r.Stats))
				if r.Error != "" {
					fmt.Fprintf(&b, "  错误: %s\n", r.Error)
				}
			}
			return actool.Text(b.String()), nil
		},
	})
}

func statsSummary(raw json.RawMessage) string {
	var st pipeline.Stats
	if json.Unmarshal(raw, &st) != nil {
		return ""
	}
	return fmt.Sprintf("候选%d/活%d/端口%d/http%d", st.Candidates, st.Live, st.OpenPorts, st.HTTPAlive)
}

func formatReconRun(r *db.ReconRun) string {
	var b strings.Builder
	fmt.Fprintf(&b, "运行 #%d 状态: %s(到达阶段 %s)\n主域: %s\n", r.ID, r.Status, r.Stage, strings.Join(r.Domains, ", "))
	if r.ProjectID != nil && *r.ProjectID > 0 {
		fmt.Fprintf(&b, "项目: %d\n", *r.ProjectID)
	}
	var st pipeline.Stats
	if json.Unmarshal(r.Stats, &st) == nil {
		fmt.Fprintf(&b, "候选: %d(被动%d/派生%d/爆破%d,泛解析滤%d)\n", st.Candidates, st.FromPassive, st.FromPermute, st.FromBrute, st.WildcardFiltered)
		fmt.Fprintf(&b, "解析: 活 %d / 死 %d;扫描 IP %d,开放端口 %d\n", st.Live, st.Dead, st.ScanIPs, st.OpenPorts)
		fmt.Fprintf(&b, "HTTP: 探测 %d,存活 %d\n", st.HTTPProbed, st.HTTPAlive)
		if len(st.Levels) > 0 {
			fmt.Fprintf(&b, "优先级分布: %v\n", st.Levels)
		}
		for _, e := range st.Errors {
			fmt.Fprintf(&b, "错误: %s\n", e)
		}
	}
	if r.Error != "" {
		fmt.Fprintf(&b, "运行错误: %s\n", r.Error)
	}
	return b.String()
}
