// diffprobe_tools.go 差分探测工具：把 agent 提出的「基线 + 变体」假设变
// 成可重复的量化对照（状态/长度/相似度/时延/DBMS 错误特征/反射），每个
// 采样都写入证据库。工具不生成 payload，也不替 agent 下漏洞结论。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capability/web/diffprobe"
	"github.com/c1ayooo/4zrec/internal/capability/web/httpprobe"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

func (s *Server) diffProbeTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolDifferentialProbe()}
}

func (s *Server) toolDifferentialProbe() actool.CoreTool {
	reqProps := func(includeMeta bool) map[string]any {
		p := map[string]any{
			"url":     map[string]any{"type": "string", "description": "完整 URL（http://host:port/path?query）"},
			"method":  map[string]any{"type": "string", "description": "HTTP 方法（默认 GET）"},
			"headers": map[string]any{"type": "object", "description": "请求头键值对（Cookie/Authorization 等）"},
			"body":    map[string]any{"type": "string", "description": "请求体"},
		}
		if includeMeta {
			p["label"] = map[string]any{"type": "string", "description": "变体名（输出里用于对照）"}
			p["role"] = map[string]any{"type": "string", "enum": []string{"probe", "control", "true", "false"}, "description": "probe=普通变体；control=对照；true/false=布尔盲注的真/假分支"}
			p["marker"] = map[string]any{"type": "string", "description": "可选：检查该字符串是否反射到响应（原样/URL 编码/HTML 转义）"}
		}
		return p
	}

	return actool.Build(actool.Spec{
		Name: "differential_probe",
		Description: "差分测量工具（SQL 注入/布尔盲注/时间盲注/错误注入等）：你给出**基线请求**和**若干变体请求**，" +
			"工具逐包重复采样并返回状态码、响应长度、内容相似度、时延统计（min/median/max/σ）、" +
			"DBMS 错误特征（MySQL/PostgreSQL/MSSQL/Oracle/SQLite）、反射标记，以及可直接绑定证据的 traffic_id。" +
			"它不生成 payload，也不自动判定漏洞——结论仍由你结合响应内容与业务语义判断。" +
			"用法：布尔盲注给 role=true/false 两条分支；时间盲注设 repeats>=3 和 timing_delta_ms（默认 1000）；" +
			"错误注入把带引号/运算符的变体交给它自动匹配错误特征；需要确认输入是否回显时设 marker。" +
			"返回的 verdict=signal 只表示观测到稳定差异，不是漏洞结论；confidence 是测量置信度。" +
			"挂项目上下文时所有目标都必须在授权范围内（逐 URL 校验）。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"baseline": map[string]any{
					"type":        "object",
					"description": "基线请求（正常业务请求）",
					"properties":  reqProps(false),
					"required":    []string{"url"},
				},
				"variants": map[string]any{
					"type":        "array",
					"description": "变体请求数组（1..20）。每个变体只改你想验证的变量，其它字段与基线保持一致。",
					"items": map[string]any{
						"type":       "object",
						"properties": reqProps(true),
						"required":   []string{"url"},
					},
				},
				"repeats":              map[string]any{"type": "integer", "description": "每个请求采样次数（1..10）。时间盲注建议 >=3；未设 timing_delta_ms 时默认 1，设了则默认 3"},
				"similarity_threshold": map[string]any{"type": "number", "description": "内容相似度阈值（0..1，默认 0.90）；低于它视为与基线内容不同"},
				"timing_delta_ms":      map[string]any{"type": "integer", "description": "时延信号阈值（毫秒，默认 1000）；变体中位时延超过基线该值且多数采样过阈值时提示 time_based"},
				"timing_tolerance_ms":  map[string]any{"type": "integer", "description": "时延采样抖动容忍（毫秒，默认 150），仅用于输出参考"},
				"error_patterns":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "追加的错误特征正则（内置常见 DBMS 错误特征之外的自定义特征）"},
				"marker":               map[string]any{"type": "string", "description": "全局反射标记；变体未单独设置 marker 时使用"},
				"proxy":                map[string]any{"type": "string", "description": "出站代理（http/socks5；空=直连）"},
				"timeout_seconds":      map[string]any{"type": "integer", "description": "单请求超时秒（默认 20）"},
				"random_fingerprint":   map[string]any{"type": "string", "description": "指纹随机化：默认开；传 off 关闭"},
				"project_id":           map[string]any{"type": "integer", "description": "项目上下文（挂项目任务自动取）"},
			},
			"required": []string{"baseline", "variants"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			var in diffProbeInput
			_ = json.Unmarshal(input, &in)
			target := strings.TrimSpace(in.Baseline.URL)
			if target == "" {
				target = "(缺少 baseline.url)"
			}
			repeats := "自动"
			if in.Repeats > 0 {
				repeats = fmt.Sprintf("%d 次", in.Repeats)
			}
			return actool.AskUser(fmt.Sprintf("差分探测：基线 %s，%d 个变体，每个采样 %s", target, len(in.Variants), repeats))
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in diffProbeInput
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(in.Baseline.URL) == "" {
				return actool.Errorf("baseline.url 不能为空"), nil
			}
			if len(in.Variants) == 0 {
				return actool.Errorf("至少需要一个 variant"), nil
			}
			if len(in.Variants) > 20 {
				return actool.Errorf("variants 最多 20 个"), nil
			}
			// marker 是全局便捷字段：变体没填时继承。
			if in.Marker != "" {
				for i := range in.Variants {
					if in.Variants[i].Marker == "" {
						in.Variants[i].Marker = in.Marker
					}
				}
			}
			// RoE 逐 URL 校验（先全部校验再发请求，避免打到一半才发现越界）。
			for _, target := range append([]diffprobe.Request{in.Baseline}, in.Variants...) {
				if msg := s.webreconRoE(ctx, in.ProjectID, target.URL); msg != "" {
					return actool.Errorf(strings.TrimSpace(msg)), nil
				}
			}
			do := func(ctx context.Context, req httpprobe.Request) (diffprobe.Response, error) {
				res, err := httpprobe.DoRequest(ctx, req)
				if err != nil {
					return diffprobe.Response{}, err
				}
				tid := s.recordProbeEvidence(res, req.Method, req.URL, "")
				return diffprobe.Response{Result: res, TrafficID: tid}, nil
			}
			rep, err := diffprobe.Run(ctx, in.Baseline, in.Variants, diffprobe.Options{
				Repeats:             in.Repeats,
				SimilarityThreshold: in.SimilarityThreshold,
				TimingDeltaMS:       in.TimingDeltaMS,
				TimingToleranceMS:   in.TimingToleranceMS,
				ErrorPatterns:       in.ErrorPatterns,
				Proxy:               in.Proxy,
				TimeoutSeconds:      in.TimeoutSeconds,
				RandomFingerprint:   in.RandomFingerprint,
			}, do)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(rep.Text()), nil
		},
	})
}

type diffProbeInput struct {
	Baseline            diffprobe.Request   `json:"baseline"`
	Variants            []diffprobe.Request `json:"variants"`
	Repeats             int                 `json:"repeats"`
	SimilarityThreshold float64             `json:"similarity_threshold"`
	TimingDeltaMS       int64               `json:"timing_delta_ms"`
	TimingToleranceMS   int64               `json:"timing_tolerance_ms"`
	ErrorPatterns       []string            `json:"error_patterns"`
	Marker              string              `json:"marker"`
	Proxy               string              `json:"proxy"`
	TimeoutSeconds      int                 `json:"timeout_seconds"`
	RandomFingerprint   string              `json:"random_fingerprint"`
	ProjectID           int64               `json:"project_id"`
}

// seedDifferentialProbeTool 把工具播种进 tools 表，默认绑给真正需要做
// 推理型验证的 agent：worker（执行）、planner（研判）、pentest（独立渗透）、
// retester（复测）。首插入生效，UI 可改绑/停用。
func (s *Server) seedDifferentialProbeTool() {
	const flag = "differential_probe_tool_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	t := s.toolDifferentialProbe()
	schema, _ := json.Marshal(t.InputSchema())
	agents, _ := json.Marshal([]string{"worker", "planner", "pentest", "retester"})
	if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
		log.Printf("[diffprobe] seed tool: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// rebindDifferentialProbeAgents 存量库迁移：把新工具补绑到执行/研判/复测
// agent。幂等，flag 守卫只做一次。
func (s *Server) rebindDifferentialProbeAgents() {
	const flag = "differential_probe_bind_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()
	for _, key := range []string{"worker", "planner", "pentest", "retester"} {
		if a, _ := s.m.pg.GetAgentByKey(key); a == nil {
			continue // 用户删过/自定义库，不重建
		}
		if err := s.m.pg.AddAgentToToolBinding(key, []string{"differential_probe"}); err != nil {
			log.Printf("[diffprobe] 绑定 %s 失败: %v", key, err)
		}
	}
}
