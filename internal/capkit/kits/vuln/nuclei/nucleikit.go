package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// kitVersion is stamped into every Result envelope (mirrors the manifest).
const kitVersion = "0.1.0"

// Kit wraps the nuclei execution engine. Execution scheduling, process
// management, concurrency and JSONL parsing belong here; template indexing is
// delegated to a TemplateCatalog implementation (wired by the host later).
type Kit struct {
	Processes core.ProcessRunner
	Binaries  core.BinaryManager
	Settings  core.Settings
	Evidence  core.EvidenceSink
}

func New(deps core.Deps) *Kit {
	return &Kit{Processes: deps.Processes, Binaries: deps.Binaries, Settings: deps.Settings, Evidence: deps.Evidence}
}

func NewCapability(deps core.Deps) (core.Capability, error) { return New(deps), nil }

func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "nucleikit", Version: kitVersion, APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "process", "binary"},
		Tools: []core.ToolSpec{
			{
				Name:        "nuclei_scan",
				Description: "Run nuclei against one or more in-scope targets and parse JSONL output. Execution is gated by scope, approval, rate limiting and audit at the runtime layer.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "targets":{"type":"array","items":{"type":"string"},"description":"in-scope URLs/hosts"},
    "templates":{"type":"array","items":{"type":"string"},"description":"template IDs or relative paths"},
    "tags":{"type":"array","items":{"type":"string"}},
    "severity":{"type":"array","items":{"type":"string"}},
    "timeout_sec":{"type":"integer","description":"per-target timeout (default 120)"}
  },
  "required":["targets"]
}`),
				Risk:         core.RiskHigh,
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"status":{"type":"integer"},"findings":{"type":"array","items":{"type":"object"}},"duration_ms":{"type":"integer"},"binary":{"type":"string"}}}`),
				RateLimit:    core.RateLimitSpec{PerSecond: 5, Burst: 2, Concurrency: 1},
				ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
					var in scanInput
					if err := json.Unmarshal(input, &in); err != nil {
						return nil, err
					}
					return core.TargetsFromStrings(0, in.Targets)
				},
			},
			{
				Name:           "nuclei_status",
				Description:    "Report the managed nuclei binary status (version/path/updated_at).",
				InputSchema:    json.RawMessage(`{"type":"object","properties":{}}`),
				Risk:           core.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"installed":{"type":"boolean"},"version":{"type":"string"},"path":{"type":"string"}}}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
		},
	}
}

type scanInput struct {
	Targets    []string `json:"targets"`
	Templates  []string `json:"templates"`
	Tags       []string `json:"tags"`
	Severity   []string `json:"severity"`
	TimeoutSec int      `json:"timeout_sec"`
}

// Call is the envelope shell: it runs the tool and normalizes the Result so
// every return path carries a valid Status, Meta.Tool and a clamped Summary.
func (k *Kit) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := k.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

// dispatch routes a call to its tool implementation, exactly as before.
func (k *Kit) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "nuclei_scan":
		return k.scan(ctx, call)
	case "nuclei_status":
		return k.status(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) status(ctx context.Context, _ core.Call) (core.Result, error) {
	if k.Binaries == nil {
		return core.FailResult(core.Unavailable(
			"nuclei 状态不可用：binary manager is not configured")), nil
	}
	st, err := k.Binaries.Status(ctx, "nuclei")
	if err != nil {
		return core.FailResult(err), nil
	}
	state := "未安装"
	if st.Installed {
		state = "已安装"
	}
	res, _ := core.SuccessResult(fmt.Sprintf("nuclei 环境：%s，版本 %s，路径 %s",
		state, orDash(st.Version), orDash(st.Path)), st)
	return res, nil
}

func (k *Kit) scan(ctx context.Context, call core.Call) (core.Result, error) {
	var in scanInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if len(in.Targets) == 0 {
		return core.FailResult(core.InvalidInput("targets is required")), nil
	}
	if k.Binaries == nil || k.Processes == nil {
		return core.FailResult(core.Unavailable(
			"nuclei 扫描不可用：binary/process runner is not configured")), nil
	}
	version := "3.11.1"
	if k.Settings != nil {
		if v, ok := k.Settings.GetString(ctx, "nuclei.version"); ok && strings.TrimSpace(v) != "" {
			version = v
		}
	}
	path, _, err := k.Binaries.Ensure(ctx, "nuclei", version)
	if err != nil {
		return core.FailResult(err), nil
	}
	timeout := time.Duration(in.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}

	targets, err := core.TargetsFromStrings(call.Context.ProjectID, in.Targets)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	var hits []any
	var rawLines []string
	for i, raw := range in.Targets {
		args := []string{"-u", raw, "-jsonl", "-silent", "-no-color"}
		for _, t := range in.Templates {
			args = append(args, "-t", t)
		}
		if len(in.Tags) > 0 {
			args = append(args, "-tags", strings.Join(in.Tags, ","))
		}
		if len(in.Severity) > 0 {
			args = append(args, "-severity", strings.Join(in.Severity, ","))
		}
		proc, err := k.Processes.Run(ctx, core.ProcessSpec{
			Path: path, Args: args, Timeout: timeout, Targets: []core.Target{targets[i]},
			RateLimit: core.RateLimitSpec{PerSecond: 5, Burst: 2, Concurrency: 1},
		})
		if err != nil {
			return core.FailResult(err), nil
		}
		rawLines = append(rawLines, string(proc.Stdout))
		hits = append(hits, parseJSONL(proc.Stdout)...)
		if proc.ExitCode != 0 {
			return core.FailResult(core.NewError(core.CodeInternal,
				fmt.Sprintf("对 %s 扫描失败：nuclei exited %d: %s",
					raw, proc.ExitCode, truncate(string(proc.Stderr), 500)))), nil
		}
	}
	out := map[string]any{
		"hits": hits, "hit_count": len(hits), "target_count": len(in.Targets),
		"raw_lines": len(strings.Split(strings.TrimSpace(strings.Join(rawLines, "\n")), "\n")),
	}
	critical, high := countSeverity(hits)
	tplPhrase := "默认模板集"
	if len(in.Templates) > 0 {
		tplPhrase = fmt.Sprintf("%d 个模板", len(in.Templates))
	}
	targetPhrase := fmt.Sprintf("%d 个目标", len(in.Targets))
	if len(in.Targets) == 1 {
		targetPhrase = in.Targets[0]
	}
	summary := fmt.Sprintf("对 %s 执行 %s，命中 %d 项，其中严重 %d/高危 %d",
		targetPhrase, tplPhrase, len(hits), critical, high)
	result, _ := core.SuccessResult(summary, out)
	if k.Evidence != nil {
		id, err := k.Evidence.Record(ctx, core.Evidence{
			Kind: "nuclei", Title: fmt.Sprintf("nuclei scan (%d targets)", len(in.Targets)),
			Data: json.RawMessage(mustJSON(out)), CreatedAt: time.Now(),
		})
		if err == nil && id != "" {
			result.EvidenceIDs = []string{id}
		}
	}
	return result, nil
}

func parseJSONL(data []byte) []any {
	var out []any
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(line), &v); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// orDash renders an empty field as "-" so a Summary never has a blank slot.
func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// countSeverity tallies nuclei JSONL hits by severity, used by the scan
// Summary so the agent sees the risk profile without parsing Data.
func countSeverity(hits []any) (critical, high int) {
	for _, h := range hits {
		m, ok := h.(map[string]any)
		if !ok {
			continue
		}
		info, ok := m["info"].(map[string]any)
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(fmt.Sprint(info["severity"]))) {
		case "critical":
			critical++
		case "high":
			high++
		}
	}
	return critical, high
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
