package core

import (
	"context"
	"sort"
)

// This file lands the Planner contract (docs §5.3). A Planner turns one
// Finding into candidate next actions. Kits contribute candidates by returning
// NextStep from their tools; hosts and agents read the same data, so the
// "what should I do now" question has one answer, not one per surface.

// PlannerFunc adapts a function to Planner.
type PlannerFunc func(ctx context.Context, f Finding) ([]NextStep, error)

func (f PlannerFunc) Suggest(ctx context.Context, finding Finding) ([]NextStep, error) {
	return f(ctx, finding)
}

// ChainPlanner merges several planners, deduping by tool name (first planner
// that suggests a tool wins, so order expresses priority).
type ChainPlanner struct {
	Planners []Planner
}

// Add appends a planner (nil is ignored).
func (c *ChainPlanner) Add(p Planner) {
	if p != nil {
		c.Planners = append(c.Planners, p)
	}
}

func (c *ChainPlanner) Suggest(ctx context.Context, f Finding) ([]NextStep, error) {
	seen := map[string]bool{}
	var out []NextStep
	for _, p := range c.Planners {
		if p == nil {
			continue
		}
		steps, err := p.Suggest(ctx, f)
		if err != nil {
			return nil, err
		}
		for _, s := range steps {
			if s.Tool == "" || seen[s.Tool] {
				continue
			}
			seen[s.Tool] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// DefaultPlanner is the built-in kind->action table. It only suggests the next
// step for a CONFIRMED finding (an unconfirmed finding yields nothing), and it
// names tools that the host may or may not have registered.
func DefaultPlanner() Planner { return PlannerFunc(defaultSuggest) }

func defaultSuggest(_ context.Context, f Finding) ([]NextStep, error) {
	if !f.Confirmed {
		return nil, nil
	}
	switch f.Kind {
	case "cmdi":
		return []NextStep{
			{Tool: "cmdi_execute", Reason: "注入已确认，可执行任意命令", Risk: RiskHigh, Preconditions: []string{"finding.confirmed"}},
			{Tool: "session_open", Reason: "建立持久会话（kind=webshell）", Risk: RiskHigh, Preconditions: []string{"session.writeable"}},
		}, nil
	case "sqli":
		return []NextStep{
			{Tool: "sqli_probe", Reason: "换 DBMS/technique 扩大验证面", Risk: RiskHigh, Preconditions: []string{"finding.confirmed"}},
		}, nil
	case "lfi":
		return []NextStep{
			{Tool: "lfi_read", Reason: "已确认包含，可读取任意文件", Risk: RiskHigh, Preconditions: []string{"finding.confirmed"}},
			{Tool: "lfi_probe", Reason: "尝试日志投毒转为代码执行", Risk: RiskHigh, Preconditions: []string{"lfi.confirmed"}},
		}, nil
	case "ssrf":
		return []NextStep{
			{Tool: "redis_gopher", Reason: "SSRF 可打内网 Redis，构造写文件链", Risk: RiskHigh, Preconditions: []string{"finding.confirmed"}},
			{Tool: "inet_portscan", Reason: "枚举 SSRF 可触达的内网端口", Risk: RiskMedium, Preconditions: []string{"finding.confirmed"}},
		}, nil
	case "upload":
		return []NextStep{
			{Tool: "session_open", Reason: "上传点可投放 WebShell 建立会话", Risk: RiskHigh, Preconditions: []string{"upload.confirmed"}},
		}, nil
	case "deser":
		return []NextStep{
			{Tool: "deser_generate", Reason: "生成反序列化 payload 并投递", Risk: RiskHigh, Preconditions: []string{"finding.confirmed"}},
		}, nil
	default:
		return nil, nil
	}
}

// DedupeNext merges suggestions from several sources into one ordered list,
// deduping by tool. Convenience for tools that build Next from a finding plus
// local knowledge.
func DedupeNext(groups ...[]NextStep) []NextStep {
	seen := map[string]bool{}
	var out []NextStep
	for _, g := range groups {
		for _, s := range g {
			if s.Tool == "" || seen[s.Tool] {
				continue
			}
			seen[s.Tool] = true
			out = append(out, s)
		}
	}
	return out
}

// SortByRisk orders steps by descending risk then tool name (stable output for
// tests and UIs).
func SortByRisk(steps []NextStep) []NextStep {
	out := make([]NextStep, len(steps))
	copy(out, steps)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk.rank() > out[j].Risk.rank()
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}
