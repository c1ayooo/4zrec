package toolparse

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Capability exposes the structured-output parsers as a tool. It turns one
// external CLI tool's raw stdout into key fields and fact candidates, so the
// agent reads structure instead of scraping text.
type Capability struct{}

// NewCapability builds the parser capability.
func NewCapability(core.Deps) (core.Capability, error) { return &Capability{}, nil }

// Manifest declares the parser tools.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: "toolparse", Version: "0.2.0", APIVersion: "v1",
		Tools: []core.ToolSpec{
			{
				Name:        "tool_parse",
				Description: "把外部 CLI 工具（httpx/ffuf/nmap/nuclei/fscan/sqlmap/katana/hashcat/john 等）的原始 stdout 解析为结构化字段与事实候选。解析失败 fail-closed：OK=false 且不产出事实。",
				Risk:        core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "tool":{"type":"string","description":"工具名，如 fscan/httpx/nmap"},
    "argv":{"type":"array","items":{"type":"string"},"description":"该次调用的参数（用于判定输出标志）"},
    "stdout":{"type":"string"},
    "stderr":{"type":"string"},
    "raw_ref":{"type":"string","description":"原始证据落盘路径"}
  },
  "required":["tool","stdout"]
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "tool":{"type":"string"},
    "ok":{"type":"boolean"},
    "fields":{"type":"object"},
    "facts":{"type":"array","items":{"type":"object"}},
    "raw_ref":{"type":"string"},
    "err":{"type":"string"}
  }
}`),
			},
			{
				Name:         "tool_parse_list",
				Description:  "列出已注册解析器的工具名。只读。",
				Risk:         core.RiskLow,
				InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"tools":{"type":"array","items":{"type":"string"}}}}`),
			},
		},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches the parser tools.
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "tool_parse":
		return c.parse(ctx, call)
	case "tool_parse_list":
		tools := RegisteredTools()
		sort.Strings(tools)
		res, _ := core.SuccessResult(fmt.Sprintf("已注册 %d 个解析器", len(tools)), map[string]any{
			"count": len(tools), "tools": tools,
		})
		return res, nil
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (c *Capability) parse(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		Tool   string   `json:"tool"`
		Argv   []string `json:"argv"`
		Stdout string   `json:"stdout"`
		Stderr string   `json:"stderr"`
		RawRef string   `json:"raw_ref"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	tool := strings.TrimSpace(in.Tool)
	if tool == "" {
		return core.FailResult(core.InvalidInput("tool 必填")), nil
	}
	p := Lookup(tool, in.Argv)
	if p == nil {
		return core.FailResult(core.NewError(core.CodeNotFound,
			"无匹配解析器（工具未注册或缺少结构化输出标志）: "+tool)), nil
	}
	out, err := p.Parse(in.Stdout, in.Stderr, in.RawRef)
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	res, _ := core.DataResult(out)
	if out.OK {
		res.Summary = fmt.Sprintf("解析 %s 成功：%d 个字段，%d 条事实候选", tool, len(out.Fields), len(out.Facts))
	} else {
		res.Status = core.StatusPartial
		res.OK = true
		res.Summary = fmt.Sprintf("解析 %s 未产出结论（输入畸形或非结构化）", tool)
	}
	return res, nil
}
