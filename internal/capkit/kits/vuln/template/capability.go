package template

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Capability exposes the template catalog as read-only tools. It never
// executes a template; execution belongs to the engine (verifykit/nucleikit).
type Capability struct {
	mu      sync.RWMutex
	catalog *Catalog
}

// NewCapability builds the capability. When the host already provides a
// *Catalog as Deps.Templates it is reused so hot-reloaded packs are visible
// here too; otherwise an empty catalog is created.
func NewCapability(deps core.Deps) (core.Capability, error) {
	c := &Capability{}
	if cat, ok := deps.Templates.(*Catalog); ok && cat != nil {
		c.catalog = cat
	} else {
		c.catalog = NewCatalog()
	}
	return c, nil
}

// Manifest declares the catalog tools.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: "templatekit", Version: "0.2.0", APIVersion: "v1",
		Tools: []core.ToolSpec{
			{
				Name:        "template_search",
				Description: "按关键字、产品、指纹、CVE、标签或严重级别检索模板目录，返回引擎中立引用（ID/名称/类型）。只读，不执行。",
				Risk:        core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "text":{"type":"string"},
    "products":{"type":"array","items":{"type":"string"}},
    "fingerprint":{"type":"string"},
    "cve":{"type":"string"},
    "tags":{"type":"array","items":{"type":"string"}},
    "severity":{"type":"array","items":{"type":"string"}},
    "kind":{"type":"string","enum":["http","nuclei","shell","chain"]},
    "limit":{"type":"integer","minimum":1,"maximum":500}
  }
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "count":{"type":"integer"},
    "total":{"type":"integer"},
    "templates":{"type":"array","items":{"type":"object","properties":{"id":{"type":"string"},"name":{"type":"string"},"kind":{"type":"string"},"engine":{"type":"string"},"meta":{"type":"object"}}}}
  }
}`),
			},
			{
				Name:        "template_get",
				Description: "按模板 ID 取出单条模板及其执行产物（引用 + 内容）。只读，不执行。",
				Risk:        core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{"id":{"type":"string"}},
  "required":["id"]
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id":{"type":"string"},"name":{"type":"string"},"kind":{"type":"string"},
    "engine":{"type":"string"},"artifact_base64":{"type":"string"},"meta":{"type":"object"}
  }
}`),
			},
		},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches the catalog tools.
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "template_search":
		return c.search(ctx, call)
	case "template_get":
		return c.get(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (c *Capability) search(ctx context.Context, call core.Call) (core.Result, error) {
	var q core.TemplateQuery
	if err := json.Unmarshal(call.Input, &q); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	refs, err := c.catalog.Search(ctx, q)
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	res, _ := core.SuccessResult(fmt.Sprintf("命中 %d 条模板（目录共 %d 条）", len(refs), c.catalog.Count()), map[string]any{
		"count": len(refs), "total": c.catalog.Count(), "templates": refs,
	})
	return res, nil
}

func (c *Capability) get(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if strings.TrimSpace(in.ID) == "" {
		return core.FailResult(core.InvalidInput("id 必填")), nil
	}
	ref, ok, err := c.catalog.Get(ctx, in.ID)
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	if !ok {
		return core.FailResult(core.NotFound("模板不存在: " + in.ID)), nil
	}
	data, _ := core.DataResult(map[string]any{
		"id": ref.ID, "name": ref.Name, "kind": ref.Kind, "engine": ref.Engine,
		"artifact_base64": base64.StdEncoding.EncodeToString(ref.Artifact), "meta": ref.Meta,
	})
	data.Summary = fmt.Sprintf("模板 %s（%s）", ref.ID, ref.Kind)
	return data, nil
}
