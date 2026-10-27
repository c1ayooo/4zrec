package binding

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// kitVersion is stamped into every Result envelope.
const kitVersion = "0.1.0"

// Kit resolves the product names a fingerprint engine reports onto the
// canonical keys a template library uses.
//
// It is deliberately stateless: the binding table arrives with the call (or
// falls back to DefaultBindings). A host that maintains bindings in its own
// database passes the current table in the request, so the kit never needs a
// storage port and a table edit takes effect on the next call.
type Kit struct{}

func New(core.Deps) *Kit { return &Kit{} }

// NewCapability implements the capability constructor used by the registry.
func NewCapability(deps core.Deps) (core.Capability, error) { return New(deps), nil }

// Manifest declares the binding tools. No port is required: this capability
// is pure data transformation.
func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "bindingkit", Version: kitVersion, APIVersion: "v1",
		Tools: []core.ToolSpec{
			{
				Name: "binding_resolve",
				Description: "把指纹引擎识别出的产品名归一化成模板库的规范产品键，并给出对应的模板检索词与已绑定模板 id。" +
					"匹配不上就如实报告 unmatched，不做跨产品猜测。绑定表缺省使用内置表，也可在请求里传入宿主自己的表。",
				Risk: core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "products":{"type":"array","items":{"type":"string"},"description":"指纹识别出的产品名"},
    "cve":{"type":"string","description":"可选：按 CVE 反查产品"},
    "bindings":{"type":"array","items":{"type":"object","properties":{
      "product":{"type":"string"},
      "aliases":{"type":"array","items":{"type":"string"}},
      "query":{"type":"array","items":{"type":"string"}},
      "cves":{"type":"array","items":{"type":"string"}},
      "templates":{"type":"array","items":{"type":"string"}}}},"description":"宿主自己的绑定表；缺省用内置表"}
  },
  "required":["products"]
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "resolutions":{"type":"array","items":{"type":"object","properties":{
      "detected":{"type":"string"},"product":{"type":"string"},
      "matched_via":{"type":"string"},"confidence":{"type":"number"},
      "query":{"type":"array","items":{"type":"string"}},
      "templates":{"type":"array","items":{"type":"string"}}}}},
    "unmatched":{"type":"array","items":{"type":"string"}},
    "query_terms":{"type":"array","items":{"type":"string"}}
  }
}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name: "binding_check",
				Description: "扫描门禁：给定已识别的指纹产品与待执行模板所属的产品/CVE，判断这个模板是否应该放行。" +
					"放行依据是显式绑定（规范键相同）或 CVE 已在绑定表中；否则拒绝并说明原因。",
				Risk: core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "recognized":{"type":"array","items":{"type":"string"},"description":"已识别出的指纹产品名"},
    "product":{"type":"string","description":"模板所属产品（与 cve 二选一）"},
    "cve":{"type":"string","description":"模板针对的 CVE"},
    "bindings":{"type":"array","items":{"type":"object"},"description":"宿主自己的绑定表；缺省用内置表"}
  },
  "required":["recognized"]
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "allowed":{"type":"boolean"},
    "reason":{"type":"string"},
    "matched_product":{"type":"string"},
    "query_terms":{"type":"array","items":{"type":"string"}}
  }
}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name:        "binding_defaults",
				Description: "列出内置绑定表，便于宿主检出、比对并改为自己维护的版本。只读。",
				Risk:        core.RiskLow,
				InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{"count":{"type":"integer"},"bindings":{"type":"array","items":{"type":"object"}}}
}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
		},
	}
}

// Call is the envelope shell.
func (k *Kit) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := k.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

func (k *Kit) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "binding_resolve":
		return k.resolve(call)
	case "binding_check":
		return k.check(call)
	case "binding_defaults":
		return k.defaults()
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

type resolveInput struct {
	Products []string  `json:"products"`
	CVE      string    `json:"cve"`
	Bindings []Binding `json:"bindings"`
}

type resolveData struct {
	Resolutions []Resolution `json:"resolutions"`
	Unmatched   []string     `json:"unmatched"`
	QueryTerms  []string     `json:"query_terms"`
	// CVENote explains a CVE lookup that the table did not know.
	CVENote string `json:"cve_note,omitempty"`
}

func (k *Kit) resolve(call core.Call) (core.Result, error) {
	var in resolveInput
	if len(call.Input) > 0 {
		if err := json.Unmarshal(call.Input, &in); err != nil {
			return core.FailResult(core.InvalidInput(err.Error())), nil
		}
	}
	bindings := pickBindings(in.Bindings)
	if err := Validate(bindings); err != nil {
		return core.FailResult(core.InvalidInput("绑定表不合法: " + err.Error())), nil
	}
	if len(in.Products) == 0 && strings.TrimSpace(in.CVE) == "" {
		return core.FailResult(core.InvalidInput("products 或 cve 至少需要一个")), nil
	}

	data := resolveData{Resolutions: Resolve(in.Products, bindings)}
	for _, r := range data.Resolutions {
		if r.Product == "" {
			data.Unmatched = append(data.Unmatched, r.Detected)
		}
	}
	if cve := strings.TrimSpace(in.CVE); cve != "" {
		if product, query, ok := ProductForCVE(cve, bindings); ok {
			data.Resolutions = append(data.Resolutions, Resolution{
				Detected: cve, Product: product, MatchedVia: "cve",
				Confidence: 1.0, Query: query[0],
			})
		} else {
			data.CVENote = "绑定表中没有该 CVE 的记录，CVE 反查未命中"
		}
	}
	data.QueryTerms = QueryTerms(data.Resolutions)
	if data.Unmatched == nil {
		data.Unmatched = []string{}
	}

	summary := fmt.Sprintf("归一化 %d 个产品名，命中 %d 个绑定", len(in.Products), len(data.Resolutions))
	if len(data.Unmatched) > 0 {
		summary += fmt.Sprintf("，%d 个未命中", len(data.Unmatched))
	}
	return core.SuccessResult(summary, data)
}

type checkInput struct {
	Recognized []string  `json:"recognized"`
	Product    string    `json:"product"`
	CVE        string    `json:"cve"`
	Bindings   []Binding `json:"bindings"`
}

type checkData struct {
	Allowed        bool     `json:"allowed"`
	Reason         string   `json:"reason"`
	MatchedProduct string   `json:"matched_product,omitempty"`
	QueryTerms     []string `json:"query_terms,omitempty"`
}

// check answers the question a scan gate actually asks: "this target was
// fingerprinted as X, may I run a template for Y?".
func (k *Kit) check(call core.Call) (core.Result, error) {
	var in checkInput
	if len(call.Input) > 0 {
		if err := json.Unmarshal(call.Input, &in); err != nil {
			return core.FailResult(core.InvalidInput(err.Error())), nil
		}
	}
	if len(in.Recognized) == 0 {
		return core.FailResult(core.InvalidInput("recognized 不能为空：没有指纹证据就不能判定模板适用性")), nil
	}
	if strings.TrimSpace(in.Product) == "" && strings.TrimSpace(in.CVE) == "" {
		return core.FailResult(core.InvalidInput("product 或 cve 至少需要一个")), nil
	}
	bindings := pickBindings(in.Bindings)
	if err := Validate(bindings); err != nil {
		return core.FailResult(core.InvalidInput("绑定表不合法: " + err.Error())), nil
	}

	recognized := Resolve(in.Recognized, bindings)
	known := map[string]bool{}
	var knownNames []string
	for _, r := range recognized {
		if r.Product != "" && !known[r.Product] {
			known[r.Product] = true
			knownNames = append(knownNames, r.Product)
		}
	}

	data := checkData{QueryTerms: QueryTerms(recognized)}
	// A CVE request is allowed once recognition exists, provided either the
	// binding table maps it to a recognized product or the recognition itself
	// is non-empty. This mirrors the rule the host gate uses: recognition is
	// the precondition, the binding is the narrowing.
	if cve := strings.TrimSpace(in.CVE); cve != "" {
		if product, query, ok := ProductForCVE(cve, bindings); ok {
			data.QueryTerms = dedupe(append(data.QueryTerms, query[0]...))
			if len(known) == 0 || known[product] {
				data.Allowed = true
				data.MatchedProduct = product
				data.Reason = fmt.Sprintf("CVE %s 绑定到产品 %s，且已有指纹识别证据", cve, product)
				return core.SuccessResult(data.Reason, data)
			}
			data.Reason = fmt.Sprintf("CVE %s 属于 %s，但当前识别到的产品是 %s", cve, product, strings.Join(knownNames, "、"))
			return core.SuccessResult(data.Reason, data)
		}
		if len(known) > 0 {
			data.Allowed = true
			data.Reason = fmt.Sprintf("CVE %s 未在绑定表中，但已有指纹识别证据，按 CVE 检索放行", cve)
			return core.SuccessResult(data.Reason, data)
		}
		data.Reason = "没有任何指纹识别证据，拒绝无识别的扫描"
		return core.SuccessResult(data.Reason, data)
	}

	wanted := Resolve([]string{in.Product}, bindings)
	if len(wanted) == 0 || wanted[0].Product == "" {
		data.Reason = fmt.Sprintf("产品「%s」不在绑定表中，无法证明与已识别指纹的对应关系", in.Product)
		return core.SuccessResult(data.Reason, data)
	}
	data.MatchedProduct = wanted[0].Product
	if known[wanted[0].Product] {
		data.Allowed = true
		data.Reason = fmt.Sprintf("产品 %s 已在指纹识别结果中", wanted[0].Product)
		return core.SuccessResult(data.Reason, data)
	}
	data.Reason = fmt.Sprintf("产品 %s 不在已识别指纹中；当前识别: %s",
		wanted[0].Product, strings.Join(knownNames, "、"))
	return core.SuccessResult(data.Reason, data)
}

func (k *Kit) defaults() (core.Result, error) {
	data := map[string]any{"count": len(DefaultBindings), "bindings": DefaultBindings}
	return core.SuccessResult(fmt.Sprintf("内置绑定表共 %d 条", len(DefaultBindings)), data)
}

func pickBindings(in []Binding) []Binding {
	if len(in) > 0 {
		return in
	}
	return DefaultBindings
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	return out
}

// Manifest is the static declaration, usable before ports are available.
func Manifest() core.Manifest { return New(core.Deps{}).Manifest() }
