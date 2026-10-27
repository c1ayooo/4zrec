package poc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// kitVersion is stamped into every Result envelope.
const kitVersion = "0.1.0"

// Kit turns one advisory into three reviewable artifacts: a structured
// analysis with a runnable verification PoC, a nuclei detection template and
// an asset fingerprint rule.
//
// Nothing here writes a library: every tool returns a draft, and the only
// write tool (poc_publish) stores the artifact the caller explicitly handed
// back. A model hallucinating a matcher must never reach the scan library on
// its own — that is what the two-step contract is for.
type Kit struct {
	completer core.Completer
	artifacts core.ArtifactStore
}

// New wires the capability. A nil Completer leaves every generation tool
// reporting "unavailable"; publishing still works, because it does not need
// the model.
func New(deps core.Deps) *Kit {
	return &Kit{completer: deps.Completer, artifacts: deps.Artifacts}
}

// NewCapability implements the capability constructor used by the registry.
func NewCapability(deps core.Deps) (core.Capability, error) { return New(deps), nil }

// Manifest declares the generation toolkit.
func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "pockit", Version: kitVersion, APIVersion: "v1",
		Requires: []string{"completer", "artifact"},
		Tools: []core.ToolSpec{
			{
				Name: "poc_generate",
				Description: "把一条漏洞情报整理成结构化中文分析：中文标题/简介、漏洞原理、攻击范围与可运行的验证 PoC。" +
					"PoC 由模型填要素（入口/参数/判定特征）、代码确定性拼装，要素在情报里找不到出处的直接不产出脚本（poc 为 null 并在 poc_note 说明原因），" +
					"不臆造厂商/版本/路径，只做无损验证性请求。单次模型调用可能耗时数十秒，可加 \"async\": true 后用 job_status 轮询。",
				Risk: core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "title":{"type":"string"},
    "description":{"type":"string"},
    "severity":{"type":"string"},
    "cve":{"type":"string"},
    "tags":{"type":"array","items":{"type":"string"}},
    "affected":{"type":"array","items":{"type":"string"}},
    "solutions":{"type":"string"},
    "github_poc":{"type":"array","items":{"type":"string"},"description":"已知公开 PoC 仓库链接"}
  },
  "required":["title"]
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "title_zh":{"type":"string"},"description_zh":{"type":"string"},
    "principle":{"type":"string"},"attack_scope":{"type":"string"},
    "poc":{"type":["object","null"],"properties":{
      "language":{"type":"string"},"code":{"type":"string"},
      "spec":{"type":"object","description":"拼装脚本所用的验证要素"}}},
    "poc_origin":{"type":"string","enum":["ai","upstream","none"]},
    "poc_note":{"type":"string","description":"未产出脚本时的原因，或参数需人工核对等提示"}
  }
}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name: "poc_template_draft",
				Description: "为一条漏洞情报生成 nuclei v3 检测模板**草稿**（不写模板库）。骨架由代码确定生成，模型只补请求路径这类指标；" +
					"情报缺少可匹配特征时直接报错，宁可不产出也不生成匹配任意响应的噪音模板。",
				Risk: core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "title":{"type":"string"},
    "description":{"type":"string","description":"情报描述；已做过分析时传 principle 效果最好"},
    "severity":{"type":"string"},
    "cve":{"type":"string"},
    "tags":{"type":"array","items":{"type":"string"}},
    "affected":{"type":"array","items":{"type":"string"}},
    "analysis":{"type":"object","properties":{
      "principle":{"type":"string"},"description_zh":{"type":"string"}},
      "description":"已生成的分析产物，避免重复消耗模型调用"}
  },
  "required":["title"]
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "template_id":{"type":"string"},"yaml":{"type":"string"},
    "matcher_summary":{"type":"string"},
    "notes":{"type":"array","items":{"type":"string"}},
    "warnings":{"type":"array","items":{"type":"string"}}
  }
}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name: "poc_fingerprint_draft",
				Description: "为一条漏洞情报生成**资产指纹规则草稿**（不写指纹库）：识别「这台机器装的是不是受影响产品」。" +
					"只能使用情报里已有的字样作为特征，缺少可区分特征时报错而不是产出万金油规则。",
				Risk: core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "title":{"type":"string"},
    "description":{"type":"string"},
    "severity":{"type":"string"},
    "cve":{"type":"string"},
    "tags":{"type":"array","items":{"type":"string"}}
  },
  "required":["title"]
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "name":{"type":"string"},"product":{"type":"string"},"category":{"type":"string"},
    "patterns":{"type":"array","items":{"type":"object","properties":{
      "type":{"type":"string"},"part":{"type":"string"},"value":{"type":"string"},"regex":{"type":"boolean"}}}},
    "reason":{"type":"string"},
    "fingerprint_id":{"type":"string"},
    "warnings":{"type":"array","items":{"type":"string"}}
  }
}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name: "poc_script_build",
				Description: "由「验证要素」确定性拼装验证脚本，不调用模型：人工核对或修改 poc_generate 返回的要素后用它重建，" +
					"既省一次模型调用，也保证重建与首次生成走同一套接地校验（入口路径与响应特征必须能在情报原文里找到出处）。",
				Risk: core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "title":{"type":"string"},
    "description":{"type":"string"},
    "severity":{"type":"string"},
    "cve":{"type":"string"},
    "tags":{"type":"array","items":{"type":"string"}},
    "affected":{"type":"array","items":{"type":"string"}},
    "solutions":{"type":"string"},
    "spec":{"type":"object","description":"poc_generate 返回的验证要素，可先人工修改"}
  },
  "required":["title","spec"]
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "poc":{"type":"object","properties":{"language":{"type":"string"},"code":{"type":"string"}}},
    "poc_note":{"type":"string"}
  }
}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name: "poc_publish",
				Description: "确认入库：把一份已复核的草稿写进宿主的产物库（模板 YAML 或指纹规则 JSON），返回落点路径。" +
					"写入的是会被扫描链路直接使用的库，属于高风险动作，运行时会走审批门禁。",
				Risk: core.RiskHigh,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "kind":{"type":"string","enum":["nuclei_template","fingerprint"]},
    "id":{"type":"string","description":"产物 id；缺省时从内容推导"},
    "content":{"type":"string","description":"草稿正文：模板为 YAML，指纹为 JSON"}
  },
  "required":["kind","content"]
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{"path":{"type":"string"},"id":{"type":"string"},"kind":{"type":"string"}}
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
	case "poc_generate":
		return k.generate(ctx, call)
	case "poc_template_draft":
		return k.templateDraft(ctx, call)
	case "poc_fingerprint_draft":
		return k.fingerprintDraft(ctx, call)
	case "poc_script_build":
		return k.scriptBuild(ctx, call)
	case "poc_publish":
		return k.publish(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) generate(ctx context.Context, call core.Call) (core.Result, error) {
	in, err := decodeInput(call)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	a, err := k.generateAnalysis(ctx, in)
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	summary := fmt.Sprintf("已生成分析：%s（PoC 来源 %s）", orDash(a.TitleZh), a.POCOrigin)
	return core.SuccessResult(summary, a)
}

func (k *Kit) templateDraft(ctx context.Context, call core.Call) (core.Result, error) {
	in, err := decodeInput(call)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	cve := normalizeCVE(in.CVE, in.Title, in.Description, strings.Join(in.Tags, " "))
	words := matcherWords(in, cve)
	if len(words) == 0 {
		return core.FailResult(core.InvalidInput(
			"情报缺少可用于匹配的特征（CVE / 组件名 / 具体标签），无法生成可靠模板")), nil
	}

	// The model only suggests where to probe; failure keeps the skeleton with
	// a "/" path rather than blocking the draft.
	method, path := "GET", "/"
	principle := strings.TrimSpace(in.Description)
	ind, indErr := k.suggestIndicators(ctx, in, principle)
	if indErr == nil {
		if p := strings.TrimSpace(ind.Path); strings.HasPrefix(p, "/") {
			path = p
		}
		if m := strings.ToUpper(strings.TrimSpace(ind.Method)); m == "GET" || m == "POST" {
			method = m
		}
	} else if k.completer != nil {
		// A configured model that failed is worth surfacing, but it must not
		// turn into a failed draft: the skeleton is still valid.
		// (Logged through the result's warnings below.)
	}
	draft, err := buildTemplate(in, cve, method, path, words, templateDescription(in, principle))
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	if indErr != nil {
		draft.Notes = append(draft.Notes, "模型未能给出探测路径，模板使用默认路径 / —— 请人工确认后修改")
	}
	summary := fmt.Sprintf("已生成模板草稿 %s（%s %s，%d 个匹配词）", draft.ID, method, path, len(words))
	return core.SuccessResult(summary, draft)
}

func (k *Kit) fingerprintDraft(ctx context.Context, call core.Call) (core.Result, error) {
	in, err := decodeInput(call)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	draft, err := k.suggestFingerprint(ctx, in)
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	draft.Name = strings.TrimSpace(draft.Name)
	draft.Product = strings.TrimSpace(draft.Product)
	draft.Category = strings.TrimSpace(draft.Category)
	if draft.Category == "" {
		draft.Category = "other"
	}
	if draft.Product == "" {
		draft.Product = draft.Name
	}
	if len(draft.Patterns) == 0 {
		return core.FailResult(core.InvalidInput(
			"情报中没有可用于区分产品的特征，未生成指纹草稿")), nil
	}
	if err := ValidateFingerprintDraft(draft); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	id := fingerprintID(draft.Name)
	body, err := MarshalFingerprint(draft)
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	out := map[string]any{
		"name": draft.Name, "product": draft.Product, "category": draft.Category,
		"patterns": draft.Patterns, "reason": draft.Reason,
		"fingerprint_id": id,
		"json":           string(body),
		"warnings": []string{
			"指纹决定资产归类，写错会让整个资产的判定跟着错；确认前请人工核对其中的特征字样",
			"规则不会自动入库：确认后再由调用方写入指纹规则库",
		},
	}
	summary := fmt.Sprintf("已生成指纹草稿 %s（%d 个匹配项）", draft.Name, len(draft.Patterns))
	return core.SuccessResult(summary, out)
}

// scriptBuild re-assembles the script from elements the caller may have
// edited. It calls no model and touches no target: the same grounding rules
// that guard first generation guard the rebuild, so an element that was
// "fixed" into something the advisory never said is refused here too.
func (k *Kit) scriptBuild(_ context.Context, call core.Call) (core.Result, error) {
	var wrapper struct {
		IntelInput
		Spec *PoCSpec `json:"spec"`
	}
	if len(call.Input) > 0 {
		if err := json.Unmarshal(call.Input, &wrapper); err != nil {
			return core.FailResult(core.InvalidInput(err.Error())), nil
		}
	}
	in := wrapper.IntelInput
	if strings.TrimSpace(in.Title) == "" && strings.TrimSpace(in.CVE) == "" {
		return core.FailResult(core.InvalidInput("title 或 cve 至少需要一个（用于校验要素是否有出处）")), nil
	}
	if wrapper.Spec == nil {
		return core.FailResult(core.InvalidInput("spec 必填")), nil
	}
	code, note, err := buildPoCScript(in, intelCorpus(in), *wrapper.Spec)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	poc := POC{Language: "python", Code: code, Spec: wrapper.Spec}
	summary := fmt.Sprintf("已按验证要素拼装脚本（%s %s，%d 个参数）",
		strings.ToUpper(strings.TrimSpace(wrapper.Spec.Method)), strings.TrimSpace(wrapper.Spec.Path), len(wrapper.Spec.Params))
	return core.SuccessResult(summary, map[string]any{"poc": poc, "poc_note": note})
}

type publishInput struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Content string `json:"content"`
}

// publish is the human-confirmed write. It re-validates the artifact instead
// of trusting the caller: the draft may have been edited between generation
// and confirmation, and the scan library must only ever contain artifacts
// this kit would have produced.
func (k *Kit) publish(ctx context.Context, call core.Call) (core.Result, error) {
	if k.artifacts == nil {
		return core.FailResult(core.Unavailable("宿主未配置产物库端口，无法入库")), nil
	}
	var in publishInput
	if len(call.Input) > 0 {
		if err := json.Unmarshal(call.Input, &in); err != nil {
			return core.FailResult(core.InvalidInput(err.Error())), nil
		}
	}
	if len(in.Content) == 0 {
		return core.FailResult(core.InvalidInput("content 必填")), nil
	}
	var (
		id    string
		name  string
		outID string
	)
	switch strings.ToLower(strings.TrimSpace(in.Kind)) {
	case "nuclei_template":
		if err := ValidateTemplateYAML(in.Content); err != nil {
			return core.FailResult(core.InvalidInput(err.Error())), nil
		}
		parsed, perr := templateIDFromYAML(in.Content)
		if perr != nil {
			return core.FailResult(core.InvalidInput(perr.Error())), nil
		}
		id = "intel-drafts/templates/" + parsed + ".yaml"
		name = "nuclei 模板"
		outID = parsed
	case "fingerprint":
		var draft FingerprintDraft
		// The caller may hand the pretty JSON this kit produced, or a raw
		// draft object; both decode the same way.
		raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(in.Content))
		payload := in.Content
		if derr == nil && looksLikeBase64JSON(raw) {
			payload = string(raw)
		}
		if err := json.Unmarshal([]byte(payload), &draft); err != nil {
			return core.FailResult(core.InvalidInput("指纹草稿不是合法 JSON: " + err.Error())), nil
		}
		if err := ValidateFingerprintDraft(draft); err != nil {
			return core.FailResult(core.InvalidInput(err.Error())), nil
		}
		if strings.TrimSpace(in.ID) != "" {
			outID = strings.TrimSpace(in.ID)
		} else {
			outID = fingerprintID(draft.Name)
		}
		id = "intel-drafts/fingerprints/" + outID + ".json"
		name = "指纹规则"
	default:
		return core.FailResult(core.InvalidInput("kind 必须是 nuclei_template 或 fingerprint")), nil
	}
	path, err := k.artifacts.Put(ctx, id, []byte(in.Content))
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	return core.SuccessResult(fmt.Sprintf("%s %s 已入库：%s", name, outID, path), map[string]any{
		"path": path, "id": outID, "kind": in.Kind,
	})
}

func templateIDFromYAML(text string) (string, error) {
	var doc templateDoc
	if err := yamlUnmarshal([]byte(text), &doc); err != nil {
		return "", fmt.Errorf("模板不是合法 YAML: %w", err)
	}
	if !reTemplateID.MatchString(doc.ID) {
		return "", fmt.Errorf("模板 id 非法: %q", doc.ID)
	}
	return doc.ID, nil
}

// looksLikeBase64JSON reports whether decoded bytes start like a JSON object.
func looksLikeBase64JSON(raw []byte) bool {
	trimmed := strings.TrimLeft(string(raw), " \t\r\n")
	return strings.HasPrefix(trimmed, "{")
}

func templateDescription(in IntelInput, principle string) string {
	var b strings.Builder
	write := func(label, s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(label)
		b.WriteString(s)
	}
	write("", in.Description)
	write("处置建议：", in.Solutions)
	if b.Len() > 0 {
		b.WriteString("\n\n")
	}
	b.WriteString("由 capkit 情报流水线自动生成，matcher 需人工复核后再用于正式扫描。")
	return b.String()
}

// Manifest is the static declaration, usable before ports are available.
func Manifest() core.Manifest { return New(core.Deps{}).Manifest() }
