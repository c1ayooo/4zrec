package poc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// scriptedCompleter answers by matching a marker in the system prompt, so one
// fake can serve the analysis, indicator and fingerprint calls of a single
// tool invocation.
type scriptedCompleter struct {
	analysisReply    string
	indicatorReply   string
	fingerprintReply string
	err              error
	calls            int
}

func (c *scriptedCompleter) Complete(_ context.Context, system, _ string, _ int) (string, error) {
	c.calls++
	if c.err != nil {
		return "", c.err
	}
	switch {
	case strings.Contains(system, "漏洞分析专家"):
		return c.analysisReply, nil
	case strings.Contains(system, "nuclei 模板工程师"):
		return c.indicatorReply, nil
	case strings.Contains(system, "资产指纹专家"):
		return c.fingerprintReply, nil
	default:
		return "{}", nil
	}
}

type memArtifacts struct {
	put  map[string]string
	fail bool
}

func (m *memArtifacts) Put(_ context.Context, name string, data []byte) (string, error) {
	if m.fail {
		return "", core.Unavailable("artifact store offline")
	}
	if m.put == nil {
		m.put = map[string]string{}
	}
	m.put[name] = string(data)
	return "/artifacts/" + name, nil
}

func (m *memArtifacts) Get(_ context.Context, path string) ([]byte, error) {
	if v, ok := m.put[strings.TrimPrefix(path, "/artifacts/")]; ok {
		return []byte(v), nil
	}
	return nil, core.NotFound("not found")
}

func (m *memArtifacts) Delete(_ context.Context, path string) error { return nil }

const analysisReply = `好的，结果如下：
{
  "title_zh": "Apache Struts2 远程代码执行漏洞",
  "description_zh": "攻击者可通过构造 OGNL 表达式在目标服务器执行任意代码。",
  "principle": "文件上传逻辑未限制参数名，OGNL 表达式被当作参数名解析并执行。",
  "attack_scope": "Struts 2.0.0 - 2.3.37 等受影响版本。",
  "poc_spec": {
    "constructible": true,
    "method": "POST",
    "path": "/upload.action",
    "params": [{"name": "OGNL", "value": "test"}],
    "body_format": "form",
    "marker": "OGNL",
    "match_status": 0,
    "evidence": "上传接口把参数名当作 OGNL 表达式解析"
  }
}`

const indicatorReply = `{"method":"POST","path":"/upload.action","words":["Struts2"],"regex":[]}`

const distinctiveFingerprintReply = `{
  "name": "Apache Struts2",
  "product": "Struts2",
  "category": "framework",
  "patterns": [
    {"type": "header", "part": "Server", "value": "Servlet/JSP"},
    {"type": "body", "value": "struts-tags"}
  ],
  "reason": "情报标题与标签中出现了 Struts2 与 struts-tags 字样"
}`

const genericFingerprintReply = `{
  "name": "Web App",
  "category": "other",
  "patterns": [{"type": "body", "value": "html"}, {"type": "title", "value": "login"}],
  "reason": "没有拿到可区分的特征"
}`

func intelInputJSON(t *testing.T, extra map[string]any) json.RawMessage {
	t.Helper()
	in := map[string]any{
		"title":       "Apache Struts2 RCE (CVE-2024-53677)",
		"description": "Struts2 file upload OGNL injection on /upload.action leading to remote code execution.",
		"severity":    "critical",
		"cve":         "CVE-2024-53677",
		"tags":        []string{"Struts2", "OGNL"},
		"affected":    []string{"maven/org.apache.struts:struts2-core"},
	}
	for k, v := range extra {
		in[k] = v
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	return raw
}

// TestGenerateReturnsAnalysisWithAIOwnedPoC pins the PoC provenance rule and
// the division of labour: the model supplied elements, code supplied the
// script, and the origin is "ai" because code exists.
func TestGenerateReturnsAnalysisWithAIOwnedPoC(t *testing.T) {
	cap, err := NewCapability(core.Deps{
		Completer: &scriptedCompleter{analysisReply: analysisReply},
		Artifacts: &memArtifacts{},
	})
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_generate", Input: intelInputJSON(t, nil)})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q err=%+v", res.Status, res.Summary, res.Error)
	}
	var a Analysis
	if err := json.Unmarshal(res.Data, &a); err != nil {
		t.Fatalf("data: %v", err)
	}
	if a.POCOrigin != pocOriginAI {
		t.Fatalf("poc_origin = %q, want ai", a.POCOrigin)
	}
	if a.TitleZh == "" || a.Principle == "" {
		t.Fatalf("analysis is missing fields: %+v", a)
	}
	if a.POC == nil {
		t.Fatalf("PoC should be assembled from the elements, note=%q", a.POCNote)
	}
	for _, want := range []string{
		"PATH = \"/upload.action\"",
		"METHOD = \"POST\"",
		"\"OGNL\": \"test\"",
		"EXPECT_WORDS = [\"OGNL\"]",
		"urllib.request.urlopen",
	} {
		if !strings.Contains(a.POC.Code, want) {
			t.Fatalf("script missing %q:\n%s", want, a.POC.Code)
		}
	}
	if a.POC.Spec == nil || a.POC.Spec.Path != "/upload.action" {
		t.Fatalf("the spec the script was built from should be echoed back: %+v", a.POC.Spec)
	}
}

// TestGenerateRefusesInventedPath pins the anti-hallucination rule: a path that
// the advisory never mentions cannot produce a script, because it would 404
// and prove nothing.
func TestGenerateRefusesInventedPath(t *testing.T) {
	reply := `{"title_zh":"x","principle":"文件上传 OGNL 注入","poc_spec":{
	  "constructible":true,"method":"POST","path":"/api/v9/secret-upload",
	  "params":[{"name":"OGNL","value":"test"}],"marker":"OGNL"}}`
	cap, _ := NewCapability(core.Deps{Completer: &scriptedCompleter{analysisReply: reply}, Artifacts: &memArtifacts{}})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_generate", Input: intelInputJSON(t, nil)})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("analysis itself succeeded, status = %q", res.Status)
	}
	var a Analysis
	_ = json.Unmarshal(res.Data, &a)
	if a.POC != nil {
		t.Fatalf("an ungrounded path must not yield a script:\n%s", a.POC.Code)
	}
	if a.POCOrigin != pocOriginNone {
		t.Fatalf("poc_origin = %q, want none", a.POCOrigin)
	}
	if !strings.Contains(a.POCNote, "找不到出处") {
		t.Fatalf("poc_note should say why: %q", a.POCNote)
	}
}

// TestGenerateRefusesWithoutVerdict pins that a request with no marker and no
// expected status is not a verification: it cannot say "vulnerable" or
// "not vulnerable".
func TestGenerateRefusesWithoutVerdict(t *testing.T) {
	reply := `{"title_zh":"x","principle":"文件上传 OGNL 注入","poc_spec":{
	  "constructible":true,"method":"GET","path":"/upload.action",
	  "params":[{"name":"OGNL","value":"test"}]}}`
	cap, _ := NewCapability(core.Deps{Completer: &scriptedCompleter{analysisReply: reply}, Artifacts: &memArtifacts{}})
	res, _ := cap.Call(context.Background(), core.Call{Tool: "poc_generate", Input: intelInputJSON(t, nil)})
	var a Analysis
	_ = json.Unmarshal(res.Data, &a)
	if a.POC != nil {
		t.Fatalf("no marker and no status must not yield a script:\n%s", a.POC.Code)
	}
	if !strings.Contains(a.POCNote, "判定") {
		t.Fatalf("poc_note should mention the missing verdict: %q", a.POCNote)
	}
}

// TestGenerateHonoursNotConstructible pins that the model's own "I cannot
// build this" is respected instead of being second-guessed into a script.
func TestGenerateHonoursNotConstructible(t *testing.T) {
	reply := `{"title_zh":"x","principle":"某组件存在缺陷","poc_spec":{
	  "constructible":false,"reason":"通告没有给出任何入口路径"}}`
	cap, _ := NewCapability(core.Deps{Completer: &scriptedCompleter{analysisReply: reply}, Artifacts: &memArtifacts{}})
	res, _ := cap.Call(context.Background(), core.Call{Tool: "poc_generate", Input: intelInputJSON(t, nil)})
	var a Analysis
	_ = json.Unmarshal(res.Data, &a)
	if a.POC != nil {
		t.Fatal("no script may be produced")
	}
	if a.POCNote != "通告没有给出任何入口路径" {
		t.Fatalf("poc_note = %q", a.POCNote)
	}
}

// TestGenerateMarksUpstreamPoCWhenSourceHasNoCode pins that a public exploit
// repo suppresses generated code rather than inventing it.
func TestGenerateMarksUpstreamPoCWhenSourceHasNoCode(t *testing.T) {
	cap, _ := NewCapability(core.Deps{
		Completer: &scriptedCompleter{analysisReply: `{"title_zh":"x","principle":"p","poc_spec":{"constructible":false,"reason":"通告未给入口"}}`},
		Artifacts: &memArtifacts{},
	})
	in := intelInputJSON(t, map[string]any{"github_poc": []string{"https://github.com/example/poc"}})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_generate", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var a Analysis
	_ = json.Unmarshal(res.Data, &a)
	if a.POCOrigin != pocOriginUpstream {
		t.Fatalf("poc_origin = %q, want upstream", a.POCOrigin)
	}
	if a.POC != nil {
		t.Fatal("no code should be generated when the source only links a repo")
	}
}

// TestGenerateWithoutModelIsUnavailable pins the dependency contract.
func TestGenerateWithoutModelIsUnavailable(t *testing.T) {
	cap, _ := NewCapability(core.Deps{Artifacts: &memArtifacts{}})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_generate", Input: intelInputJSON(t, nil)})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusUnavailable {
		t.Fatalf("status = %q, want unavailable", res.Status)
	}
}

// TestTemplateDraftIsCodeOwnedAndNeverPublished pins the two things that make
// the template path safe: the structure comes from code (id, severity,
// matcher shape) and the tool writes nothing.
func TestTemplateDraftIsCodeOwnedAndNeverPublished(t *testing.T) {
	store := &memArtifacts{}
	cap, _ := NewCapability(core.Deps{
		Completer: &scriptedCompleter{indicatorReply: indicatorReply},
		Artifacts: store,
	})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_template_draft", Input: intelInputJSON(t, nil)})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q err=%+v", res.Status, res.Summary, res.Error)
	}
	var draft TemplateDraft
	if err := json.Unmarshal(res.Data, &draft); err != nil {
		t.Fatalf("data: %v", err)
	}
	if draft.ID != "capkit-cve-2024-53677" {
		t.Fatalf("template id = %q", draft.ID)
	}
	for _, want := range []string{
		"id: " + draft.ID,
		"author: capkit",
		"severity: critical",
		"cve-id: CVE-2024-53677",
		"CVE-2024-53677",
		"path:",
	} {
		if !strings.Contains(draft.YAML, want) {
			t.Fatalf("yaml missing %q:\n%s", want, draft.YAML)
		}
	}
	if !strings.Contains(draft.YAML, "struts2-core") {
		t.Fatalf("affected package should feed the matcher:\n%s", draft.YAML)
	}
	if len(store.put) != 0 {
		t.Fatalf("drafting must not write to the artifact store, got %v", store.put)
	}
}

// TestTemplateDraftRefusesWithoutMatchFeatures pins the "no noisy template"
// rule: an advisory with nothing distinctive produces an error, not a
// template that matches every response.
func TestTemplateDraftRefusesWithoutMatchFeatures(t *testing.T) {
	cap, _ := NewCapability(core.Deps{
		Completer: &scriptedCompleter{indicatorReply: indicatorReply},
		Artifacts: &memArtifacts{},
	})
	raw, _ := json.Marshal(map[string]any{"title": "Some 漏洞 x", "severity": "high"})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_template_draft", Input: raw})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("error = %+v, want bad_input", res.Error)
	}
}

// TestFingerprintDraftAcceptsDistinctiveRule pins the happy path and the id
// derived from the product name.
func TestFingerprintDraftAcceptsDistinctiveRule(t *testing.T) {
	cap, _ := NewCapability(core.Deps{
		Completer: &scriptedCompleter{fingerprintReply: distinctiveFingerprintReply},
		Artifacts: &memArtifacts{},
	})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_fingerprint_draft", Input: intelInputJSON(t, nil)})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q err=%+v", res.Status, res.Summary, res.Error)
	}
	var out struct {
		Name          string               `json:"name"`
		FingerprintID string               `json:"fingerprint_id"`
		Patterns      []FingerprintPattern `json:"patterns"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("data: %v", err)
	}
	if out.FingerprintID != "apache-struts2" {
		t.Fatalf("fingerprint id = %q", out.FingerprintID)
	}
	if len(out.Patterns) != 2 {
		t.Fatalf("patterns = %d, want 2", len(out.Patterns))
	}
}

// TestFingerprintDraftRejectsGenericRule pins that a rule matching nearly
// every site is refused instead of published.
func TestFingerprintDraftRejectsGenericRule(t *testing.T) {
	cap, _ := NewCapability(core.Deps{
		Completer: &scriptedCompleter{fingerprintReply: genericFingerprintReply},
		Artifacts: &memArtifacts{},
	})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_fingerprint_draft", Input: intelInputJSON(t, nil)})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("error = %+v, want bad_input", res.Error)
	}
	if !strings.Contains(res.Summary, "区分度") {
		t.Fatalf("summary should explain the refusal: %q", res.Summary)
	}
}

// TestPublishWritesValidatedArtifact pins the confirmation step: a valid
// draft reaches the artifact store, and its id comes from the template itself.
func TestPublishWritesValidatedArtifact(t *testing.T) {
	store := &memArtifacts{}
	cap, _ := NewCapability(core.Deps{
		Completer: &scriptedCompleter{indicatorReply: indicatorReply},
		Artifacts: store,
	})
	draftRes, _ := cap.Call(context.Background(), core.Call{Tool: "poc_template_draft", Input: intelInputJSON(t, nil)})
	var draft TemplateDraft
	_ = json.Unmarshal(draftRes.Data, &draft)

	in, _ := json.Marshal(map[string]any{"kind": "nuclei_template", "content": draft.YAML})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_publish", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q err=%+v", res.Status, res.Summary, res.Error)
	}
	if _, ok := store.put["intel-drafts/templates/"+draft.ID+".yaml"]; !ok {
		t.Fatalf("artifact store got %v", store.put)
	}
}

// TestPublishRejectsUnvalidatedArtifact pins that confirmation re-validates:
// a hand-edited draft that no longer matches the contract is refused and
// nothing is written.
func TestPublishRejectsUnvalidatedArtifact(t *testing.T) {
	store := &memArtifacts{}
	cap, _ := NewCapability(core.Deps{Artifacts: store})
	in, _ := json.Marshal(map[string]any{"kind": "nuclei_template", "content": "id: Bad ID\nhttp: []\n"})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_publish", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if len(store.put) != 0 {
		t.Fatalf("nothing may be written on a rejected artifact: %v", store.put)
	}
}

// TestPublishFingerprintRejectsGenericDraft pins that the fingerprint
// confirmation runs the same distinctiveness check as generation.
func TestPublishFingerprintRejectsGenericDraft(t *testing.T) {
	store := &memArtifacts{}
	cap, _ := NewCapability(core.Deps{Artifacts: store})
	body, _ := json.Marshal(FingerprintDraft{
		Name:     "Web App",
		Patterns: []FingerprintPattern{{Type: "body", Value: "html"}},
	})
	in, _ := json.Marshal(map[string]any{"kind": "fingerprint", "content": string(body)})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_publish", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if len(store.put) != 0 {
		t.Fatalf("nothing may be written: %v", store.put)
	}
}

// TestUnknownToolPinsNotFound pins the dispatcher contract.
// TestScriptBuildReassemblesWithoutTheModel pins the edit-then-rebuild loop: a
// human fixes an element and gets a new script deterministically, with the
// model untouched — and the grounding rules still apply, so an element edited
// into something the advisory never said is refused just as it would be on
// first generation.
func TestScriptBuildReassemblesWithoutTheModel(t *testing.T) {
	completer := &scriptedCompleter{analysisReply: analysisReply}
	cap, _ := NewCapability(core.Deps{Completer: completer, Artifacts: &memArtifacts{}})
	genRes, _ := cap.Call(context.Background(), core.Call{Tool: "poc_generate", Input: intelInputJSON(t, nil)})
	var a Analysis
	_ = json.Unmarshal(genRes.Data, &a)
	if a.POC == nil || a.POC.Spec == nil {
		t.Fatalf("generate should hand back the spec: %+v", a.POCNote)
	}
	callsAfterGenerate := completer.calls

	spec := *a.POC.Spec
	spec.Params = append(spec.Params, PoCParam{Name: "OGNL", Value: "edited"})
	_ = spec
	in, _ := json.Marshal(map[string]any{
		"title":       "Apache Struts2 RCE (CVE-2024-53677)",
		"description": "Struts2 file upload OGNL injection on /upload.action leading to remote code execution.",
		"cve":         "CVE-2024-53677",
		"spec":        a.POC.Spec,
	})
	res, err := cap.Call(context.Background(), core.Call{Tool: "poc_script_build", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q err=%+v", res.Status, res.Summary, res.Error)
	}
	if completer.calls != callsAfterGenerate {
		t.Fatalf("rebuild must not call the model: calls %d -> %d", callsAfterGenerate, completer.calls)
	}
	var out struct {
		POC POC `json:"poc"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("data: %v", err)
	}
	if out.POC.Code != a.POC.Code {
		t.Fatal("the same elements must rebuild the same script")
	}

	// An element edited into something the advisory never mentions is refused.
	bad, _ := json.Marshal(map[string]any{
		"title": "Apache Struts2 RCE", "cve": "CVE-2024-53677",
		"spec": map[string]any{
			"constructible": true, "method": "POST", "path": "/upload.action",
			"params": []map[string]string{{"name": "OGNL", "value": "x"}},
			"marker": "root:x:0:0",
		},
	})
	res, err = cap.Call(context.Background(), core.Call{Tool: "poc_script_build", Input: bad})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("an ungrounded element must be refused: %q %+v", res.Status, res.Error)
	}
}

// TestScriptBuildRequiresSpec pins the input contract.
func TestScriptBuildRequiresSpec(t *testing.T) {
	cap, _ := NewCapability(core.Deps{Artifacts: &memArtifacts{}})
	res, err := cap.Call(context.Background(), core.Call{
		Tool: "poc_script_build", Input: json.RawMessage(`{"title":"x"}`),
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("status = %q err = %+v, want bad_input", res.Status, res.Error)
	}
}

func TestUnknownToolPinsNotFound(t *testing.T) {
	cap, _ := NewCapability(core.Deps{Artifacts: &memArtifacts{}})
	res, err := cap.Call(context.Background(), core.Call{Tool: "nope"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("error = %+v, want not_found", res.Error)
	}
}
