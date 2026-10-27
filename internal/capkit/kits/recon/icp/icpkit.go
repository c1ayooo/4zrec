// Package icpkit queries the MIIT (工信部) ICP filing database at
// beian.miit.gov.cn. It is the Go port of the "ICP_Query"/ymicp tool: it
// speaks the undocumented icpproject_query API (auth -> slider captcha ->
// checkImage -> queryByCondition), including the blacklist variants and the
// App/MiniApp/快应用 detail fan-out.
//
// Like oastkit, MIIT is an external data source rather than a project target:
// the kit talks to it through core.Fetcher, so the host still applies proxy,
// timeout, rate limit and audit policy, but not project target scope.
package icp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// kitVersion is the manifest version Normalize stamps into Result.Meta.Version.
const kitVersion = "0.1.0"

// Kit exposes the MIIT beian lookup as a capkit capability.
type Kit struct {
	client   *Client
	evidence core.EvidenceSink
}

// New builds the kit from host ports. It never stores credentials: the MIIT
// API needs none, only a transient token obtained per call.
func New(deps core.Deps) *Kit {
	return &Kit{
		client:   NewClient(deps.Fetcher),
		evidence: deps.Evidence,
	}
}

// NewCapability adapts New to the capkit constructor signature.
func NewCapability(deps core.Deps) (core.Capability, error) {
	if deps.Fetcher == nil {
		return nil, fmt.Errorf("icpkit: 需要 fetcher 端口")
	}
	return New(deps), nil
}

// Client 暴露底层协议客户端，便于宿主注入代理等传输配置。
func (k *Kit) Client() *Client { return k.client }

// Manifest declares the tool surface. MIIT is not a project target, so no tool
// extracts targets; the lookup key is carried in the query result instead.
func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "icpkit", Version: kitVersion, APIVersion: "v1",
		Requires: []string{"fetcher"},
		Tools: []core.ToolSpec{
			mustTool(core.ToolSpec{
				Name: "icp_query",
				Description: "查询工信部 ICP 备案（beian.miit.gov.cn）：按单位名称/域名检索网站、App、小程序、快应用的备案信息，" +
					"或查询黑名单（违法违规）备案。type 取值：web(网站，默认)|app(App)|mapp(小程序)|kapp(快应用)，" +
					"黑名单前缀 b：bweb|bapp|bmapp|bkapp。app/mapp/kapp 会自动并发补齐每条记录的详情。" +
					"同一查询空结果属正常（未备案/关键词无匹配）。",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "query":{"type":"string","description":"查询关键词：域名或单位名称（如 baidu.com / 北京百度网讯科技有限公司）"},
    "type":{"type":"string","description":"web|app|mapp|kapp|bweb|bapp|bmapp|bkapp","enum":["web","app","mapp","kapp","bweb","bapp","bmapp","bkapp"]},
    "page":{"type":"integer","description":"页码（默认 1，黑名单类型忽略）"},
    "size":{"type":"integer","description":"每页条数（默认 10，黑名单类型忽略）"}
  },
  "required":["query"]
}`),
				Risk:           core.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"records":{"type":"array","items":{"type":"object"}}}}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			}),
			mustTool(core.ToolSpec{
				Name:           "icp_types",
				Description:    "列出 icp_query 支持的查询类型（普通备案 / 黑名单）及其含义。",
				InputSchema:    json.RawMessage(`{"type":"object","properties":{}}`),
				Risk:           core.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"types":{"type":"array","items":{"type":"object"}}}}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			}),
		},
	}
}

// mustTool fills a default empty input schema and returns the spec.
func mustTool(t core.ToolSpec) core.ToolSpec {
	if len(t.InputSchema) == 0 {
		t.InputSchema = json.RawMessage(`{"type":"object"}`)
	}
	return t
}

// Call routes one tool invocation. It is a thin envelope shell: dispatch does
// the work, then Normalize completes Status/OK/Meta.Tool/Meta.Version and clamps
// Summary, so every return path — happy or error — carries the same envelope.
func (k *Kit) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := k.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

func (k *Kit) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "icp_query":
		return k.query(ctx, call.Input)
	case "icp_types":
		catalog := TypeCatalog()
		return core.SuccessResult(
			fmt.Sprintf("返回 %d 种 ICP 主体类型", len(catalog)), catalog)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) query(ctx context.Context, input json.RawMessage) (core.Result, error) {
	var in struct {
		Query string `json:"query"`
		Type  string `json:"type"`
		Page  int    `json:"page"`
		Size  int    `json:"size"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return core.FailResult(core.InvalidInput("请求参数不是合法 JSON: " + err.Error())), nil
	}
	name := strings.TrimSpace(in.Query)
	if name == "" {
		return core.FailResult(core.InvalidInput("query 不能为空")), nil
	}
	qtype := strings.ToLower(strings.TrimSpace(in.Type))
	if qtype == "" {
		qtype = TypeWeb
	}
	if !IsSupportedType(qtype) {
		return core.FailResult(core.InvalidInput("不支持的查询类型: " + qtype)), nil
	}

	var (
		raw string
		err error
	)
	if IsBlackType(qtype) {
		raw, err = k.client.QueryBlack(ctx, name, qtype)
	} else {
		page, size := in.Page, in.Size
		if page <= 0 {
			page = 1
		}
		if size <= 0 {
			size = 10
		}
		raw, err = k.client.Query(ctx, name, qtype, page, size)
	}
	if err != nil {
		return core.FailResult(err), nil
	}

	var parsed any
	if uerr := json.Unmarshal([]byte(raw), &parsed); uerr != nil {
		// 上游返回非 JSON（例如网关 HTML），原样透出便于排查。
		return core.FailResult(core.Unavailable("上游响应不是合法 JSON")), nil
	}

	out := map[string]any{
		"query":  name,
		"type":   qtype,
		"result": parsed,
	}
	if n, ok := listLen(parsed); ok {
		out["count"] = n
	}

	res, rerr := core.SuccessResult(summarizeQuery(name, qtype, parsed), out)
	if rerr != nil {
		return core.FailResult(rerr), nil
	}
	if k.evidence != nil {
		if blob, merr := json.Marshal(parsed); merr == nil {
			id, eerr := k.evidence.Record(ctx, core.Evidence{
				Kind:      "icp",
				Title:     fmt.Sprintf("ICP 备案查询 %s (%s)", name, qtype),
				Data:      blob,
				CreatedAt: time.Now(),
				Metadata:  map[string]string{"query": name, "type": qtype},
			})
			if eerr == nil && id != "" {
				res.EvidenceIDs = []string{id}
			}
		}
	}
	return res, nil
}

// listLen reports the length of params.list when the upstream answered with a
// success envelope carrying results.
func listLen(parsed any) (int, bool) {
	root, ok := parsed.(map[string]any)
	if !ok {
		return 0, false
	}
	params, ok := root["params"].(map[string]any)
	if !ok {
		return 0, false
	}
	list, ok := params["list"].([]any)
	if !ok {
		return 0, false
	}
	return len(list), true
}

// summarizeQuery renders the agent-facing Summary for icp_query: what was
// queried, what was found and the key result. The target always comes from the
// caller's query — never a hardcoded domain.
func summarizeQuery(name, qtype string, parsed any) string {
	subject := "ICP 备案"
	if IsBlackType(qtype) {
		subject = "ICP 黑名单备案"
	}
	n, _ := listLen(parsed)
	if n == 0 {
		if IsBlackType(qtype) {
			return fmt.Sprintf("%s 未查到黑名单记录", name)
		}
		return fmt.Sprintf("%s 未查到备案", name)
	}
	unit, no := firstRecordIdentity(parsed)
	switch {
	case unit != "" && no != "":
		return fmt.Sprintf("查询 %s 的 %s：主办单位 %s，备案号 %s", name, subject, unit, no)
	case unit != "":
		return fmt.Sprintf("查询 %s 的 %s：主办单位 %s", name, subject, unit)
	case no != "":
		return fmt.Sprintf("查询 %s 的 %s：备案号 %s", name, subject, no)
	default:
		return fmt.Sprintf("查询 %s 的 %s：返回 %d 条记录", name, subject, n)
	}
}

// firstRecordIdentity pulls the 主办单位 and 备案号 out of the first record, so
// the Summary can name the entity rather than just count rows. Field names vary
// between the list and the App/MiniApp/快应用 detail payloads.
func firstRecordIdentity(parsed any) (unit, no string) {
	root, ok := parsed.(map[string]any)
	if !ok {
		return "", ""
	}
	params, ok := root["params"].(map[string]any)
	if !ok {
		return "", ""
	}
	list, ok := params["list"].([]any)
	if !ok || len(list) == 0 {
		return "", ""
	}
	rec, ok := list[0].(map[string]any)
	if !ok {
		return "", ""
	}
	unit = recordString(rec, "unitName", "unit_name", "companyName", "company")
	no = recordString(rec, "serviceLicence", "mainLicence", "licence", "license", "number")
	return unit, no
}

func recordString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
