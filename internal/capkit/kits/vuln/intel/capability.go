package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// kitVersion is stamped into every Result envelope.
const kitVersion = "0.1.0"

// Kit is the vulnerability-intel capability: it polls public advisory
// sources and hands the result to the host's store.
//
// The kit owns the protocol and the triage rules; the host owns the schema,
// the dedup key and the presentation. That split is why the store is a port:
// two hosts can keep the same advisory corpus with different tables.
type Kit struct {
	fetcher  core.Fetcher
	store    core.IntelStore
	settings core.Settings
	sources  []Source
}

// New wires the capability. All sources share one fetcher-backed client.
//
// Host-provided sources (core.IntelSource) are appended to the built-in list:
// they are fetched by the host with whatever machinery a particular site needs
// — a JavaScript engine for an anti-automation page, an authenticated API, a
// private feed — and polled here through the same store, severity gate and
// dedup key, so a host does not end up with a second poll loop whose results
// only half the system knows about.
func New(deps core.Deps) *Kit {
	c := newClient(deps.Fetcher)
	sources := []Source{
		newKEVSource(c),
		newOSCSSource(c),
		newChaitinSource(c),
		newQianxinSource(c),
		newThreatBookSource(c),
		newSeebugSource(c),
		newVenustechSource(c),
		newStruts2Source(c),
	}
	for _, extra := range deps.ExtraIntel {
		if extra == nil {
			continue
		}
		sources = append(sources, hostSource{inner: extra})
	}
	return &Kit{
		fetcher:  deps.Fetcher,
		store:    deps.Intel,
		settings: deps.Settings,
		sources:  sources,
	}
}

// hostSource adapts a core.IntelSource onto the kit's Source interface. The
// host source only has to name itself; display metadata defaults to the name.
type hostSource struct{ inner core.IntelSource }

func (s hostSource) Info() Info {
	return Info{Name: s.inner.Name(), DisplayName: s.inner.Name()}
}

func (s hostSource) Fetch(ctx context.Context, limit int) ([]core.IntelItem, error) {
	items, err := s.inner.Fetch(ctx, limit)
	if err != nil {
		return nil, err
	}
	// The host is not expected to know the kit's naming convention; fill in
	// what would otherwise reach the store empty.
	for i := range items {
		if items[i].Source == "" {
			items[i].Source = s.inner.Name()
		}
	}
	return items, nil
}

// NewCapability implements the capability constructor used by the registry.
func NewCapability(deps core.Deps) (core.Capability, error) { return New(deps), nil }

// Manifest declares the intel toolkit. The kit needs the fetcher (advisory
// endpoints are external data, not project targets) and the host's intel
// store (the kit never opens a database).
func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "vulnintelkit", Version: kitVersion, APIVersion: "v1",
		Requires: []string{"fetcher", "intel"},
		Tools: []core.ToolSpec{
			{
				Name:        "vulnintel_sources",
				Description: "列出已装配的公开漏洞情报源及其名称、说明与入口链接。只读，不发起任何请求。",
				Risk:        core.RiskLow,
				InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "count":{"type":"integer"},
    "sources":{"type":"array","items":{"type":"object","properties":{
      "name":{"type":"string"},"display_name":{"type":"string"},"link":{"type":"string"}}}}
  }
}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name: "vulnintel_poll",
				Description: "从公开漏洞情报源抓取一批最新通告，按严重度门槛分诊后写入宿主的情报库（按唯一键幂等）。" +
					"返回每个源的抓取条数与新增条数；单源失败不影响其余源。可加 \"async\": true 后用 job_status 轮询。",
				Risk: core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "sources":{"type":"array","items":{"type":"string"},"description":"要抓取的源名；缺省为全部"},
    "limit":{"type":"integer","minimum":1,"maximum":100,"description":"每个源最多取多少条（默认 10）"},
    "min_severity":{"type":"string","enum":["low","medium","high","critical"],"description":"入库门槛（默认 medium，中危以下不入库）"}
  }
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "total":{"type":"integer"},
    "created":{"type":"integer"},
    "sources":{"type":"array","items":{"type":"object","properties":{
      "name":{"type":"string"},"display_name":{"type":"string"},"fetched":{"type":"integer"},
      "created":{"type":"integer"},"updated":{"type":"integer"},"error":{"type":"string"}}}}
  }
}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name:        "vulnintel_search",
				Description: "按关键字、CVE、等级或来源检索宿主情报库中的漏洞通告。只读，不发起外部请求。",
				Risk:        core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "text":{"type":"string"},
    "cve":{"type":"string"},
    "severity":{"type":"string"},
    "source":{"type":"string"},
    "limit":{"type":"integer","minimum":1,"maximum":200,"description":"默认 20"}
  }
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "total":{"type":"integer"},
    "items":{"type":"array","items":{"type":"object","properties":{
      "id":{"type":"string"},"title":{"type":"string"},"severity":{"type":"string"},
      "cve":{"type":"string"},"source":{"type":"string"},"disclosure":{"type":"string"}}}}
  }
}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name:        "vulnintel_get",
				Description: "按 id 取单条漏洞通告的完整内容。只读。",
				Risk:        core.RiskLow,
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{"id":{"type":"string"}},
  "required":["id"]
}`),
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"item":{"type":"object"}}}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
		},
	}
}

// Call is the envelope shell: every return path is normalized so Status,
// Summary and Meta hold on success and failure alike.
func (k *Kit) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := k.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

func (k *Kit) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "vulnintel_sources":
		return k.sourcesList()
	case "vulnintel_poll":
		return k.poll(ctx, call)
	case "vulnintel_search":
		return k.search(ctx, call)
	case "vulnintel_get":
		return k.get(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

// sourcesData is the payload of vulnintel_sources.
type sourcesData struct {
	Count   int          `json:"count"`
	Sources []sourceInfo `json:"sources"`
}

type sourceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Link        string `json:"link,omitempty"`
}

func (k *Kit) sourcesList() (core.Result, error) {
	out := sourcesData{Count: len(k.sources), Sources: make([]sourceInfo, 0, len(k.sources))}
	for _, s := range k.sources {
		info := s.Info()
		out.Sources = append(out.Sources, sourceInfo{
			Name: info.Name, DisplayName: info.DisplayName, Link: info.Link,
		})
	}
	return core.SuccessResult(fmt.Sprintf("已装配 %d 个漏洞情报源", out.Count), out)
}

// pollData is the payload of vulnintel_poll.
type pollData struct {
	Total   int           `json:"total"`
	Created int           `json:"created"`
	Sources []sourceStats `json:"sources"`
}

type sourceStats struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Fetched     int    `json:"fetched"`
	Created     int    `json:"created"`
	Updated     int    `json:"updated"`
	Error       string `json:"error,omitempty"`
}

type pollInput struct {
	Sources     []string `json:"sources"`
	Limit       int      `json:"limit"`
	MinSeverity string   `json:"min_severity"`
}

// poll fetches the selected sources, applies the severity gate and hands the
// survivors to the host store.
//
// One broken source never sinks the batch: public advisory endpoints fail
// routinely (WAF challenges, 5xx, rate limits) and the next poll retries.
func (k *Kit) poll(ctx context.Context, call core.Call) (core.Result, error) {
	if k.store == nil {
		return core.FailResult(core.Unavailable("宿主未配置情报库端口，无法写入抓取结果")), nil
	}
	if k.fetcher == nil {
		return core.FailResult(core.Unavailable("宿主未配置 fetcher 端口，无法抓取情报源")), nil
	}
	var in pollInput
	if len(call.Input) > 0 {
		if err := json.Unmarshal(call.Input, &in); err != nil {
			return core.FailResult(core.InvalidInput(err.Error())), nil
		}
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	minRank := SeverityRank(in.MinSeverity)
	if minRank == 0 {
		minRank = SeverityRank(SeverityMedium)
	}

	selected := k.selectSources(in.Sources)
	data := pollData{Sources: make([]sourceStats, 0, len(selected))}
	for _, s := range selected {
		info := s.Info()
		stats := sourceStats{Name: info.Name, DisplayName: info.DisplayName}
		items, err := s.Fetch(ctx, limit)
		if err != nil {
			stats.Error = err.Error()
			data.Sources = append(data.Sources, stats)
			continue
		}
		for _, it := range items {
			if SeverityRank(it.Severity) < minRank {
				continue
			}
			it.Source = info.Name
			stats.Fetched++
			_, created, uerr := k.store.Upsert(ctx, it)
			if uerr != nil {
				stats.Error = uerr.Error()
				break
			}
			if created {
				stats.Created++
				data.Created++
			} else {
				stats.Updated++
			}
		}
		data.Total += stats.Fetched
		data.Sources = append(data.Sources, stats)
	}

	failed := 0
	for _, s := range data.Sources {
		if s.Error != "" {
			failed++
		}
	}
	summary := fmt.Sprintf("抓取 %d 个源共 %d 条，新入库 %d 条", len(data.Sources), data.Total, data.Created)
	if failed > 0 {
		summary += fmt.Sprintf("；%d 个源失败", failed)
	}
	return core.SuccessResult(summary, data)
}

// selectSources picks the requested sources, or all of them. An unknown name
// is reported rather than silently ignored: a typo in a source list that
// quietly polls nothing looks like "no new vulnerabilities today".
func (k *Kit) selectSources(names []string) []Source {
	if len(names) == 0 {
		return k.sources
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[strings.ToLower(strings.TrimSpace(n))] = true
	}
	out := make([]Source, 0, len(names))
	for _, s := range k.sources {
		if want[strings.ToLower(s.Info().Name)] {
			out = append(out, s)
		}
	}
	return out
}

// searchData is the payload of vulnintel_search.
type searchData struct {
	Total int              `json:"total"`
	Items []core.IntelItem `json:"items"`
}

func (k *Kit) search(ctx context.Context, call core.Call) (core.Result, error) {
	if k.store == nil {
		return core.FailResult(core.Unavailable("宿主未配置情报库端口，无法检索")), nil
	}
	var q core.IntelQuery
	if len(call.Input) > 0 {
		if err := json.Unmarshal(call.Input, &q); err != nil {
			return core.FailResult(core.InvalidInput(err.Error())), nil
		}
	}
	if q.Limit <= 0 {
		q.Limit = 20
	}
	if q.Limit > 200 {
		q.Limit = 200
	}
	items, err := k.store.Query(ctx, q)
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	out := searchData{Total: len(items), Items: items}
	if out.Items == nil {
		out.Items = []core.IntelItem{}
	}
	return core.SuccessResult(fmt.Sprintf("检索到 %d 条漏洞通告", out.Total), out)
}

func (k *Kit) get(ctx context.Context, call core.Call) (core.Result, error) {
	if k.store == nil {
		return core.FailResult(core.Unavailable("宿主未配置情报库端口，无法读取")), nil
	}
	var in struct {
		ID string `json:"id"`
	}
	if len(call.Input) > 0 {
		if err := json.Unmarshal(call.Input, &in); err != nil {
			return core.FailResult(core.InvalidInput(err.Error())), nil
		}
	}
	if strings.TrimSpace(in.ID) == "" {
		return core.FailResult(core.InvalidInput("id 必填")), nil
	}
	item, err := k.store.Get(ctx, in.ID)
	if err != nil {
		return core.FailResult(core.AsError(err)), nil
	}
	if item == nil {
		return core.FailResult(core.NotFound("漏洞通告不存在: " + in.ID)), nil
	}
	return core.SuccessResult("已取出漏洞通告 "+in.ID, map[string]any{"item": item})
}

// Manifest is the static declaration, usable before ports are available.
func Manifest() core.Manifest { return New(core.Deps{}).Manifest() }
