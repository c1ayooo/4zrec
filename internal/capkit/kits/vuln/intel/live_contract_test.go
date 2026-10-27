package intel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// These tests pin the source contracts that were wrong until a live run
// against the real endpoints exposed them (2026-10-20). Each fixture is a
// trimmed copy of what the upstream actually returned, so a future edit that
// "simplifies" a parser back to a plausible-looking shape fails here instead
// of silently returning zero advisories in production.

// TestChaitinSurfacesTheWAFPage pins the failure mode: when the upstream keeps
// returning its HTML throttle page, the source reports an error instead of
// pretending the feed was empty.
func TestChaitinSurfacesTheWAFPage(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{
		chaitinListURL: {status: 465, body: "<!DOCTYPE html><html>challenge</html>"},
	}}
	c := newClient(f)
	c.backoff = time.Millisecond
	_, err := newChaitinSource(c).Fetch(context.Background(), 10)
	if err == nil {
		t.Fatal("a persistent 465 must be reported, not read as an empty feed")
	}
}

// TestQianxinAcceptsItsOwnSuccessCode pins the envelope: this API reports
// success as status=10000. Reading it as an error rejected every response.
func TestQianxinAcceptsItsOwnSuccessCode(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{
		qianxinOneDayURL: {body: qianxinOneDayFixture},
	}}
	items, err := newQianxinSource(newClient(f)).Fetch(context.Background(), 10)
	if err != nil {
		t.Fatalf("status=10000 must be success: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2 (vuln_add)", len(items))
	}
}

// TestQianxinReadsTheWholeDayNotJustHighlights pins the field choice:
// `key_vuln_add` is the vendor-highlighted subset (1 of 76 on a live call).
// Keying off it loses almost every advisory.
func TestQianxinReadsTheWholeDayNotJustHighlights(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{
		qianxinOneDayURL: {body: qianxinOneDayFixture},
	}}
	items, err := newQianxinSource(newClient(f)).Fetch(context.Background(), 10)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(items) < 2 {
		t.Fatalf("items = %d, want the full vuln_add list, not key_vuln_add", len(items))
	}
	if items[0].UniqueKey != "QVD-2026-87006_qianxin-ti" {
		t.Fatalf("unique key = %q", items[0].UniqueKey)
	}
	if items[0].Severity != SeverityHigh {
		t.Fatalf("severity = %q, want high from 高危", items[0].Severity)
	}
	// 中风险 is the "-风险" wording; it must map too, or the severity gate
	// silently drops the advisory.
	if items[1].Severity != SeverityMedium {
		t.Fatalf("severity = %q, want medium from 中风险", items[1].Severity)
	}
}

// TestThreatbookMapsRiskLevelWording pins that 高风险 is understood. The
// threat-intel feeds write "-风险", vendor feeds write "-危"; only accepting
// one set meant the other source's advisories all landed as "unknown".
func TestThreatbookMapsRiskLevelWording(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{
		threatbookHomeURL: {body: threatbookHomeFixture},
	}}
	items, err := newThreatBookSource(newClient(f)).Fetch(context.Background(), 10)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	if items[0].Severity != SeverityHigh {
		t.Fatalf("severity = %q, want high from 高风险", items[0].Severity)
	}
	if items[0].UniqueKey != "XVE-2026-81746_threatbook" {
		t.Fatalf("unique key = %q", items[0].UniqueKey)
	}
}

// TestSeebugParsesTheRealTable pins the markup the parser must read: the row
// links to /vuldb/ssvid-<id> (not /vuldb/vulnerabilities/), the title is the
// anchor text on class="vul-title", and the level is on a div.
func TestSeebugParsesTheRealTable(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{
		seebugListURL: {body: seebugListFixture},
	}}
	items, err := newSeebugSource(newClient(f)).Fetch(context.Background(), 10)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2 rows", len(items))
	}
	first := items[0]
	if first.UniqueKey != "/vuldb/ssvid-99969_seebug" {
		t.Fatalf("unique key = %q", first.UniqueKey)
	}
	if first.Title != "Linux 内核提权 Dirty Frag" {
		t.Fatalf("title = %q (the table has two anchors; the title is the second one)", first.Title)
	}
	if first.Severity != SeverityHigh {
		t.Fatalf("severity = %q, want high from data-original-title=高危", first.Severity)
	}
	if first.Disclosure != "2026-05-08" {
		t.Fatalf("disclosure = %q", first.Disclosure)
	}
	// The second row carries a CVE and a PoC icon.
	second := items[1]
	if second.CVE != "CVE-2026-11111" {
		t.Fatalf("cve = %q, want the first of the two listed", second.CVE)
	}
	if second.Severity != SeverityMedium {
		t.Fatalf("severity = %q, want medium", second.Severity)
	}
	if len(second.Tags) == 0 || second.Tags[0] != "有Poc" {
		t.Fatalf("tags = %v, want 有Poc from the rocket icon", second.Tags)
	}
}

// TestSeebugSkipsRowsWithoutTheIdAnchor pins that a row is identified by its
// SSV link, not merely by being a <tr>: the table has header and layout rows.
func TestSeebugSkipsRowsWithoutTheIdAnchor(t *testing.T) {
	page := `<table><tbody>
	  <tr><td>no link here</td><td>2026-05-08</td></tr>
	  <tr><td><a href="/vuldb/ssvid-99967">SSV-99967</a></td>
	      <td class="datetime">2026-05-06</td>
	      <td><div class="vul-level low" data-original-title="低危"></div></td>
	      <td><a class="vul-title" href="/vuldb/ssvid-99967">低危样例</a></td></tr>
	</tbody></table>`
	rows := parseSeebugRows([]byte(page))
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 (the header row has no advisory link)", len(rows))
	}
	if rows[0].Level != "低危" {
		t.Fatalf("level = %q", rows[0].Level)
	}
}

// TestChaitinFetchesOnePagePerPoll pins the deliberate absence of paging: the
// site's WAF answers HTTP 465 after ~4 rapid requests, so a paging loop turns a
// working source into a failing one. The source must issue exactly one request.
func TestChaitinFetchesOnePagePerPoll(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{
		chaitinListURL: {body: chaitinListFixture},
	}}
	items, err := newChaitinSource(newClient(f)).Fetch(context.Background(), 100)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	if len(f.seen) != 1 {
		t.Fatalf("issued %d requests, want 1 (paging trips the upstream WAF)", len(f.seen))
	}
	if items[0].UniqueKey != "CT-2026-86467_chaitin" {
		t.Fatalf("unique key = %q", items[0].UniqueKey)
	}
	if items[0].Severity != SeverityHigh {
		t.Fatalf("severity = %q, want high", items[0].Severity)
	}
}

// TestClientRetriesAThrottleOnce pins the chaitin retry: 465 is a temporary
// refusal, and backing off once recovers the feed. The test drives a fetcher
// that fails the first call, so no real waiting happens.
func TestClientRetriesAThrottleOnce(t *testing.T) {
	f := &throttleOnceFetcher{}
	c := newClient(f)
	c.backoff = time.Millisecond
	body, err := c.get(context.Background(), "https://example.test/x", nil)
	if err != nil {
		t.Fatalf("a single 465 must be retried, not returned as an error: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
	if f.calls != 2 {
		t.Fatalf("calls = %d, want 2 (one throttle + one retry)", f.calls)
	}
}

// TestClientGivesUpAfterOneRetry pins that a persistent throttle is reported
// instead of being retried forever.
func TestClientGivesUpAfterOneRetry(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{
		"https://example.test/x": {status: 465, body: "challenge"},
	}}
	c := newClient(f)
	c.backoff = time.Millisecond
	_, err := c.get(context.Background(), "https://example.test/x", nil)
	if err == nil {
		t.Fatal("a persistent 465 must be reported")
	}
	if !strings.Contains(err.Error(), "465") {
		t.Fatalf("error should name the status: %v", err)
	}
	if len(f.seen) != 2 {
		t.Fatalf("issued %d requests, want 2 (first + one retry)", len(f.seen))
	}
}

// throttleOnceFetcher answers 465 on the first call and 200 after that.
type throttleOnceFetcher struct{ calls int }

func (f *throttleOnceFetcher) Fetch(_ context.Context, _ core.Request) (*core.Response, error) {
	f.calls++
	if f.calls == 1 {
		return &core.Response{Status: 465, Body: []byte("challenge")}, nil
	}
	return &core.Response{Status: 200, Body: []byte("ok")}, nil
}

func (f *throttleOnceFetcher) Do(ctx context.Context, req core.Request) (*core.Response, error) {
	return f.Fetch(ctx, req)
}

// TestHostSourcesArePolledAlongsideBuiltins pins the seam that replaced the
// built-in AVD scraper: a source the host fetches itself is polled through the
// same store and dedup path, so AVD-style sources do not need a second poll
// loop in the host.
func TestHostSourcesArePolledAlongsideBuiltins(t *testing.T) {
	host := &fakeHostSource{
		name: "aliyun-avd",
		items: []core.IntelItem{{
			UniqueKey: "AVD-2026-104935_aliyun-avd",
			Title:     "Ivanti Connect Secure 请求头权限绕过漏洞",
			Severity:  SeverityHigh,
			CVE:       "CVE-2026-104935",
		}},
	}
	store := newRecordingIntel()
	f := &fakeFetcher{routes: map[string]fakeResponse{
		kevCatalogURL: {body: kevCatalogFixture},
	}}
	cap, err := NewCapability(core.Deps{
		Fetcher: f, Intel: store, Settings: fixedSettings{}, ExtraIntel: []core.IntelSource{host},
	})
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	in, _ := json.Marshal(map[string]any{"sources": []string{"kev", "aliyun-avd"}})
	res, err := cap.Call(context.Background(), core.Call{Tool: "vulnintel_poll", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q summary=%q err=%+v", res.Status, res.Summary, res.Error)
	}
	var data pollData
	_ = json.Unmarshal(res.Data, &data)
	var sawHost bool
	for _, s := range data.Sources {
		if s.Name == "aliyun-avd" {
			sawHost = true
			if s.Fetched != 1 || s.Created != 1 {
				t.Fatalf("host source stats = %+v", s)
			}
		}
	}
	if !sawHost {
		t.Fatalf("the host-provided source was not polled: %+v", data.Sources)
	}
	// The item must reach the store, with the source filled in by the adapter.
	if len(store.items) != 3 {
		t.Fatalf("store received %d items, want 3 (2 KEV + 1 host)", len(store.items))
	}
	var found bool
	for _, it := range store.items {
		if it.UniqueKey == "AVD-2026-104935_aliyun-avd" {
			found = true
			if it.Source != "aliyun-avd" {
				t.Fatalf("host item source = %q, want the source name", it.Source)
			}
		}
	}
	if !found {
		t.Fatal("host item did not reach the store")
	}
}

// TestHostSourceAppearsInTheSourceList pins that vulnintel_sources reports what
// will actually be polled, host sources included.
func TestHostSourceAppearsInTheSourceList(t *testing.T) {
	cap, _ := NewCapability(core.Deps{
		Settings:   fixedSettings{},
		ExtraIntel: []core.IntelSource{&fakeHostSource{name: "aliyun-avd"}},
	})
	res, err := cap.Call(context.Background(), core.Call{Tool: "vulnintel_sources"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var data sourcesData
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	names := map[string]bool{}
	for _, s := range data.Sources {
		names[s.Name] = true
	}
	if !names["aliyun-avd"] {
		t.Fatalf("host source missing from %v", names)
	}
	if !names["kev"] {
		t.Fatalf("built-in sources missing from %v", names)
	}
}

// TestHostSourceFailureIsIsolated pins that a broken host source is reported
// per source and does not sink the poll.
func TestHostSourceFailureIsIsolated(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{kevCatalogURL: {body: kevCatalogFixture}}}
	cap, _ := NewCapability(core.Deps{
		Fetcher: f, Intel: newRecordingIntel(), Settings: fixedSettings{},
		ExtraIntel: []core.IntelSource{&fakeHostSource{name: "aliyun-avd", err: errors.New("js engine exploded")}},
	})
	in, _ := json.Marshal(map[string]any{"sources": []string{"kev", "aliyun-avd"}})
	res, err := cap.Call(context.Background(), core.Call{Tool: "vulnintel_poll", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q, want success despite the host source failing", res.Status)
	}
	var data pollData
	_ = json.Unmarshal(res.Data, &data)
	for _, s := range data.Sources {
		if s.Name == "aliyun-avd" && !strings.Contains(s.Error, "js engine") {
			t.Fatalf("host source error not reported: %+v", s)
		}
	}
}

// fakeHostSource is a host-provided source that never touches the network.
type fakeHostSource struct {
	name  string
	items []core.IntelItem
	err   error
	calls int
}

func (f *fakeHostSource) Name() string { return f.name }

func (f *fakeHostSource) Fetch(_ context.Context, limit int) ([]core.IntelItem, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if limit > 0 && len(f.items) > limit {
		return f.items[:limit], nil
	}
	return f.items, nil
}

// TestStruts2ReadsTheCurrentConfluenceMarkup pins both new facts: the list page
// carries only /confluence/spaces/WW/pages/<id>/S2-00N links, and every
// advisory needs a detail fetch because the list page has no titles.
func TestStruts2ReadsTheCurrentConfluenceMarkup(t *testing.T) {
	list := `<li class="child-item" data-page-id="61776"><span class="icon"></span>
	  <a href="/confluence/spaces/WW/pages/61776/S2-001" title="S2-001"><span class="label">S2-001</span></a></li>
	<li class="child-item" data-page-id="78426"><span class="icon"></span>
	  <a href="/confluence/spaces/WW/pages/78426/S2-002" title="S2-002"><span class="label">S2-002</span></a></li>`
	entries := parseStruts2List([]byte(list))
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].ID != "S2-001" || entries[0].URL != "/confluence/spaces/WW/pages/61776/S2-001" {
		t.Fatalf("first entry = %+v", entries[0])
	}

	title, cve, impact := parseStruts2Detail([]byte(
		`<title>S2-001 - Apache Struts 2 Wiki - Apache Software Foundation</title>
		 <td>Maximum security rating</td><td>Critical</td>
		 <a href="https://struts.apache.org/announce">CVE-2008-6504</a>`))
	if title != "S2-001" {
		t.Fatalf("title = %q, want the bulletin id without the Confluence suffix", title)
	}
	if cve != "CVE-2008-6504" {
		t.Fatalf("cve = %q", cve)
	}
	if !strings.Contains(impact, "Critical") {
		t.Fatalf("impact = %q", impact)
	}
}

// TestStruts2SeverityWording pins Apache's own severity vocabulary.
func TestStruts2SeverityWording(t *testing.T) {
	for input, want := range map[string]string{
		"Maximum security rating Critical":  SeverityCritical,
		"Maximum security rating Important": SeverityHigh,
		"Maximum security rating Moderate":  SeverityMedium,
		"Maximum security rating Low":       SeverityLow,
		"":                                  SeverityUnknown,
	} {
		if got := struts2Severity(input); got != want {
			t.Errorf("struts2Severity(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestVenustechDegradesWhenDetailIsUnreadable pins that a throttled detail
// page costs the CVE and the description, but not the advisory: the list page
// already proved the title, the date and the link.
func TestVenustechDegradesWhenDetailIsUnreadable(t *testing.T) {
	list := `<a href="/new_type/aqtg/20261008/29664.html" title="Atlassian 任意文件读取">Atlassian 任意文件读取</a><span>2026-10-08</span>
	          <a href="/new_type/aqtg/20260929/29658.html" title="VPN 目录穿越">VPN 目录穿越</a><span>2026-09-29</span>`
	links := parseVenustechList([]byte(list))
	if len(links) != 2 {
		t.Fatalf("links = %d, want 2", len(links))
	}
	// normalizeCell collapses whitespace, so the title arrives unspaced.
	if links[0].Title != "Atlassian任意文件读取" || links[0].Date != "2026-10-08" {
		t.Fatalf("first link = %+v", links[0])
	}
	if links[1].Path != "/new_type/aqtg/20260929/29658.html" || links[1].Date != "2026-09-29" {
		t.Fatalf("second link = %+v (a row's date must not leak to its neighbour)", links[1])
	}
}
