package intel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// fakeFetcher serves canned upstream bodies by URL. It never touches the
// network, so source tests are deterministic.
type fakeFetcher struct {
	routes map[string]fakeResponse
	seen   []string
}

type fakeResponse struct {
	status int
	body   string
}

func (f *fakeFetcher) Fetch(ctx context.Context, req core.Request) (*core.Response, error) {
	f.seen = append(f.seen, req.URL)
	for url, r := range f.routes {
		if url == req.URL {
			status := r.status
			if status == 0 {
				status = 200
			}
			return &core.Response{Status: status, Body: []byte(r.body)}, nil
		}
	}
	return &core.Response{Status: 404, Body: []byte("no route")}, nil
}

func (f *fakeFetcher) Do(ctx context.Context, req core.Request) (*core.Response, error) {
	return f.Fetch(ctx, req)
}

type recordingIntel struct {
	items  []core.IntelItem
	byID   map[string]*core.IntelItem
	byKey  map[string]bool
	failOn int
	calls  int
}

func newRecordingIntel() *recordingIntel {
	return &recordingIntel{byID: map[string]*core.IntelItem{}, byKey: map[string]bool{}}
}

func (r *recordingIntel) Upsert(ctx context.Context, item core.IntelItem) (string, bool, error) {
	r.calls++
	if r.failOn > 0 && r.calls >= r.failOn {
		return "", false, errUpstream
	}
	if r.byKey[item.UniqueKey] {
		return "id-" + item.UniqueKey, false, nil
	}
	r.byKey[item.UniqueKey] = true
	id := "id-" + item.UniqueKey
	item.ID = id
	cp := item
	r.byID[id] = &cp
	r.items = append(r.items, item)
	return id, true, nil
}

func (r *recordingIntel) Query(ctx context.Context, q core.IntelQuery) ([]core.IntelItem, error) {
	out := make([]core.IntelItem, 0, len(r.items))
	for _, it := range r.items {
		if q.Text != "" && !strings.Contains(it.Title, q.Text) {
			continue
		}
		if q.CVE != "" && !strings.EqualFold(it.CVE, q.CVE) {
			continue
		}
		out = append(out, it)
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out, nil
}

func (r *recordingIntel) Get(ctx context.Context, id string) (*core.IntelItem, error) {
	if it, ok := r.byID[id]; ok {
		return it, nil
	}
	return nil, core.NotFound("not found")
}

type fixedSettings struct{ m map[string]string }

func (s fixedSettings) GetString(ctx context.Context, key string) (string, bool) {
	v, ok := s.m[key]
	return v, ok
}
func (s fixedSettings) GetBool(ctx context.Context, key string) (bool, bool) {
	return false, false
}
func (s fixedSettings) GetInt(ctx context.Context, key string) (int64, bool) {
	return 0, false
}

// TestPollReturnsNormalizedEnvelope pins the seam: one poll must return a
// Result envelope whose Data carries the source count and every item, and the
// host store must have received them all.
func TestPollReturnsNormalizedEnvelope(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{
		kevCatalogURL: {body: kevCatalogFixture},
	}}
	store := newRecordingIntel()
	cap, err := NewCapability(core.Deps{Fetcher: f, Intel: store, Settings: fixedSettings{}})
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	in, _ := json.Marshal(map[string]any{"sources": []string{"kev"}})
	res, err := cap.Call(context.Background(), core.Call{Tool: "vulnintel_poll", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q, want success (summary %q err %+v)", res.Status, res.Summary, res.Error)
	}
	if res.Summary == "" {
		t.Fatal("summary must not be empty")
	}
	var data pollData
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	if len(data.Sources) != 1 {
		t.Fatalf("sources = %d, want 1", len(data.Sources))
	}
	if data.Sources[0].Created == 0 {
		t.Fatalf("expected new items, got %+v", data.Sources[0])
	}
	if data.Total == 0 {
		t.Fatal("total must count fetched items")
	}
	// Every fetched item must reach the host store exactly once per unique key.
	if len(store.items) == 0 {
		t.Fatal("store received nothing")
	}
	for _, it := range store.items {
		if it.UniqueKey == "" {
			t.Fatal("item reached the store without a unique key")
		}
		if it.Source == "" {
			t.Fatal("item reached the store without a source name")
		}
	}
}

// TestPollIsIdempotentThroughTheStore pins the delta semantics: a second poll
// of the same feed must report zero created, because dedup belongs to the
// host's unique key.
func TestPollIsIdempotentThroughTheStore(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{
		kevCatalogURL: {body: kevCatalogFixture},
	}}
	store := newRecordingIntel()
	cap, _ := NewCapability(core.Deps{Fetcher: f, Intel: store, Settings: fixedSettings{}})
	in, _ := json.Marshal(map[string]any{"sources": []string{"kev"}})
	if _, err := cap.Call(context.Background(), core.Call{Tool: "vulnintel_poll", Input: in}); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	first := len(store.items)
	res, err := cap.Call(context.Background(), core.Call{Tool: "vulnintel_poll", Input: in})
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	var data pollData
	_ = json.Unmarshal(res.Data, &data)
	if data.Sources[0].Created != 0 {
		t.Fatalf("second poll created %d, want 0", data.Sources[0].Created)
	}
	if len(store.items) != first {
		t.Fatalf("store grew from %d to %d", first, len(store.items))
	}
}

// TestPollSourceFailureIsIsolated pins that one broken source must not sink
// the batch: the other sources still report and the run stays success.
func TestPollSourceFailureIsIsolated(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{
		kevCatalogURL: {body: kevCatalogFixture},
		// oscs deliberately absent -> 404
	}}
	store := newRecordingIntel()
	cap, _ := NewCapability(core.Deps{Fetcher: f, Intel: store, Settings: fixedSettings{}})
	in, _ := json.Marshal(map[string]any{"sources": []string{"kev", "oscs"}})
	res, err := cap.Call(context.Background(), core.Call{Tool: "vulnintel_poll", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q, want success despite one failed source", res.Status)
	}
	var data pollData
	_ = json.Unmarshal(res.Data, &data)
	var oscsOK bool
	for _, s := range data.Sources {
		if s.Name == "oscs" && s.Error != "" {
			oscsOK = true
		}
		if s.Name == "kev" && s.Created == 0 {
			t.Fatalf("healthy source lost its items: %+v", s)
		}
	}
	if !oscsOK {
		t.Fatal("failed source must be reported with an error")
	}
}

// TestPollWithoutIntelStoreReportsUnavailable pins the dependency contract:
// the kit refuses to fabricate persistence instead of silently dropping items.
func TestPollWithoutIntelStoreReportsUnavailable(t *testing.T) {
	f := &fakeFetcher{routes: map[string]fakeResponse{kevCatalogURL: {body: kevCatalogFixture}}}
	cap, err := NewCapability(core.Deps{Fetcher: f, Settings: fixedSettings{}})
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	in, _ := json.Marshal(map[string]any{"sources": []string{"kev"}})
	res, err := cap.Call(context.Background(), core.Call{Tool: "vulnintel_poll", Input: in})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusUnavailable {
		t.Fatalf("status = %q, want unavailable", res.Status)
	}
}

// TestSearchAndGetDelegateToStore pins that read tools pass the query through
// to the host store untouched, so the host owns filtering and paging.
func TestSearchAndGetDelegateToStore(t *testing.T) {
	store := newRecordingIntel()
	_, _, _ = store.Upsert(context.Background(), core.IntelItem{
		UniqueKey: "CVE-2024-0001", Title: "Apache Struts2 RCE", CVE: "CVE-2024-0001",
		Severity: "high", Source: "阿里云漏洞库",
	})
	cap, err := NewCapability(core.Deps{Intel: store, Settings: fixedSettings{}})
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	in, _ := json.Marshal(map[string]any{"cve": "CVE-2024-0001"})
	res, err := cap.Call(context.Background(), core.Call{Tool: "vulnintel_search", Input: in})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if res.Status != core.StatusSuccess {
		t.Fatalf("search status = %q", res.Status)
	}
	var found searchData
	_ = json.Unmarshal(res.Data, &found)
	if found.Total != 1 {
		t.Fatalf("total = %d, want 1", found.Total)
	}

	getIn, _ := json.Marshal(map[string]any{"id": "id-CVE-2024-0001"})
	res2, err := cap.Call(context.Background(), core.Call{Tool: "vulnintel_get", Input: getIn})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if res2.Status != core.StatusSuccess {
		t.Fatalf("get status = %q", res2.Status)
	}
}

// TestUnknownToolPinsNotFound pins the dispatcher contract every capkit kit
// follows.
func TestUnknownToolPinsNotFound(t *testing.T) {
	cap, err := NewCapability(core.Deps{Intel: newRecordingIntel(), Settings: fixedSettings{}})
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	res, err := cap.Call(context.Background(), core.Call{Tool: "nope"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("error = %+v, want not_found", res.Error)
	}
}
