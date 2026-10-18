package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

func TestFeatureCallsAPI(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	const feature = FeatureVulnKB
	cleanup := func() {
		_, _ = d.Exec(`DELETE FROM feature_call_log WHERE actor LIKE 'zz-test%'`)
	}
	cleanup()
	defer cleanup()

	now := time.Now()
	for _, row := range []*db.FeatureCall{
		{
			TS: now.Add(-time.Minute), Feature: feature, Action: "search", Source: "web",
			Status: "ok", Actor: "zz-test", Query: "泛微 OA", Summary: "搜索命中 3 条",
			Request: json.RawMessage(`{"q":"泛微 OA"}`), Result: json.RawMessage(`{"total":3}`),
			DurationMS: 60,
		},
		{
			TS: now, Feature: feature, Action: "scan", Source: "agent",
			Status: "error", Actor: "zz-test-worker", Error: "target unreachable", Summary: "扫描失败",
			DurationMS: 120,
		},
	} {
		if err := d.InsertFeatureCall(row); err != nil {
			t.Fatal(err)
		}
	}

	s := &Server{m: &Manager{pg: d}}

	listReq := httptest.NewRequest(http.MethodGet, "/api/feature-calls?feature="+feature+"&q=zz-test&page=1&size=10", nil)
	listRec := httptest.NewRecorder()
	s.getFeatureCalls(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listRec.Code, listRec.Body.String())
	}
	var list struct {
		Items []db.FeatureCall `json:"items"`
		Total int              `json:"total"`
		Page  int              `json:"page"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 2 || len(list.Items) != 2 || list.Page != 1 {
		t.Fatalf("list = %+v", list)
	}
	if list.Items[0].Request != nil {
		t.Fatalf("list must omit request, got %s", list.Items[0].Request)
	}

	fromStr := now.Add(-2 * time.Minute).Format(time.RFC3339)
	toStr := now.Add(time.Minute).Format(time.RFC3339)
	statsReq := httptest.NewRequest(http.MethodGet, "/api/feature-calls/stats?feature="+feature+"&from="+url.QueryEscape(fromStr)+"&to="+url.QueryEscape(toStr), nil)
	statsRec := httptest.NewRecorder()
	s.getFeatureCallStats(statsRec, statsReq)
	if statsRec.Code != http.StatusOK {
		t.Fatalf("stats status=%d body=%s", statsRec.Code, statsRec.Body.String())
	}
	var stats struct {
		Stats db.FeatureCallStats `json:"stats"`
	}
	if err := json.Unmarshal(statsRec.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.Stats.Total != 2 || stats.Stats.OK != 1 || stats.Stats.Error != 1 {
		t.Fatalf("stats = %+v", stats.Stats)
	}

	search := list.Items[1]
	detailReq := httptest.NewRequest(http.MethodGet, "/api/feature-calls/"+strconv.FormatInt(search.ID, 10), nil)
	detailReq.SetPathValue("id", strconv.FormatInt(search.ID, 10))
	detailRec := httptest.NewRecorder()
	s.getFeatureCall(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", detailRec.Code, detailRec.Body.String())
	}
	var detail struct {
		Call db.FeatureCall `json:"call"`
	}
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Call.Request) == 0 || len(detail.Call.Result) == 0 {
		t.Fatalf("detail payloads = %s / %s", detail.Call.Request, detail.Call.Result)
	}
}
