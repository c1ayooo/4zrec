package db

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFeatureCallLedger(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	const feature = "zz_test_feature_call"
	cleanup := func() {
		_, _ = d.Exec(`DELETE FROM feature_call_log WHERE feature = $1`, feature)
	}
	cleanup()
	defer cleanup()

	now := time.Now()
	rows := []*FeatureCall{
		{
			TS: now.Add(-2 * time.Hour), Feature: feature, Action: "search", Source: "web",
			Status: "ok", Actor: "tester", Query: "泛微 OA",
			Summary: "搜索命中 3 条", Request: json.RawMessage(`{"q":"泛微 OA"}`),
			Result: json.RawMessage(`{"total":3}`), DurationMS: 30,
		},
		{
			TS: now.Add(-time.Hour), Feature: feature, Action: "scan", Source: "agent",
			Status: "ok", Actor: "worker", TaskID: 42, Query: "https://demo.example.com",
			Summary: "扫描 1 个目标", Request: json.RawMessage(`{"targets":["https://demo.example.com"]}`),
			Result: json.RawMessage(`{"hits":2}`), DurationMS: 4200,
		},
		{
			TS: now.Add(-30 * time.Minute), Feature: feature, Action: "scan", Source: "agent",
			Status: "error", Actor: "worker", Error: "target unreachable",
			Summary: "扫描失败", DurationMS: 100,
		},
	}
	for _, row := range rows {
		if err := d.InsertFeatureCall(row); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	items, total, err := d.ListFeatureCalls(FeatureCallFilter{Feature: feature, Page: 0, Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("list total=%d len=%d, want 3", total, len(items))
	}
	if items[0].Action != "scan" || items[0].Status != "error" {
		t.Fatalf("newest row = %+v, want scan/error", items[0])
	}
	if items[0].Request != nil {
		t.Fatalf("list must not return request, got %s", items[0].Request)
	}

	scans, scanTotal, err := d.ListFeatureCalls(FeatureCallFilter{Feature: feature, Action: "scan", Page: 0, Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	if scanTotal != 2 || len(scans) != 2 {
		t.Fatalf("scan filter total=%d len=%d, want 2", scanTotal, len(scans))
	}

	found, foundTotal, err := d.ListFeatureCalls(FeatureCallFilter{Feature: feature, Query: "泛微", Page: 0, Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	if foundTotal != 1 || len(found) != 1 || found[0].Query != "泛微 OA" {
		t.Fatalf("query filter = %+v total=%d", found, foundTotal)
	}

	stats, err := d.FeatureCallStats(feature, now.Add(-3*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 3 || stats.OK != 2 || stats.Error != 1 || stats.Denied != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.AvgDurationMS != 1443 {
		t.Fatalf("avg duration = %d, want 1443", stats.AvgDurationMS)
	}

	detail, err := d.GetFeatureCall(items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(detail.Request) != "{}" || string(detail.Result) != "{}" {
		t.Fatalf("detail empty payloads = %s / %s", detail.Request, detail.Result)
	}

	searchID := found[0].ID
	detail, err = d.GetFeatureCall(searchID)
	if err != nil {
		t.Fatal(err)
	}
	var req, res map[string]any
	if err := json.Unmarshal(detail.Request, &req); err != nil {
		t.Fatalf("detail request json: %v (%s)", err, detail.Request)
	}
	if err := json.Unmarshal(detail.Result, &res); err != nil {
		t.Fatalf("detail result json: %v (%s)", err, detail.Result)
	}
	if req["q"] != "泛微 OA" {
		t.Fatalf("detail request = %s", detail.Request)
	}
	if res["total"] != float64(3) {
		t.Fatalf("detail result = %s", detail.Result)
	}

	if err := d.InsertFeatureCall(&FeatureCall{
		TS: now.AddDate(0, 0, -100), Feature: feature, Action: "search", Source: "web",
		Status: "ok", Summary: "old row",
	}); err != nil {
		t.Fatal(err)
	}
	deleted, err := d.PruneFeatureCalls(now.AddDate(0, 0, -99))
	if err != nil {
		t.Fatal(err)
	}
	if deleted < 1 {
		t.Fatalf("prune deleted=%d, want >=1", deleted)
	}
	_, total, err = d.ListFeatureCalls(FeatureCallFilter{Feature: feature, Page: 0, Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("after prune total=%d, want 3", total)
	}
}
