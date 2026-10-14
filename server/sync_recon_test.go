package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func reconItem(host, ts string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"host": host, "time": ts})
	return raw
}

// 水位回拨：正常解析回拨 60s；坏值/空值原样返回（不推进坏水位）。
func TestReconRollbackWatermark(t *testing.T) {
	got := reconRollbackWatermark("2026-10-14 12:00:00")
	if got != "2026-10-14 11:59:00" {
		t.Fatalf("rollback = %q, want 2026-10-14 11:59:00", got)
	}
	for _, bad := range []string{"", "not-a-time", "2026-10-14"} {
		if got := reconRollbackWatermark(bad); got != bad {
			t.Fatalf("bad watermark %q should pass through, got %q", bad, got)
		}
	}
}

func TestReconItemTime(t *testing.T) {
	if got := reconItemTime(reconItem("a.com", "2026-10-14 12:00:00")); got != "2026-10-14 12:00:00" {
		t.Fatalf("reconItemTime = %q", got)
	}
	noTime, _ := json.Marshal(map[string]any{"host": "a.com"})
	if got := reconItemTime(noTime); got != "" {
		t.Fatalf("missing time should be empty, got %q", got)
	}
}

// 倒序页截断（施工单变更1验收项）：服务端按 time 倒序，客户端遇 time <= watermark
// 整页止，只保留新于水位的条目，maxTime 取本轮见到的最大值。
func TestReconPageSincePagesStopsAtWatermark(t *testing.T) {
	var pagesFetched int
	pages := [][]json.RawMessage{
		{reconItem("new3", "2026-10-14 12:03:00"), reconItem("new2", "2026-10-14 12:02:00"), reconItem("new1", "2026-10-14 12:01:00")},
		{reconItem("old1", "2026-10-14 11:00:00"), reconItem("old2", "2026-10-14 10:00:00")},
	}
	fetch := func(page int) ([]json.RawMessage, error) {
		pagesFetched++
		if page > len(pages) {
			return nil, nil
		}
		return pages[page-1], nil
	}
	items, maxTime, truncated, err := reconPageSincePages(fetch, 3, "2026-10-14 12:00:30")
	if err != nil || truncated {
		t.Fatalf("err=%v truncated=%v", err, truncated)
	}
	if len(items) != 3 || reconItemTime(items[0]) != "2026-10-14 12:03:00" {
		t.Fatalf("items = %v", items)
	}
	if maxTime != "2026-10-14 12:03:00" {
		t.Fatalf("maxTime = %q", maxTime)
	}
	if pagesFetched != 2 {
		t.Fatalf("should stop after the page that crosses the watermark, fetched %d", pagesFetched)
	}
}

// 水位同页混排：新条目后跟老条目，老条目被丢弃且不再翻页。
func TestReconPageSincePagesPageBoundary(t *testing.T) {
	pages := [][]json.RawMessage{
		{reconItem("new1", "2026-10-14 12:05:00"), reconItem("old", "2026-10-14 11:59:00")},
		{reconItem("older", "2026-10-14 10:00:00")},
	}
	var pagesFetched int
	fetch := func(page int) ([]json.RawMessage, error) {
		pagesFetched++
		if page > len(pages) {
			return nil, nil
		}
		return pages[page-1], nil
	}
	items, _, _, err := reconPageSincePages(fetch, 2, "2026-10-14 12:00:00")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || reconItemTime(items[0]) != "2026-10-14 12:05:00" {
		t.Fatalf("items = %v", items)
	}
	if pagesFetched != 1 {
		t.Fatalf("watermark reached within page 1 should stop paging, fetched %d", pagesFetched)
	}
}

// 无 time 的条目按新数据处理（fail-open），并参与 maxTime 之外的保留。
func TestReconPageSincePagesKeepsTimelessItems(t *testing.T) {
	none, _ := json.Marshal(map[string]any{"host": "no-time"})
	fetch := func(page int) ([]json.RawMessage, error) {
		if page > 1 {
			return nil, nil
		}
		return []json.RawMessage{none, reconItem("new", "2026-10-14 12:01:00")}, nil
	}
	items, maxTime, _, err := reconPageSincePages(fetch, 2, "2026-10-14 12:00:00")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("timeless item must be kept, items = %v", items)
	}
	if maxTime != "2026-10-14 12:01:00" {
		t.Fatalf("maxTime = %q", maxTime)
	}
}

// 单轮保护上限：永远有新数据时 5000 条截断并置 truncated（增量=单轮保护）。
func TestReconPageSincePagesTruncatesAtCap(t *testing.T) {
	page := make([]json.RawMessage, syncDefaultPage)
	for i := range page {
		page[i] = reconItem(fmt.Sprintf("h%d", i), "2026-10-14 12:00:00")
	}
	fetch := func(int) ([]json.RawMessage, error) { return page, nil }
	items, _, truncated, err := reconPageSincePages(fetch, syncDefaultPage, "2026-10-13 00:00:00")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != syncMaxPerType || !truncated {
		t.Fatalf("cap: len=%d truncated=%v", len(items), truncated)
	}
}

// fetch 中途报错：已取条目与错误一并返回（调用方不推进水位，下轮重拉幂等吸收）。
func TestReconPageSincePagesErrorStopsPaging(t *testing.T) {
	pages := [][]json.RawMessage{
		{reconItem("new1", "2026-10-14 12:01:00"), reconItem("new2", "2026-10-14 12:02:00")},
	}
	var pagesFetched int
	fetch := func(page int) ([]json.RawMessage, error) {
		pagesFetched++
		if page == 1 {
			return pages[0], nil
		}
		return nil, fmt.Errorf("boom")
	}
	items, _, _, err := reconPageSincePages(fetch, 2, "2026-10-14 12:00:00")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want boom error, got %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("partial items should be returned, got %d", len(items))
	}
	if pagesFetched != 2 {
		t.Fatalf("fetched %d", pagesFetched)
	}
}

// 模式归一（施工单变更1：默认 inc、旧客户端带 targets 仍走 full）。
func TestReconNormalizeMode(t *testing.T) {
	cases := []struct {
		mode    string
		targets int
		want    string
	}{
		{"inc", 0, "inc"},
		{"full", 1, "full"},
		{"", 1, "full"}, // 旧客户端：带 targets 的调用曾是唯一语义
		{"", 0, "inc"},  // 新调用缺省 mode：默认增量
		{"FULL", 1, "full"},
		{" Inc ", 0, "inc"},
		{"bogus", 0, ""}, // 显式非法值 → handler 400
	}
	for _, c := range cases {
		if got := reconNormalizeMode(c.mode, c.targets); got != c.want {
			t.Errorf("reconNormalizeMode(%q, %d) = %q, want %q", c.mode, c.targets, got, c.want)
		}
	}
}

// 对账判定：上游净增长明显而增量入库停滞 → 判失明；首对账(prev<=0)不判。
func TestReconcileNeedsReset(t *testing.T) {
	if reconcileNeedsReset(0, 10000, 0, 200) {
		t.Errorf("首对账无从比较不应判失明")
	}
	if reconcileNeedsReset(1000, 1050, 0, 200) {
		t.Errorf("增长 50 未过阈值不应判失明")
	}
	if !reconcileNeedsReset(1000, 1500, 0, 200) {
		t.Errorf("增长 500 且零入库应判失明")
	}
	if reconcileNeedsReset(1000, 1500, 400, 200) {
		t.Errorf("增长 500 入库 400（>一半）不应判失明")
	}
	if reconcileNeedsReset(1000, 900, 0, 200) {
		t.Errorf("上游缩量（清理噪音）不应判失明")
	}
}

// 对账到期：从未对过账/时间串损坏 → 到期；24h 内 → 未到期。
func TestSyncReconcileDue(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.Local)
	if !syncReconcileDue("", now) {
		t.Errorf("从未对账应到期")
	}
	if !syncReconcileDue("not-a-time", now) {
		t.Errorf("坏时间串应视为到期（防永久跳过）")
	}
	recent := now.Add(-2 * time.Hour).Format(time.RFC3339)
	if syncReconcileDue(recent, now) {
		t.Errorf("2h 前对过账不应到期")
	}
	stale := now.Add(-25 * time.Hour).Format(time.RFC3339)
	if !syncReconcileDue(stale, now) {
		t.Errorf("25h 前对过账应到期")
	}
}
