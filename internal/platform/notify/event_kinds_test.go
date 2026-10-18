package notify

import (
	"strings"
	"testing"
)

func TestFilterEventKinds(t *testing.T) {
	taskDone := Snapshot{Kind: EventTaskDone, Severity: "info"}
	if !Match(Filter{EventKinds: []string{EventTaskDone}}, taskDone) {
		t.Fatal("selected event kind should match")
	}
	if Match(Filter{EventKinds: []string{EventFindingCreated}}, taskDone) {
		t.Fatal("unselected event kind must not match")
	}
	// 旧库兼容：event_kinds 为空时只收 finding_created，状态变更需显式开启。
	if !Match(Filter{}, Snapshot{Kind: EventFindingCreated, Severity: "high"}) {
		t.Fatal("legacy filter should accept finding_created")
	}
	if Match(Filter{}, taskDone) {
		t.Fatal("legacy filter must not accept new event kinds")
	}
	if Match(Filter{}, Snapshot{Kind: EventFindingStatusChanged, Severity: "high"}) {
		t.Fatal("legacy filter should reject status change unless enabled")
	}
	if !Match(Filter{OnStatusChange: true}, Snapshot{Kind: EventFindingStatusChanged, Severity: "high"}) {
		t.Fatal("legacy status change toggle should work")
	}
	if Match(Filter{EventKinds: []string{EventTaskDone}, MinSeverity: "high"}, taskDone) {
		t.Fatal("min severity must still apply to generic events")
	}
}

func TestFilterValidateEventKinds(t *testing.T) {
	if err := (Filter{EventKinds: []string{"unknown_kind"}}).Validate(); err == nil {
		t.Fatal("unknown event kind must be rejected on save")
	}
	if err := (Filter{EventKinds: []string{EventTaskDone, EventApprovalRequired}}).Validate(); err != nil {
		t.Fatalf("known event kinds should validate: %v", err)
	}
}

func TestGenericEventTitleAndCounts(t *testing.T) {
	m := Message{Batch: true, Items: []Item{
		{Kind: EventTaskDone, Name: "任务 A", Severity: "info"},
		{Kind: EventApprovalRequired, Name: "Bash", Severity: "high"},
	}}
	if m.AllFindings() {
		t.Fatal("mixed events must not be treated as findings")
	}
	if title := markdownTitle(m); !strings.Contains(title, "通知汇总") {
		t.Fatalf("batch title = %q", title)
	}
	counts := m.KindCounts()
	if len(counts) != 2 {
		t.Fatalf("kind counts = %+v", counts)
	}
	if got := (Item{Kind: EventApprovalRequired, Name: "Bash"}).DisplayTitle(); !strings.Contains(got, "待审批") {
		t.Fatalf("display title = %q", got)
	}
	if !(Message{Items: []Item{{Kind: EventFindingCreated, Name: "SQLi"}}}).AllFindings() {
		t.Fatal("pure finding messages should keep finding wording")
	}
}
