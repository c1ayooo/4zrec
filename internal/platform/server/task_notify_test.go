package server

import (
	"testing"

	"github.com/c1ayooo/4zrec/internal/platform/notify"
)

func TestTaskNotificationMapping(t *testing.T) {
	cases := []struct {
		newStatus, oldStatus string
		wantKind             string
	}{
		{"done", "running", notify.EventTaskDone},
		{"failed", "running", notify.EventTaskFailed},
		{"blocked", "running", notify.EventTaskBlocked},
		{"timeout", "running", notify.EventTaskTimeout},
		{"paused", "running", notify.EventTaskPaused},
		{"running", "paused", notify.EventTaskResumed},
		{"running", "blocked", notify.EventTaskResumed},
		{"running", "", notify.EventTaskStarted},
		{"running", "running", ""},
		{"done", "done", ""},
		{"archived", "done", ""},
	}
	for _, c := range cases {
		kind, _, _ := taskNotification(c.newStatus, c.oldStatus)
		if kind != c.wantKind {
			t.Fatalf("%s (%s→%s): kind=%q want %q", c.newStatus, c.oldStatus, c.newStatus, kind, c.wantKind)
		}
	}
}

func TestTaskStatusLabels(t *testing.T) {
	if got := taskStatusLabel("running"); got != "运行中" {
		t.Fatalf("running label = %q", got)
	}
	if got := taskStatusLabel("custom"); got != "custom" {
		t.Fatalf("unknown label = %q", got)
	}
}
