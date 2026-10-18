package server

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/internal/platform/notify"
)

// notifyTaskStatus 把任务生命周期变化转成通知事件。由 Manager 的状态钩子调用，
// 必须快速返回——实际落库放在 goroutine 里，避免阻塞任务状态更新。
func (s *Server) notifyTaskStatus(taskID, oldStatus, newStatus string) {
	kind, title, severity := taskNotification(newStatus, oldStatus)
	if kind == "" || s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	n, err := strconv.ParseInt(strings.TrimSpace(taskID), 10, 64)
	if err != nil || n <= 0 {
		return
	}
	desc, projectID := "", int64(0)
	if task, err := s.m.pg.GetTask(n); err == nil && task != nil {
		desc = strings.TrimSpace(task.Description)
		if task.ProjectID != nil {
			projectID = *task.ProjectID
		}
	}
	if desc == "" {
		desc = "任务 #" + taskID
	}
	if runes := []rune(desc); len(runes) > 80 {
		desc = string(runes[:80]) + "…"
	}
	title += "：" + desc
	go func() {
		_, _ = s.m.pg.AddNotificationEvent(s.ctx, kind, 0, notify.Snapshot{
			Kind:      kind,
			Title:     title,
			Category:  "任务",
			Severity:  severity,
			Summary:   fmt.Sprintf("状态 %s → %s", taskStatusLabel(oldStatus), taskStatusLabel(newStatus)),
			TaskID:    n,
			ProjectID: projectID,
			ActionURL: "/function/tasks/detail?id=" + taskID,
		})
	}()
}

func taskNotification(newStatus, oldStatus string) (kind, title, severity string) {
	if newStatus == oldStatus {
		return "", "", ""
	}
	switch newStatus {
	case "done":
		return notify.EventTaskDone, "任务完成", "info"
	case "failed":
		return notify.EventTaskFailed, "任务失败", "high"
	case "blocked":
		return notify.EventTaskBlocked, "任务阻塞", "high"
	case "timeout":
		return notify.EventTaskTimeout, "任务超时", "high"
	case "paused":
		return notify.EventTaskPaused, "任务暂停", "info"
	case "running":
		switch oldStatus {
		case "paused", "blocked":
			return notify.EventTaskResumed, "任务恢复", "info"
		case "", "queued", "pending":
			return notify.EventTaskStarted, "任务启动", "info"
		}
	}
	return "", "", ""
}

func taskStatusLabel(status string) string {
	switch status {
	case "", "queued":
		return "排队"
	case "pending":
		return "待启动"
	case "running":
		return "运行中"
	case "paused":
		return "暂停"
	case "blocked":
		return "阻塞"
	case "done":
		return "完成"
	case "failed":
		return "失败"
	case "timeout":
		return "超时"
	case "stopped":
		return "停止"
	default:
		return status
	}
}
