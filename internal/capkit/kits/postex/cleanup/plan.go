package cleanup

import (
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// evidenceRefs collects the non-empty evidence handles from command outputs.

// fillCommands populates PreviewCmd and DeleteStep for one scope entry on the
// given platform. It enforces that line-scoped kinds carry a pattern (removing
// every line of a log is only allowed by naming the exact file, not by a
// directory), so cleanup stays bounded regardless of caller input.
func fillCommands(t *cleanupTarget, platform string) *core.Error {
	if strings.Contains(platform, "win") {
		return fillWindows(t)
	}
	return fillLinux(t)
}

func fillLinux(t *cleanupTarget) *core.Error {
	q := core.ShellQuote
	switch t.Kind {
	case "log", "history":
		if strings.TrimSpace(t.Pattern) == "" {
			return core.InvalidInput(t.Kind + " 清理必须提供 pattern（按行匹配删除，禁止整文件清空）")
		}
		t.PreviewCmd = fmt.Sprintf("grep -c -E %s %s 2>/dev/null", q(t.Pattern), q(t.Path))
		t.DeleteStep = []string{fmt.Sprintf("sed -i -E %s %s", q("/"+t.Pattern+"/d"), q(t.Path))}
	case "utmp":
		if strings.TrimSpace(t.Pattern) == "" {
			return core.InvalidInput("utmp 清理必须提供 pattern（按记录过滤）")
		}
		t.PreviewCmd = fmt.Sprintf("utmpdump %s 2>/dev/null | grep -c -E %s", q(t.Path), q(t.Pattern))
		t.DeleteStep = []string{fmt.Sprintf(
			"utmpdump %s 2>/dev/null | grep -v -E %s | utmpdump -r > %s.new && mv %s.new %s",
			q(t.Path), q(t.Pattern), q(t.Path), q(t.Path), q(t.Path))}
	case "file":
		t.PreviewCmd = fmt.Sprintf("ls -la %s 2>/dev/null | wc -l", q(t.Path))
		t.DeleteStep = []string{"rm -f " + q(t.Path)}
	default:
		return core.InvalidInput("Linux 不支持的 kind: " + t.Kind + "（可选 log|history|utmp|file）")
	}
	return nil
}

func fillWindows(t *cleanupTarget) *core.Error {
	q := core.ShellQuote
	switch t.Kind {
	case "eventlog", "log":
		// A named event log is a bounded unit; wevtutil cl clears exactly it.
		t.PreviewCmd = fmt.Sprintf("wevtutil gli %s | findstr /i numberOfRecords", q(t.Path))
		t.DeleteStep = []string{"wevtutil cl " + q(t.Path)}
	case "history":
		if strings.TrimSpace(t.Pattern) == "" {
			return core.InvalidInput("history 清理必须提供 pattern（按行匹配删除）")
		}
		t.PreviewCmd = fmt.Sprintf("findstr /c:%s %s | find /c /v \"\"", q(t.Pattern), q(t.Path))
		t.DeleteStep = []string{fmt.Sprintf("powershell -NoProfile -Command \"(Get-Content -LiteralPath %s) | Where-Object { $_ -notmatch %s } | Set-Content -LiteralPath %s\"", q(t.Path), q(t.Pattern), q(t.Path))}
	case "file":
		t.PreviewCmd = fmt.Sprintf("dir %s", q(t.Path))
		t.DeleteStep = []string{"del /f /q " + q(t.Path)}
	default:
		return core.InvalidInput("Windows 不支持的 kind: " + t.Kind + "（可选 eventlog|log|history|file）")
	}
	return nil
}
