package server

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

func TestParseChatCommand(t *testing.T) {
	cases := []struct {
		msg     string
		ok      bool
		name    string
		raw     string
		args    []string
	}{
		{msg: "/bond", ok: true, name: "bond", raw: "/bond"},
		{msg: "  /bond 虎牙 167 ", ok: true, name: "bond", raw: "/bond", args: []string{"虎牙", "167"}},
		{msg: "/BOND OFF", ok: true, name: "bond", raw: "/BOND", args: []string{"OFF"}},
		{msg: "/new", ok: true, name: "new", raw: "/new"},
		{msg: "/commands", ok: true, name: "commands", raw: "/commands"},
		{msg: "/help", ok: true, name: "help", raw: "/help"},
		// 未知纯字母 token：按形似指令处理（name=""，调用方回复清单）
		{msg: "/bondx 虎牙", ok: true, name: "", raw: "/bondx", args: []string{"虎牙"}},
		// 路径/URL 形态：不是指令，透传给 agent
		{msg: "/etc/passwd", ok: false},
		{msg: "/home/c1ay/reports", ok: false},
		{msg: "https://example.com/a", ok: false},
		{msg: "你好 /bond", ok: false}, // 指令必须在首位
		{msg: "", ok: false},
		{msg: "普通消息", ok: false},
	}
	for _, c := range cases {
		cmd, ok := parseChatCommand(c.msg)
		if ok != c.ok {
			t.Fatalf("parseChatCommand(%q) ok=%v want %v", c.msg, ok, c.ok)
		}
		if !ok {
			continue
		}
		if cmd.name != c.name || cmd.raw != c.raw || strings.Join(cmd.args, ",") != strings.Join(c.args, ",") {
			t.Fatalf("parseChatCommand(%q) = %+v, want name=%q raw=%q args=%v", c.msg, cmd, c.name, c.raw, c.args)
		}
	}
}

func proj(id int64, name string, taskCount int64) db.Project {
	return db.Project{ID: id, Name: name, TaskCount: taskCount, AssetCount: id * 10}
}

func tsk(id int64, name, status string, pid int64) *db.Task {
	t := &db.Task{ID: id, Name: name, Status: status}
	if pid > 0 {
		t.ProjectID = &pid
	}
	return t
}

func TestMatchProject(t *testing.T) {
	ps := []db.Project{proj(7, "虎牙src", 3), proj(12, "Huya APP", 1), proj(33, "哔哩哔哩", 0), proj(44, "虎牙APP", 2)}
	if p, _, ok := matchProject(ps, "7"); !ok || p.ID != 7 {
		t.Fatalf("编号匹配失败: %v %v", p, ok)
	}
	if p, _, ok := matchProject(ps, "huya app"); !ok || p.ID != 12 {
		t.Fatalf("精确名(不分大小写)匹配失败: %v %v", p, ok)
	}
	if p, _, ok := matchProject(ps, "哔哩"); !ok || p.ID != 33 {
		t.Fatalf("子串唯一命中失败: %v %v", p, ok)
	}
	if _, amb, ok := matchProject(ps, "app"); ok || len(amb) != 2 {
		t.Fatalf("子串多命中应返回候选: ok=%v amb=%d", ok, len(amb))
	}
	if _, amb, ok := matchProject(ps, "不存在"); ok || amb != nil {
		t.Fatalf("未命中应 ok=false: %v %v", ok, amb)
	}
	// 编号不存在 → 未命中（不能拿编号做子串误配）
	if _, _, ok := matchProject(ps, "99"); ok {
		t.Fatal("编号不存在应未命中")
	}
}

func TestMatchTask(t *testing.T) {
	ts := []*db.Task{tsk(167, "虎牙主站", "running", 7), tsk(168, "虎牙主站-二轮", "done", 7), tsk(200, "哔哩", "created", 33)}
	if x, _, ok := matchTask(ts, "167"); !ok || x.ID != 167 {
		t.Fatalf("编号匹配失败: %v %v", x, ok)
	}
	if x, _, ok := matchTask(ts, "虎牙主站"); !ok || x.ID != 167 {
		t.Fatalf("精确名匹配失败: %v %v", x, ok)
	}
	if _, amb, ok := matchTask(ts, "主站"); ok || len(amb) != 2 {
		t.Fatalf("子串多命中应返回候选: ok=%v amb=%d", ok, len(amb))
	}
}

func TestTasksOfProject(t *testing.T) {
	ts := []*db.Task{tsk(1, "a", "running", 7), tsk(2, "b", "done", 33), tsk(3, "c", "created", 7), tsk(4, "无项目", "created", 0)}
	got := tasksOfProject(ts, 7)
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 3 {
		t.Fatalf("tasksOfProject = %v", got)
	}
}

func TestTaskStatusZH(t *testing.T) {
	cases := []struct {
		t    *db.Task
		want string
	}{
		{tsk(1, "", "running", 0), "运行中"},
		{tsk(1, "", "done", 0), "已完成"},
		{tsk(1, "", "created", 0), "已创建"},
		{tsk(1, "", "failed", 0), "已失败"},
		{tsk(1, "", "timeout", 0), "已超时"},
		{tsk(1, "", "custom", 0), "custom"},
		{func() *db.Task { x := tsk(1, "", "running", 0); x.Paused = true; return x }(), "已暂停"},
		{func() *db.Task { x := tsk(1, "", "running", 0); x.Queued = true; return x }(), "排队中"},
	}
	for _, c := range cases {
		if got := taskStatusZH(c.t); got != c.want {
			t.Fatalf("taskStatusZH(%+v) = %q want %q", c.t, got, c.want)
		}
	}
}

func TestFormatLists(t *testing.T) {
	ps := []db.Project{proj(7, "虎牙src", 3)}
	if got := formatProjectList(ps); got != "- #7 虎牙src（任务 3 · 资产 70）" {
		t.Fatalf("formatProjectList = %q", got)
	}
	if got := formatProjectList(nil); got != "（无项目）" {
		t.Fatalf("formatProjectList(nil) = %q", got)
	}
	ts := []*db.Task{tsk(167, "", "running", 7)}
	if got := formatTaskList(ts); got != "- #167 未命名任务（运行中）" {
		t.Fatalf("formatTaskList = %q", got)
	}
	// 截断：超出 limit 给余量提示
	many := make([]*db.Task, 0, bondTaskListLimit+2)
	for i := 0; i < bondTaskListLimit+2; i++ {
		many = append(many, tsk(int64(100+i), "x", "created", 7))
	}
	got := formatTaskList(many)
	if !strings.Contains(got, "另有 2 个任务略") || strings.Count(got, "\n") != bondTaskListLimit {
		t.Fatalf("formatTaskList 截断异常:\n%s", got)
	}
}

func TestConvIDFromSession(t *testing.T) {
	if got := convIDFromSession("conv-42"); got != 42 {
		t.Fatalf("convIDFromSession(conv-42) = %d", got)
	}
	for _, s := range []string{"", "task-1", "conv-", "conv-0", "conv-x", "conv--1"} {
		if got := convIDFromSession(s); got != 0 {
			t.Fatalf("convIDFromSession(%q) = %d want 0", s, got)
		}
	}
}

func TestChatCommandHelp(t *testing.T) {
	h := chatCommandHelp()
	for _, want := range []string{"/bond", "/new", "/commands"} {
		if !strings.Contains(h, want) {
			t.Fatalf("help 缺少 %s:\n%s", want, h)
		}
	}
}
