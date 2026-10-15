package db

import (
	"fmt"
	"testing"
	"time"
)

// TestFindingsFilterByProject 项目详情页漏洞 tab 的后端:finding 经
// task.project_id 归属项目,ProjectID 过滤只命中项目内任务的发现。
func TestFindingsFilterByProject(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	p, err := d.Projects().CreateProject(fmt.Sprintf("漏洞项目筛选-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)
	pid := p.ID

	inTask, err := d.CreateTaskWithOptions("项目内任务", "目标", TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(inTask.ID)
	outTask, err := d.CreateTask("项目外任务", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(outTask.ID)

	mk := func(tk *Task, vulnclass string) {
		t.Helper()
		es := d.Exploration(tk.ExplorationID)
		nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "s", "severity": "high"}, 5, "confirmed", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.AddFinding(tk.ID, nodeID, vulnclass, vulnclass, "high", "summary", "poc", "worker", nil); err != nil {
			t.Fatal(err)
		}
	}
	mk(inTask, fmt.Sprintf("PROJIN-%d", suffix))
	mk(outTask, fmt.Sprintf("PROJOUT-%d", suffix))

	// 按项目过滤:只有项目内任务的那条。
	fs, total, err := d.ListFindingsPage(FindingFilter{ProjectID: pid}, 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(fs) != 1 || fs[0].VulnClass != fmt.Sprintf("PROJIN-%d", suffix) {
		t.Fatalf("project filter: total=%d findings=%+v, want only PROJIN", total, fs)
	}

	// 不过滤(ProjectID=0)时本夹具两条都在,证明上一条不是夹具本身只有一条。
	for _, vc := range []string{fmt.Sprintf("PROJIN-%d", suffix), fmt.Sprintf("PROJOUT-%d", suffix)} {
		if _, total, err = d.ListFindingsPage(FindingFilter{VulnClass: vc}, 1, 20); err != nil || total != 1 {
			t.Fatalf("unfiltered %s: total=%d err=%v, want 1", vc, total, err)
		}
	}
}
