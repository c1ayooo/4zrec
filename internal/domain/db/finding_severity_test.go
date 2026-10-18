package db

import (
	"context"
	"strings"
	"testing"
)

// TestSetFindingReportWithSeverityOnlyDowngrades 钉住 reporter 的「仅降不升」：
// 上调请求被忽略且保留原等级，下调才写入 findings 行并同步探索节点 payload。
func TestSetFindingReportWithSeverityOnlyDowngrades(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("报告定级测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)
	nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x", "severity": SeverityHigh}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := d.AddFinding(tk.ID, nodeID, "未授权读取", "未授权读取", SeverityHigh, "summary", "poc", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id=$1`, fid)

	ctx := context.Background()

	// 上调：忽略请求，等级保持 high。
	n, eff, downgraded, err := d.SetFindingReportWithSeverityByNodeID(ctx, nodeID, "# report\n", nil, SeverityCritical)
	if err != nil || n != 1 {
		t.Fatalf("upgrade: n=%d err=%v", n, err)
	}
	if downgraded || eff != SeverityHigh {
		t.Fatalf("upgrade must be ignored: downgraded=%v effective=%q", downgraded, eff)
	}
	one, err := d.GetFinding(fid)
	if err != nil || one.Severity != SeverityHigh {
		t.Fatalf("upgrade changed severity: %+v err=%v", one, err)
	}

	// 下调：写入 medium，并同步探索节点 payload。
	n, eff, downgraded, err = d.SetFindingReportWithSeverityByNodeID(ctx, nodeID, "# report\n\n## 1.4\n", nil, SeverityMedium)
	if err != nil || n != 1 {
		t.Fatalf("downgrade: n=%d err=%v", n, err)
	}
	if !downgraded || eff != SeverityMedium {
		t.Fatalf("downgrade not applied: downgraded=%v effective=%q", downgraded, eff)
	}
	one, err = d.GetFinding(fid)
	if err != nil || one.Severity != SeverityMedium {
		t.Fatalf("finding severity not downgraded: %+v err=%v", one, err)
	}
	var payload []byte
	if err := d.QueryRow(`SELECT payload FROM exploration_nodes WHERE id=$1`, nodeID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"medium"`) {
		t.Fatalf("node payload severity not synced: %s", payload)
	}

	// 同等级：不重复写入，返回当前等级。
	_, eff, downgraded, err = d.SetFindingReportWithSeverityByNodeID(ctx, nodeID, "report 2", nil, SeverityMedium)
	if err != nil || downgraded || eff != SeverityMedium {
		t.Fatalf("equal severity: downgraded=%v effective=%q err=%v", downgraded, eff, err)
	}
}

// TestSetFindingReportSeverityFloor 验证 reporter 不能把未授权管理员接管
// 压到 critical 以下；服务端会拒绝保存并保留原等级。
func TestSetFindingReportSeverityFloor(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("定级下限测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)
	nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x", "severity": SeverityHigh}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := d.AddFinding(tk.ID, nodeID, "认证绕过 / 未授权访问",
		"未授权管理员注册接口导致创建 admin 账号并接管 OA",
		SeverityHigh, "无需认证创建 role_code=admin 管理员账号并登录接管",
		"POST /api/test/admin-register\n{\"code\":0}\nrole_code: admin", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id=$1`, fid)

	ctx := context.Background()
	if _, _, _, err := d.SetFindingReportWithSeverityByNodeID(ctx, nodeID, "# report", nil, SeverityMedium); err == nil ||
		!strings.Contains(err.Error(), "低于服务端下限") {
		t.Fatalf("medium below floor should be rejected, err=%v", err)
	}
	one, err := d.GetFinding(fid)
	if err != nil || one.Severity != SeverityHigh {
		t.Fatalf("rejected write must keep severity: %+v err=%v", one, err)
	}

	n, eff, downgraded, err := d.SetFindingReportWithSeverityByNodeID(ctx, nodeID, "# report critical", nil, SeverityCritical)
	if err != nil || n != 1 || eff != SeverityCritical || downgraded {
		t.Fatalf("critical accepted: n=%d eff=%q downgraded=%v err=%v", n, eff, downgraded, err)
	}
	one, err = d.GetFinding(fid)
	if err != nil || one.Severity != SeverityCritical {
		t.Fatalf("floor must raise severity: %+v err=%v", one, err)
	}
}
