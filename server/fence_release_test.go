package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestAssetApprovalReleasesHangingFenceAsk 围栏审批闭环的联动半边:任务打范围外
// 资产被围栏挂起(pending 审批)→ 用户在待审批队列批准该资产 → 挂起的围栏审批
// 自动放行(阻塞的调用继续);另一条目标未获批的挂起审批不受影响。
// 另半边(审批页批 ask → authorize 就地登记资产)在 guard 的 fence 流程内,
// 批准即授权、资产随之离开待审批队列。
func TestAssetApprovalReleasesHangingFenceAsk(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	stamp := time.Now().UnixNano()
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("围栏联动-%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)
	pid := p.ID

	task, err := m.pg.CreateTaskWithOptions("围栏联动任务", "目标", db.TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.DeleteTask(task.ID)

	dom := fmt.Sprintf("hang-%d.example", stamp)
	other := fmt.Sprintf("other-%d.example", stamp)

	// 发现侧:范围外资产入库 pending(与任务发现路径同形)。
	assetID, err := m.pg.EnsureDiscoveredAsset(pid, "subdomain", dom, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Assets().DeleteByIDs([]int64{assetID}) })

	// 执行侧:两条挂起的围栏审批(与 applyFence 合成的 ask 同形:消息前缀+工具输入)。
	msg := func(target string) string {
		return fmt.Sprintf("【资产围栏】目标资产不在项目授权范围内：%s。若确属本次委托范围，请批准；否则请拒绝并改测授权内资产。", target)
	}
	ask, err := m.pg.CreateInterceptPending(0, 0, strconv.FormatInt(task.ID, 10), "worker", "Bash",
		[]byte(fmt.Sprintf(`{"command":"nmap -p 80 %s"}`, dom)), msg(dom))
	if err != nil {
		t.Fatal(err)
	}
	askOther, err := m.pg.CreateInterceptPending(0, 0, strconv.FormatInt(task.ID, 10), "worker", "Bash",
		[]byte(fmt.Sprintf(`{"command":"nmap -p 80 %s"}`, other)), msg(other))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM intercept_pending WHERE id IN ($1,$2)`, ask, askOther)
	})

	// 用户在待审批队列批准资产(与 UI 同一端点)。
	s := &Server{m: m}
	body, _ := json.Marshal(map[string]any{"ids": []int64{assetID}, "action": "approve", "project_id": pid})
	w := httptest.NewRecorder()
	s.setAssetAuthz(w, httptest.NewRequest("POST", "/api/assets/authz", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("approve http %d: %s", w.Code, w.Body.String())
	}

	// 挂起的围栏审批被联动放行;另一条(目标未获批)仍 pending。
	if d, _ := m.pg.GetInterceptDetail(ask); d == nil || d.Status != "allowed" {
		t.Fatalf("资产获批后,因它挂起的围栏审批未放行: %+v", d)
	}
	if d, _ := m.pg.GetInterceptDetail(askOther); d == nil || d.Status != "pending" {
		t.Fatalf("目标未获批的围栏审批不应被放行: %+v", d)
	}
	// 授权判定随批准生效:后续同一目标的命令不再围栏。
	if !m.pg.AuthorizedTarget(pid, []string{dom}, nil) {
		t.Fatal("批准后 AuthorizedTarget 应放行该目标")
	}
	if m.pg.AuthorizedTarget(pid, []string{other}, nil) {
		t.Fatal("未批准的目标不应放行")
	}
}
