package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/db"
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

// TestDecideFenceAskAuthorizesOnlyCheckedTargets 审批卡上的逐目标复选:一次
// 审批带多个目标时,只把用户勾选的目标登记为 approved;未勾选的保持未授权,
// 但本次调用仍按人工允许执行。
func TestDecideFenceAskAuthorizesOnlyCheckedTargets(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	stamp := time.Now().UnixNano()
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("围栏复选-%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)
	pid := p.ID

	task, err := m.pg.CreateTaskWithOptions("围栏复选任务", "目标", db.TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.DeleteTask(task.ID)

	keep := fmt.Sprintf("keep-%d.example", stamp)
	skip := fmt.Sprintf("skip-%d.example", stamp)
	keepIP := "203.0.113.77"
	targets, _ := json.Marshal(map[string]any{"domains": []string{keep, skip}, "ips": []string{keepIP}})
	ask, err := m.pg.CreateInterceptPending(0, 0, strconv.FormatInt(task.ID, 10), "worker", "Bash",
		[]byte(fmt.Sprintf(`{"command":"nmap %s %s %s"}`, keep, skip, keepIP)),
		"【资产围栏】目标资产不在项目授权范围内："+keep+"、"+skip+"。若确属本次委托范围，请批准；否则请拒绝并改测授权内资产。")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM intercept_pending WHERE id=$1`, ask) })
	if err := m.pg.SetInterceptTargets(ask, targets); err != nil {
		t.Fatal(err)
	}

	// 项目维度过滤:同一个挂起审批在项目页能看到,结构化目标原样返回。
	pendingRows, err := m.pg.ListPendingInterceptsByProject(pid)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pendingRows {
		if p.ID == ask {
			found = true
			if len(p.Targets) == 0 {
				t.Fatal("按项目查询应带回结构化 targets")
			}
		}
	}
	if !found {
		t.Fatal("项目过滤应包含本项目的挂起审批")
	}
	if _, total, err := m.pg.ListProjectInterceptsPage(pid, 1, 20, db.InterceptApprovalFilter{}); err != nil || total == 0 {
		t.Fatalf("项目审批历史应包含本项目记录: total=%d err=%v", total, err)
	}

	s := &Server{m: m}
	body, _ := json.Marshal(map[string]any{"decision": "allowed", "targets": []string{keep, keepIP}})
	req := httptest.NewRequest("POST", "/api/intercept/pending/1/decide", bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(ask, 10))
	w := httptest.NewRecorder()
	s.interceptDecide(w, req)
	if w.Code != 200 {
		t.Fatalf("decide http %d: %s", w.Code, w.Body.String())
	}

	d, err := m.pg.GetInterceptDetail(ask)
	if err != nil || d == nil || d.Status != "allowed" {
		t.Fatalf("审批应已允许: %+v err=%v", d, err)
	}
	if !m.pg.AuthorizedTarget(pid, []string{keep}, nil) {
		t.Fatal("勾选的域名应获批")
	}
	if m.pg.AuthorizedTarget(pid, []string{skip}, nil) {
		t.Fatal("未勾选的域名不应获批")
	}
	if !m.pg.AuthorizedTarget(pid, nil, []string{keepIP}) {
		t.Fatal("勾选的 IP 应获批")
	}

	// 显式全不选(targets:[]):本次仍允许执行,但一个目标都不登记。
	none := fmt.Sprintf("none-%d.example", stamp)
	ntargets, _ := json.Marshal(map[string]any{"domains": []string{none}})
	askNone, err := m.pg.CreateInterceptPending(0, 0, strconv.FormatInt(task.ID, 10), "worker", "Bash",
		[]byte(fmt.Sprintf(`{"command":"nmap %s"}`, none)),
		"【资产围栏】目标资产不在项目授权范围内："+none+"。若确属本次委托范围，请批准；否则请拒绝并改测授权内资产。")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM intercept_pending WHERE id=$1`, askNone) })
	if err := m.pg.SetInterceptTargets(askNone, ntargets); err != nil {
		t.Fatal(err)
	}
	bodyNone, _ := json.Marshal(map[string]any{"decision": "allowed", "targets": []string{}})
	reqNone := httptest.NewRequest("POST", "/api/intercept/pending/1/decide", bytes.NewReader(bodyNone))
	reqNone.SetPathValue("id", strconv.FormatInt(askNone, 10))
	wNone := httptest.NewRecorder()
	s.interceptDecide(wNone, reqNone)
	if wNone.Code != 200 {
		t.Fatalf("decide http %d: %s", wNone.Code, wNone.Body.String())
	}
	if m.pg.AuthorizedTarget(pid, []string{none}, nil) {
		t.Fatal("显式全不选时不应授权任何目标")
	}
}
