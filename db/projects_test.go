package db

import (
	"testing"
)

// =====================================================================
// 项目围栏:范围匹配 + 授权状态机
// =====================================================================

func TestMatchProjectScope(t *testing.T) {
	rules := []ProjectScope{
		{ID: 1, Kind: "domain", Domain: "example.com"},
		{ID: 2, Kind: "cidr", Net: "10.0.0.0/16"},
		{ID: 3, Kind: "ip", Net: "192.168.1.5/32"},
		{ID: 4, Kind: "icp", Value: "京ICP备12345678号"},
		{ID: 5, Kind: "keyword", Value: "example corp"},
	}
	cases := []struct {
		domain, ip string
		want       bool
	}{
		{"example.com", "", true},           // 根域本身
		{"sub.example.com", "", true},        // 一级子域
		{"a.b.example.com", "", true},        // 多级子域
		{"notexample.com", "", false},        // 后缀伪装不命中
		{"evil.com", "", false},              // 无关域名
		{"", "10.0.5.9", true},               // CIDR 内
		{"", "10.1.0.1", false},              // CIDR 外
		{"", "192.168.1.5", true},            // 单 IP 精确
		{"", "192.168.1.6", false},           // 单 IP 邻居
		{"", "", false},                      // 空输入
	}
	for _, tc := range cases {
		if _, got := MatchProjectScope(rules, tc.domain, tc.ip); got != tc.want {
			t.Errorf("MatchProjectScope(%q,%q) = %v, want %v", tc.domain, tc.ip, got, tc.want)
		}
	}
	// icp/keyword 是提示规则,永不参与围栏判定(上面 Value 项未命中任何 domain/ip 已覆盖)。
}

// TestProjectFenceLifecycle 端到端:建项目→录范围→发现资产打标(范围内自动批/
// 范围外 pending)→意图闸门拒 pending→人工批准→放行;拒绝为终态。
func TestProjectFenceLifecycle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	p, err := d.Projects().CreateProject("围栏测试项目", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)

	added, _, invalid, errMsgs := d.Projects().AddProjectScope(p.ID, []string{"scope-test.example", "10.99.0.0/16", "999.888.777.1"}, "测试")
	if added != 2 || invalid != 1 {
		t.Fatalf("scope 录入 added=%d invalid=%d msgs=%v", added, invalid, errMsgs)
	}

	// 范围内子域 → approved;范围外 → pending
	inID, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: "in.scope-test.example", TaskID: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, inID)
	outID, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: "out-of-scope.example", TaskID: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, outID)

	if authz, err := d.Assets().StampDiscoveredAsset(inID, p.ID); err != nil || authz != "approved" {
		t.Fatalf("范围内资产应自动批: authz=%q err=%v", authz, err)
	}
	if authz, err := d.Assets().StampDiscoveredAsset(outID, p.ID); err != nil || authz != "pending" {
		t.Fatalf("范围外资产应待审批: authz=%q err=%v", authz, err)
	}
	// 项目归属应被打上
	got, _ := d.Assets().GetByIDs([]int64{inID, outID})
	if len(got) != 2 || (got[0].ProjectID == nil && got[1].ProjectID == nil) {
		t.Fatalf("资产应归属项目: %+v", got)
	}

	// 意图闸门:pending 资产被拒,approved 放行
	hits, err := d.Assets().CheckAssetsIntercept(0, []int64{inID, outID})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Asset.ID != outID {
		t.Fatalf("闸门应只拒 pending 资产: %+v", hits)
	}

	// 执行侧授权判定:范围内域名授权,范围外未授权,批准过的资产授权
	if !d.AuthorizedTarget(p.ID, []string{"x.scope-test.example"}, nil) {
		t.Fatal("项目范围内的域名应视为已授权")
	}
	if d.AuthorizedTarget(p.ID, []string{"unknown.example"}, nil) {
		t.Fatal("范围外域名不应授权")
	}
	// 人工批准后资产可见为 approved(批准即授权)
	if err := d.Assets().ApproveAssetsWithProject([]int64{outID}, p.ID); err != nil {
		t.Fatal(err)
	}
	approved, _ := d.Assets().GetByIDs([]int64{outID})
	if len(approved) == 1 && approved[0].AuthzState() != "approved" {
		t.Fatalf("批准后应为 approved: %s", approved[0].Authz)
	}

	// 拒绝是终态:Stamp 不能把 rejected 翻回
	if err := d.Assets().SetAssetAuthz([]int64{outID}, "rejected"); err != nil {
		t.Fatal(err)
	}
	if authz, _ := d.Assets().StampDiscoveredAsset(outID, p.ID); authz != "rejected" {
		t.Fatalf("rejected 应为终态,不被范围命中翻回: %s", authz)
	}
	// 待审批队列
	pend, total, err := d.Assets().ListPendingAssets(p.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(pend) != 0 {
		t.Fatalf("批准/拒绝后队列应为空: total=%d", total)
	}
}

// TestRetestConversationInheritsProject 复测会话必须从漏洞所属任务继承项目
// (围栏的授权语义随任务走);任务未挂项目时会话 project_id 为空。
func TestRetestConversationInheritsProject(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	p, err := d.Projects().CreateProject("复测继承项目", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)

	task, err := d.CreateTaskWithOptions("复测继承任务", "目标", TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })

	fid, err := d.AddFinding(task.ID, 0, "retest-inherit", "测试漏洞", "high", "s", "e", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM finding_retests WHERE finding_id=$1)`, fid)
		_, _ = d.DeleteFinding(fid)
	})

	_, c, created, err := d.CreateFindingRetest(t.Context(), fid, "")
	if err != nil || !created || c == nil {
		t.Fatalf("CreateFindingRetest: created=%v c=%v err=%v", created, c, err)
	}
	got, err := d.GetConversation(c.ID)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if got.ProjectID == nil || *got.ProjectID != p.ID {
		t.Fatalf("复测会话应继承项目 %d, got %v", p.ID, got.ProjectID)
	}
}
