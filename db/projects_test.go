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
		{"example.com", "", true},     // 根域本身
		{"sub.example.com", "", true}, // 一级子域
		{"a.b.example.com", "", true}, // 多级子域
		{"notexample.com", "", false}, // 后缀伪装不命中
		{"evil.com", "", false},       // 无关域名
		{"", "10.0.5.9", true},        // CIDR 内
		{"", "10.1.0.1", false},       // CIDR 外
		{"", "192.168.1.5", true},     // 单 IP 精确
		{"", "192.168.1.6", false},    // 单 IP 邻居
		{"", "", false},               // 空输入
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

// TestAuthorizedTargetAllMatchAndProjectIsolation 2026-10-16 围栏加固回归:
//  1. ALL 语义——混合目标里存在任一未授权项,整体不得授权(旧实现任一命中
//     即放行整条命令,nmap 授权域+未授权IP 可借道);
//  2. 项目隔离——他项目 approved 的资产不构成本项目授权;本项目围栏审批
//     不翻写他项目的资产行(rejected 终态不被他项目复活);未归属(NULL
//     project)的 approved 资产维持全局授权语义(兼容存量库)。
func TestAuthorizedTargetAllMatchAndProjectIsolation(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	pa, err := d.Projects().CreateProject("围栏隔离A", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(pa.ID)
	pb, err := d.Projects().CreateProject("围栏隔离B", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(pb.ID)

	if _, _, _, _ = d.Projects().AddProjectScope(pa.ID, []string{"iso-a.example", "10.77.0.0/16"}, "测试"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _ = d.Projects().AddProjectScope(pb.ID, []string{"iso-b.example"}, "测试"); err != nil {
		t.Fatal(err)
	}

	// ---- ALL 语义 ----
	if d.AuthorizedTarget(pa.ID, []string{"x.iso-a.example", "evil.example"}, nil) {
		t.Fatal("混合目标存在未授权域名时不应整体授权")
	}
	if d.AuthorizedTarget(pa.ID, []string{"x.iso-a.example"}, []string{"10.77.1.1", "10.99.99.99"}) {
		t.Fatal("混合目标存在未授权 IP 时不应整体授权")
	}
	if !d.AuthorizedTarget(pa.ID, []string{"x.iso-a.example", "y.iso-a.example"}, []string{"10.77.1.1"}) {
		t.Fatal("全部目标命中范围时应授权")
	}

	// ---- 项目隔离:他项目 approved 不构成本项目授权 ----
	bID, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: "b-owned.iso-b.example", TaskID: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, bID)
	if _, err = d.Assets().StampDiscoveredAsset(bID, pb.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.Assets().ApproveAssetsWithProject([]int64{bID}, pb.ID); err != nil {
		t.Fatal(err)
	}
	if d.AuthorizedTarget(pa.ID, []string{"b-owned.iso-b.example"}, nil) {
		t.Fatal("他项目 approved 资产不应构成本项目授权")
	}
	if !d.AuthorizedTarget(pb.ID, []string{"b-owned.iso-b.example"}, nil) {
		t.Fatal("本项目 approved 资产应授权")
	}

	// ---- 他项目占据的行:审批项目接管(单行模型) ----
	// assets 按类型全局唯一,同一域名只有一行。用一个不在任何项目范围里的域名
	// 演示:B 先 approved(经资产行),A 的围栏审批命中该行 → 归属移交 A、状态
	// 随 A 的审批走。安全性质:移交后仅 A 可经该行授权;B 侧(范围不覆盖该域)
	// 授权失效——"他项目审批、本项目放行"的漂移不再存在。
	sID, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: "shared-foreign.example", TaskID: 0})
	if err != nil {
		t.Fatal(err)
	}
	// UpsertSubdomain 的副作用会建同名 root_domain 行,一并清理。
	defer d.Exec(`DELETE FROM assets WHERE domain IN ('shared-foreign.example')`)
	defer deleteAsset(d, sID)
	if _, err = d.Assets().StampDiscoveredAsset(sID, pb.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.Assets().SetAssetAuthz([]int64{sID}, "approved"); err != nil {
		t.Fatal(err)
	}
	// 行归属 B 且 approved:对 A 不构成授权,对 B 构成(经资产行)。
	if d.AuthorizedTarget(pa.ID, []string{"shared-foreign.example"}, nil) {
		t.Fatal("他项目 approved 资产不应构成本项目授权")
	}
	if !d.AuthorizedTarget(pb.ID, []string{"shared-foreign.example"}, nil) {
		t.Fatal("本项目 approved 资产应授权")
	}
	// A 的围栏审批命中同一行 → 移交归属,随后 A 批准。
	aID, err := d.EnsureDiscoveredAsset(pa.ID, "subdomain", "shared-foreign.example", "")
	if err != nil {
		t.Fatal(err)
	}
	if aID != sID {
		defer deleteAsset(d, aID) // 单行模型下应复用同一行;防御性清理异常多出的行
		t.Fatalf("单行模型下应复用同一资产行: aID=%d sID=%d", aID, sID)
	}
	if err = d.Assets().SetAssetAuthz([]int64{aID}, "approved"); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Assets().GetByIDs([]int64{sID})
	if len(got) != 1 || got[0].ProjectID == nil || *got[0].ProjectID != pa.ID {
		t.Fatalf("行归属应移交给审批项目 A: %+v", got)
	}
	if !d.AuthorizedTarget(pa.ID, []string{"shared-foreign.example"}, nil) {
		t.Fatal("A 审批接管后,该目标在 A 项目内应授权")
	}
	if d.AuthorizedTarget(pb.ID, []string{"shared-foreign.example"}, nil) {
		t.Fatal("移交后 B 不得再经该行获得授权(范围不覆盖时)")
	}

	// B 的 rejected 终态语义(范围内域名):A 审批移交后,B 侧经资产行的通道
	// 已断;B 若仍可测,那必须是 B 自己的范围规则在授权——与行状态无关。
	if err = d.Assets().SetAssetAuthz([]int64{bID}, "rejected"); err != nil {
		t.Fatal(err)
	}
	if d.AuthorizedTarget(pa.ID, []string{"b-owned.iso-b.example"}, nil) {
		t.Fatal("B 范围内的 rejected 资产对 A 不得授权(项目隔离)")
	}

	// ---- 未归属(NULL project)的 approved 资产维持全局授权(存量库兼容) ----
	nID, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: "global-legacy.example", TaskID: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, nID)
	if err = d.Assets().SetAssetAuthz([]int64{nID}, "approved"); err != nil {
		t.Fatal(err)
	}
	if !d.AuthorizedTarget(pa.ID, []string{"global-legacy.example"}, nil) {
		t.Fatal("未归属的 approved 资产应维持全局授权语义")
	}
}
