package db

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// =====================================================================
// 项目围栏 × 任务作用域:任务挂项目(授权根)后,作用域的种子、扩大与读取
// 都必须落在项目授权范围之内。背景:2026-10-15 woniuxy 项目的任务被规划器
// 经 add_task_scope 把「西安文理」公司整库圈进作用域,跨项目资产全量可读。
// =====================================================================

// TestTaskInheritsProjectScope 建任务挂项目时,project_scope(domain/ip/cidr)
// 种成初始 task_scope(source='project'),规划器第一轮就有范围可依;
// icp/keyword 是提示规则不构成授权,不种子。未挂项目的任务无种子行。
func TestTaskInheritsProjectScope(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	root := fmt.Sprintf("inherit-%d.example", suffix)
	cidr := fmt.Sprintf("10.%d.0.0/16", suffix%200)
	p, err := d.Projects().CreateProject(fmt.Sprintf("围栏继承-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)
	if added, _, invalid, msgs := d.Projects().AddProjectScope(p.ID, []string{root, cidr}, "测试"); added != 2 || invalid != 0 {
		t.Fatalf("scope 录入 added=%d invalid=%d msgs=%v", added, invalid, msgs)
	}

	task, err := d.CreateTaskWithOptions("继承任务", "目标", TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	scopes, err := d.Assets().ListTaskScopeWithSources(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 2 {
		t.Fatalf("task_scope 种子行数 = %d, want 2(根域+网段): %+v", len(scopes), scopes)
	}
	kinds := map[string]TaskScope{}
	for _, ts := range scopes {
		if ts.Source != "project" {
			t.Fatalf("种子行 source = %q, want project: %+v", ts.Source, ts)
		}
		kinds[ts.Kind] = ts
	}
	if ts := kinds["root_domain"]; ts.Domain != root {
		t.Fatalf("root_domain 种子 = %q, want %q", ts.Domain, root)
	}
	if ts := kinds["cidr"]; ts.Net != cidr {
		t.Fatalf("cidr 种子 = %q, want %q", ts.Net, cidr)
	}

	// 未挂项目的任务:不种子(旧行为)。
	loose, err := d.CreateTaskWithOptions("无项目任务", "目标", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(loose.ID)
	if scopes, err := d.Assets().ListTaskScopeWithSources(loose.ID); err != nil || len(scopes) != 0 {
		t.Fatalf("未挂项目任务 task_scope = %+v err=%v, want 空", scopes, err)
	}
}

// TestAddAgentScopeFencedByProject 挂项目的任务经 add_task_scope 扩大范围时,
// 新增行必须落在项目授权范围内:范围内子域放行,范围外公司/根域/IP/CIDR 与
// 提示类规则(icp/keyword)一律拒绝;未挂项目任务保持旧行为。
func TestAddAgentScopeFencedByProject(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	root := fmt.Sprintf("fence-%d.example", suffix)
	other := fmt.Sprintf("other-%d.example", suffix)
	cidr := fmt.Sprintf("10.%d.0.0/16", suffix%200)
	p, err := d.Projects().CreateProject(fmt.Sprintf("围栏拒绝-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)
	if added, _, invalid, msgs := d.Projects().AddProjectScope(p.ID, []string{root, cidr}, "测试"); added != 2 || invalid != 0 {
		t.Fatalf("scope 录入 added=%d invalid=%d msgs=%v", added, invalid, msgs)
	}

	companyName := fmt.Sprintf("围栏外公司-%d", suffix)
	companyID, _, _, _, _, err := d.Companies().CreateCompanyWithScope(companyName, "", []ScopeInput{
		{Kind: "domain", Value: other},
	}, "测试")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Companies().DeleteCompany(companyID)

	task, err := d.CreateTaskWithOptions("围栏内任务", "目标", TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	// 范围内:子域/根域落在授权根下 → 放行。
	if _, err := d.Assets().AddAgentScope(task.ID, "subdomain", fmt.Sprintf("www.%s", root), "测试", "agent"); err != nil {
		t.Fatalf("范围内子域被拒: %v", err)
	}
	if _, err := d.Assets().AddAgentScope(task.ID, "root_domain", fmt.Sprintf("sub.%s", root), "测试", "agent"); err != nil {
		t.Fatalf("范围内根域被拒: %v", err)
	}
	if _, err := d.Assets().AddAgentScope(task.ID, "ip", fmt.Sprintf("10.%d.5.9", suffix%200), "测试", "agent"); err != nil {
		t.Fatalf("范围内 IP 被拒: %v", err)
	}

	// 范围外:整库公司/别的根域/网段外 IP 与 CIDR → 拒绝,报错要提到围栏。
	for _, tc := range []struct{ kind, value string }{
		{"company", companyName},
		{"root_domain", other},
		{"subdomain", fmt.Sprintf("www.%s", other)},
		{"ip", "192.0.2.9"},
		{"cidr", "192.0.2.0/24"},
		{"icp", "京ICP备12345号"},
	} {
		if _, err := d.Assets().AddAgentScope(task.ID, tc.kind, tc.value, "测试", "agent"); err == nil {
			t.Fatalf("范围外 %s=%s 未被围栏拒绝", tc.kind, tc.value)
		} else if !strings.Contains(err.Error(), "围栏") {
			t.Fatalf("范围外 %s=%s 的报错未提围栏: %v", tc.kind, tc.value, err)
		}
	}

	// 未挂项目任务:company 仍可加(旧行为,围栏不启用)。
	loose, err := d.CreateTaskWithOptions("无项目任务", "目标", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(loose.ID)
	if _, err := d.Assets().AddAgentScope(loose.ID, "company", companyName, "测试", "agent"); err != nil {
		t.Fatalf("未挂项目任务 company scope 被误拒: %v", err)
	}
}

// TestCreateTaskForeignCompanyFenced 建任务时的「关联企业」也要过围栏:
// 挂项目任务只能关联项目所属企业;项目未挂企业时不允许关联任何企业。
func TestCreateTaskForeignCompanyFenced(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	ownName := fmt.Sprintf("项目自有企业-%d", suffix)
	foreignName := fmt.Sprintf("外来企业-%d", suffix)
	ownID, _, _, _, _, err := d.Companies().CreateCompanyWithScope(ownName, "", []ScopeInput{
		{Kind: "domain", Value: fmt.Sprintf("own-%d.example", suffix)},
	}, "测试")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Companies().DeleteCompany(ownID)
	foreignID, _, _, _, _, err := d.Companies().CreateCompanyWithScope(foreignName, "", []ScopeInput{
		{Kind: "domain", Value: fmt.Sprintf("foreign-%d.example", suffix)},
	}, "测试")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Companies().DeleteCompany(foreignID)

	p, err := d.Projects().CreateProject(fmt.Sprintf("企业围栏-%d", suffix), &ownID, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)

	if _, err := d.CreateTaskWithOptions("外来企业任务", "目标", TaskCreateOptions{
		ProjectID: &p.ID, CompanyIDs: []int64{foreignID},
	}); err == nil {
		t.Fatal("挂项目任务关联外来企业未被拒绝")
	}
	orphanProject, err := d.Projects().CreateProject(fmt.Sprintf("无主-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(orphanProject.ID)
	if _, err := d.CreateTaskWithOptions("无主项目关联企业", "目标", TaskCreateOptions{
		ProjectID: &orphanProject.ID, CompanyIDs: []int64{ownID},
	}); err == nil {
		t.Fatal("未挂企业的项目关联企业未被拒绝")
	}

	ok, err := d.CreateTaskWithOptions("自有企业任务", "目标", TaskCreateOptions{
		ProjectID: &p.ID, CompanyIDs: []int64{ownID},
	})
	if err != nil {
		t.Fatalf("关联项目自有企业被误拒: %v", err)
	}
	defer d.DeleteTask(ok.ID)
}

// TestScopeReadsIntersectProject 读取路径兜底:即使 task_scope 被漂移写入了
// 项目范围之外的行(直插模拟——经 ② 后 agent 路径已写不进去),挂项目任务的
// 资产读取仍与项目授权范围求交,跨项目资产不可见、不可按 id 直取、不入待测
// 集合;未挂项目任务不受影响。
func TestScopeReadsIntersectProject(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	rootA := fmt.Sprintf("proj-a-%d.example", suffix)
	rootB := fmt.Sprintf("proj-b-%d.example", suffix)
	pa, err := d.Projects().CreateProject(fmt.Sprintf("求交A-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(pa.ID)
	pb, err := d.Projects().CreateProject(fmt.Sprintf("求交B-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(pb.ID)
	if added, _, invalid, msgs := d.Projects().AddProjectScope(pa.ID, []string{rootA}, "测试"); added != 1 || invalid != 0 {
		t.Fatalf("A scope 录入 added=%d invalid=%d msgs=%v", added, invalid, msgs)
	}
	if added, _, invalid, msgs := d.Projects().AddProjectScope(pb.ID, []string{rootB}, "测试"); added != 1 || invalid != 0 {
		t.Fatalf("B scope 录入 added=%d invalid=%d msgs=%v", added, invalid, msgs)
	}

	inA, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("www.%s", rootA)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, inA)
	inB, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("www.%s", rootB)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, inB)
	orphan, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("orphan-%d.example", suffix)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, orphan)
	if _, err := d.Projects().RecomputeProjectAttribution(); err != nil {
		t.Fatal(err)
	}

	task, err := d.CreateTaskWithOptions("求交任务", "目标", TaskCreateOptions{ProjectID: &pa.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	// 漂移:直插一条项目范围外的 task_scope(模拟绕过工具层的脏数据/存量)。
	if _, err := d.Exec(`INSERT INTO task_scope(task_id, kind, domain, source, reason)
VALUES ($1, 'root_domain', $2, 'agent', '漂移夹具') ON CONFLICT DO NOTHING`, task.ID, rootB); err != nil {
		t.Fatal(err)
	}

	// DSL 查询:B 的资产即使在 task_scope 里也不可见。
	got, err := d.Assets().QueryDSLInScope(fmt.Sprintf("root_domain=%s", rootB), "", task.ID, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("跨项目资产经 DSL 泄漏: %+v", got)
	}
	got, err = d.Assets().QueryDSLInScope(fmt.Sprintf("root_domain=%s", rootA), "", task.ID, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[int64]bool{}
	for _, a := range got {
		ids[a.ID] = true
	}
	if !ids[inA] {
		t.Fatal("项目内资产应可见")
	}
	if ids[inB] || ids[orphan] {
		t.Fatal("项目外资产经 list_assets 泄漏")
	}

	// 按 id 直取:范围外的 id 被丢弃。
	got, err = d.Assets().GetByIDsInScope(task.ID, []int64{inA, inB, orphan})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != inA {
		t.Fatalf("GetByIDsInScope 越界: got %+v", got)
	}

	// 待测集合(覆盖度 CTE):同样只含项目内。
	backlog, total, err := d.Assets().ListUntestedAssetsWithSources(task.ID, "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range backlog {
		if c.ID == inB || c.ID == orphan {
			t.Fatalf("项目外资产进入待测集合: %+v", c)
		}
	}
	if total < 1 {
		t.Fatalf("待测集合为空, 项目内资产丢失: total=%d", total)
	}

	// 未挂项目任务:旧行为,task_scope 指到哪读到哪。
	loose, err := d.CreateTaskWithOptions("无项目求交对照", "目标", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(loose.ID)
	if _, err := d.Exec(`INSERT INTO task_scope(task_id, kind, domain, source, reason)
VALUES ($1, 'root_domain', $2, 'agent', '对照夹具') ON CONFLICT DO NOTHING`, loose.ID, rootB); err != nil {
		t.Fatal(err)
	}
	got, err = d.Assets().QueryDSLInScope(fmt.Sprintf("domain=%s", rootB), "subdomain", loose.ID, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	sawB := false
	for _, a := range got {
		if a.ID == inB {
			sawB = true
		}
	}
	if !sawB {
		t.Fatal("未挂项目任务的读取被误伤(应保持旧行为)")
	}
}

// TestClaimAssetToProject 手工资产归属项目:只认领 project_id IS NULL 的资产
// (不抢别项目的),authz 空/pending 提为 approved,rejected 终态不复活。
func TestClaimAssetToProject(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	p, err := d.Projects().CreateProject(fmt.Sprintf("认领接口-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)
	q, err := d.Projects().CreateProject(fmt.Sprintf("认领接口他项目-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(q.ID)

	free, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("free-%d.example", suffix)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, free)
	rej, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("rej-%d.example", suffix)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, rej)
	if _, err := d.Exec(`UPDATE assets SET authz='rejected' WHERE id=$1`, rej); err != nil {
		t.Fatal(err)
	}
	taken, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("taken-%d.example", suffix)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, taken)
	if err := d.Assets().ApproveAssetsWithProject([]int64{taken}, q.ID); err != nil {
		t.Fatal(err)
	}

	claimed, err := d.Assets().ClaimAssetToProject(free, p.ID)
	if err != nil || !claimed {
		t.Fatalf("自由资产认领 claimed=%v err=%v", claimed, err)
	}
	claimed, err = d.Assets().ClaimAssetToProject(free, p.ID)
	if err != nil || claimed {
		t.Fatalf("重复认领 claimed=%v err=%v(应 false)", claimed, err)
	}
	claimed, err = d.Assets().ClaimAssetToProject(rej, p.ID)
	if err != nil || !claimed {
		t.Fatalf("rejected 资产可归属项目(认领≠改授权): claimed=%v err=%v", claimed, err)
	}
	claimed, err = d.Assets().ClaimAssetToProject(taken, p.ID)
	if err != nil || claimed {
		t.Fatalf("他项目资产被抢占: claimed=%v err=%v", claimed, err)
	}

	got, err := d.Assets().GetByIDs([]int64{free, rej, taken})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]*Asset{}
	for _, a := range got {
		byID[a.ID] = a
	}
	if a := byID[free]; a.ProjectID == nil || *a.ProjectID != p.ID || a.AuthzState() != "approved" {
		t.Fatalf("自由资产认领结果异常: %+v", a)
	}
	if a := byID[rej]; a.ProjectID == nil || *a.ProjectID != p.ID || a.AuthzState() != "rejected" {
		t.Fatalf("rejected 资产被认领后授权态被改写: %+v", a)
	}
	if a := byID[taken]; a.ProjectID == nil || *a.ProjectID != q.ID {
		t.Fatalf("他项目资产归属被改动: %+v", a)
	}
}

// TestProjectScopeSeedsRootDomainAssets 项目授权域名正向生成资产:范围里的
// domain 规则本身就是一条可见的 root_domain 资产(归属项目、approved),任务
// 作用域继承后 list_assets 才有东西可读——2026-10-15:woniuxy 项目只录了两个
// 域名范围,资产表无行,规划器读 0 条,只能去翻 /etc/hosts 找目标。存量规则
// (补建)与幂等(重复 recompute 不多建)一并覆盖。
func TestProjectScopeSeedsRootDomainAssets(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	root := fmt.Sprintf("seed-%d.example", suffix)
	p, err := d.Projects().CreateProject(fmt.Sprintf("范围生资产-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)
	if added, _, invalid, msgs := d.Projects().AddProjectScope(p.ID, []string{root}, "测试"); added != 1 || invalid != 0 {
		t.Fatalf("scope 录入 added=%d invalid=%d msgs=%v", added, invalid, msgs)
	}

	scopeAsset := func() *Asset {
		rows, err := d.Assets().QueryByProject(p.ID, "root_domain", 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range rows {
			if a.RootDomain == root || a.Domain == root {
				return a
			}
		}
		return nil
	}

	// 项目详情页的「资产」与任务的 list_assets 走同一张表:范围落库后由
	// RecomputeProjectAttribution(addProjectScope handler 每次都触发)补种。
	if _, err := d.Projects().RecomputeProjectAttribution(); err != nil {
		t.Fatal(err)
	}
	a := scopeAsset()
	if a == nil {
		t.Fatal("授权域名未生成 root_domain 资产")
	}
	if a.ProjectID == nil || *a.ProjectID != p.ID {
		t.Fatalf("生成的资产未归属项目: %+v", a)
	}
	if a.AuthzState() != "approved" {
		t.Fatalf("生成的资产授权态 = %s, want approved", a.AuthzState())
	}

	// 幂等:重复 recompute 不多建。
	if _, err := d.Projects().RecomputeProjectAttribution(); err != nil {
		t.Fatal(err)
	}
	rows, err := d.Assets().QueryByProject(p.ID, "root_domain", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range rows {
		if x.RootDomain == root || x.Domain == root {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("重复 recompute 后同根资产 = %d 条, want 1", n)
	}

	// 存量补建:把资产行删掉(模拟规则先于资产的老项目),recompute 应再补上。
	var assetID int64
	if err := d.QueryRow(`SELECT id FROM assets WHERE type='root_domain' AND root_domain=$1`, root).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	deleteAsset(d, assetID)
	if _, err := d.Projects().RecomputeProjectAttribution(); err != nil {
		t.Fatal(err)
	}
	if again := scopeAsset(); again == nil {
		t.Fatal("存量规则未被补建为资产")
	}

	// 任务读取:挂项目任务的 list_assets 应能看到它。
	task, err := d.CreateTaskWithOptions("读范围资产", "目标", TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	got, err := d.Assets().QueryDSLInScope(fmt.Sprintf("root_domain=%s", root), "", task.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("任务 list_assets 读到 %d 条, want 1(授权根本身)", len(got))
	}
}
