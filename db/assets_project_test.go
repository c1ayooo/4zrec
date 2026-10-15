package db

import (
	"fmt"
	"testing"
	"time"
)

// TestAssetProjectQueries 资产页「归属项目」筛选的后端查询:按项目过滤、
// 未归属项目过滤、类型条件叠加。归属写入走 ApproveAssetsWithProject
// (待审批队列批准路径,与线上写入方式一致)。
func TestAssetProjectQueries(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	p, err := d.Projects().CreateProject(fmt.Sprintf("资产项目筛选测试-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)

	subID, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("pf-sub-%d.example", suffix)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, subID)
	rootID, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: fmt.Sprintf("pf-root-%d.example", suffix)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, rootID)
	looseID, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("pf-loose-%d.example", suffix)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, looseID)

	if err := d.Assets().ApproveAssetsWithProject([]int64{subID, rootID}, p.ID); err != nil {
		t.Fatal(err)
	}

	// 按项目过滤:恰为已归属的两条。
	got, err := d.Assets().QueryByProject(p.ID, "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("QueryByProject = %d assets, want 2", len(got))
	}
	n, err := d.Assets().CountByProject(p.ID, "")
	if err != nil || n != 2 {
		t.Fatalf("CountByProject = %d err=%v, want 2", n, err)
	}

	// 类型叠加:项目内 subdomain 一条、root_domain 一条。
	got, err = d.Assets().QueryByProject(p.ID, "subdomain", 100, 0)
	if err != nil || len(got) != 1 || got[0].ID != subID {
		t.Fatalf("QueryByProject(subdomain) = %+v err=%v", got, err)
	}
	if n, err = d.Assets().CountByProject(p.ID, "root_domain"); err != nil || n != 1 {
		t.Fatalf("CountByProject(root_domain) = %d err=%v, want 1", n, err)
	}

	// 未归属项目:loose 在内,已归属两条绝不出现。
	un, err := d.Assets().QueryNoProject("subdomain", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	sawLoose := false
	for _, a := range un {
		switch a.ID {
		case looseID:
			sawLoose = true
		case subID, rootID:
			t.Fatalf("已归属项目的资产出现在未归属查询里: id=%d", a.ID)
		}
	}
	if !sawLoose {
		t.Fatal("未归属项目的资产没有出现在 QueryNoProject 结果里")
	}
	if n, err = d.Assets().CountNoProject(""); err != nil || n < 1 {
		t.Fatalf("CountNoProject = %d err=%v, want >= 1", n, err)
	}
}

// TestProjectScopeClaimsAssets 范围命中认领存量资产:域名精确匹配与网段包含
// 把 project_id IS NULL 的资产认领进项目,authz 空/pending 提为 approved;
// rejected 不复活(只升不降);不命中的不动。
func TestProjectScopeClaimsAssets(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	root := fmt.Sprintf("claim-%d.example", suffix)
	p, err := d.Projects().CreateProject(fmt.Sprintf("认领测试-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)

	// 先有资产,后录范围——认领要能吃到存量。
	subID, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("www.%s", root)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, subID)
	ipID, err := d.Assets().UpsertIP(UpsertIPReq{IP: fmt.Sprintf("10.%d.5.9", suffix%200)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, ipID)
	missID, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("miss-%d.example", suffix)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, missID)
	rejID, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("rej.%s", root)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, rejID)
	if _, err := d.Exec(`UPDATE assets SET authz='rejected' WHERE id=$1`, rejID); err != nil {
		t.Fatal(err)
	}

	added, _, invalid, errMsgs := d.Projects().AddProjectScope(p.ID, []string{root, fmt.Sprintf("10.%d.0.0/16", suffix%200)}, "测试")
	if added != 2 || invalid != 0 {
		t.Fatalf("scope 录入 added=%d invalid=%d msgs=%v", added, invalid, errMsgs)
	}

	claimed, err := d.Projects().RecomputeProjectAttribution()
	if err != nil {
		t.Fatal(err)
	}
	if claimed < 2 {
		t.Fatalf("claimed = %d, want >= 2(域名+网段)", claimed)
	}

	got, _ := d.Assets().GetByIDs([]int64{subID, ipID, missID, rejID})
	byID := map[int64]*Asset{}
	for _, a := range got {
		byID[a.ID] = a
	}
	// 域名命中:归属项目 + approved(root_domain 由子域推导,同根命中)。
	if a := byID[subID]; a == nil || a.ProjectID == nil || *a.ProjectID != p.ID || a.AuthzState() != "approved" {
		t.Fatalf("域名命中资产未被认领: %+v", a)
	}
	// 网段命中:归属项目。
	if a := byID[ipID]; a == nil || a.ProjectID == nil || *a.ProjectID != p.ID {
		t.Fatalf("网段命中资产未被认领: %+v", a)
	}
	// 不命中:保持未归属。
	if a := byID[missID]; a == nil || a.ProjectID != nil {
		t.Fatalf("不命中资产不应被认领: %+v", a)
	}
	// rejected 终态:范围命中也不复活(只升不降)。
	if a := byID[rejID]; a == nil {
		t.Fatal("rejected 夹具资产缺失")
	} else if a.AuthzState() != "rejected" {
		t.Fatalf("rejected 资产被范围认领改写为 %s", a.AuthzState())
	}
}
