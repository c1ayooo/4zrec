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
