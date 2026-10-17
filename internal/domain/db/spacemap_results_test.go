package db

import (
	"context"
	"testing"
)

// TestStampAssetSourceQuery 出处查询语法的落库语义:首次写入、已有值不覆盖
// (更早的具体查询优先),并且能被资产读取路径带出来。
func TestStampAssetSourceQuery(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	id, err := d.Assets().UpsertSubdomain(UpsertSubdomainReq{Domain: "provenance-test.example"})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, id)
	d.StampAssetSource(context.Background(), id, "Quake")
	d.StampAssetSourceQuery(context.Background(), id, `cert:"provenance-test.example"`)
	// 第二个查询不能覆盖第一个。
	d.StampAssetSourceQuery(context.Background(), id, "domain=\"other.example\"")

	got, err := d.Assets().GetByIDs([]int64{id})
	if err != nil || len(got) != 1 {
		t.Fatalf("读取资产失败: %v %+v", err, got)
	}
	if got[0].Source != "Quake" {
		t.Fatalf("source = %q", got[0].Source)
	}
	if q, _ := got[0].Extra["source_query"].(string); q != `cert:"provenance-test.example"` {
		t.Fatalf("source_query = %q", q)
	}
}
