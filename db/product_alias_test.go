package db

// 变更4：指纹归一化回归（真连 PostgreSQL，无库跳过）。

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func productAliasTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// paPrefix 每用例一次性唯一前缀：库是持久的，跨运行不撞键；同用例内所有键必须
// 由同一前缀派生（断言才能对上）。
func paPrefix(t *testing.T) string {
	return fmt.Sprintf("%s:%d", t.Name(), time.Now().UnixNano())
}

func paCleanupAliases(t *testing.T, d *DB) {
	t.Cleanup(func() {
		_, _ = d.ExecContext(context.Background(),
			`DELETE FROM product_alias WHERE alias_key LIKE $1`, t.Name()+":%")
	})
}

func TestNormalizeTechnologiesFailOpenAndAlias(t *testing.T) {
	d := productAliasTestDB(t)
	paCleanupAliases(t, d)
	ctx := context.Background()
	pref := paPrefix(t)
	mk := func(s string) string { return pref + ":" + s }

	raw := []string{" " + mk("Nginx") + " ", mk("nginx"), mk("Apache")}
	got := d.NormalizeTechnologies(raw)
	// 无别名（fail-open）：原样透传、不丢不重映射
	if len(got) != 3 || got[0] != raw[0] || got[1] != raw[1] || got[2] != raw[2] {
		t.Fatalf("fail-open 透传失真: %v", got)
	}

	// 未知键应挂待归类行（canonical 空串）
	var c string
	if err := d.QueryRowContext(ctx,
		`SELECT canonical FROM product_alias WHERE alias_key = $1`, aliasKey(mk("nginx"))).Scan(&c); err != nil {
		t.Fatalf("待归类行缺失: %v", err)
	}
	if c != "" {
		t.Fatalf("待归类行 canonical 应为空: %q", c)
	}

	// 设别名后：大小写/空白变体全部归一到规范名并去重
	if err := d.SetProductAlias(mk("nginx"), mk("Nginx"), "test"); err != nil {
		t.Fatal(err)
	}
	got = d.NormalizeTechnologies(raw[:2])
	if len(got) != 1 || got[0] != mk("Nginx") {
		t.Fatalf("别名归一+去重失败: %v", got)
	}
}

func TestNormalizeTechnologiesEmpty(t *testing.T) {
	d := productAliasTestDB(t)
	if got := d.NormalizeTechnologies(nil); got != nil {
		t.Errorf("空输入应原样返回")
	}
}

func TestBootstrapAndRewrite(t *testing.T) {
	d := productAliasTestDB(t)
	paCleanupAliases(t, d)
	ctx := context.Background()
	as := d.Assets()

	pref := paPrefix(t) + ":Foo"
	url := fmt.Sprintf("https://pa-test-%d.example.invalid", time.Now().UnixNano())
	assetID, err := as.UpsertHTTPService(UpsertHTTPServiceReq{
		URL: url, PageTitle: "pa-bootstrap", Technologies: []string{pref, " " + pref},
	})
	if err != nil {
		t.Fatalf("造数失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.ExecContext(context.Background(), `DELETE FROM assets WHERE id = $1`, assetID)
	})

	if _, err := d.BootstrapProductAliases(ctx); err != nil {
		t.Fatalf("播种失败: %v", err)
	}
	var c string
	if err := d.QueryRowContext(ctx,
		`SELECT canonical FROM product_alias WHERE alias_key = $1`, aliasKey(pref)).Scan(&c); err != nil {
		t.Fatalf("播种别名键缺失: %v", err)
	}
	// 频次并列取字典序小者（输入只有 Foo 形态的空白变体，trim 后同为 Foo）
	if c != pref {
		t.Fatalf("规范名应取频次最高（并列取字典序小）: %q", c)
	}

	if _, err := d.RewriteAssetsTechnologiesToCanonical(ctx); err != nil {
		t.Fatalf("回填失败: %v", err)
	}
	var techsJSON string
	if err := d.QueryRowContext(ctx,
		`SELECT array_to_json(technologies)::text FROM assets WHERE id = $1`, assetID).Scan(&techsJSON); err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	var techs []string
	if err := json.Unmarshal([]byte(techsJSON), &techs); err != nil {
		t.Fatalf("technologies 解析失败: %v", err)
	}
	if len(techs) != 1 || techs[0] != pref {
		t.Fatalf("存量应归一为规范名: %v", techs)
	}
}
