package db

import (
	"strings"
	"testing"
	"time"
)

// TestAPIKeyLifecycle 持久 key:创建/认证/过期/撤销,项目级必须绑定 project。
func TestAPIKeyLifecycle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	p, err := d.Projects().CreateProject("APIKey测试项目", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)

	raw, key, err := d.CreateAPIKey("hermes-proj", "project", p.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteAPIKey(key.ID)
	if !strings.HasPrefix(raw, APIKeyPrefix) || key.Scope != "project" || key.ProjectID == nil || *key.ProjectID != p.ID {
		t.Fatalf("create key = %q %+v", raw, key)
	}
	// 明文不落库:库里查不到 raw。
	var n int
	_ = d.QueryRow(`SELECT count(*) FROM api_keys WHERE token_hash=$1`, raw).Scan(&n)
	if n != 0 {
		t.Fatal("token 明文不应可查")
	}
	if got, ok := d.AuthenticateAPIKey(raw); !ok || got.ID != key.ID {
		t.Fatalf("authenticate = %+v ok=%v", got, ok)
	}
	if _, ok := d.AuthenticateAPIKey("zrec_deadbeef"); ok {
		t.Fatal("错误 token 不应通过")
	}

	// 过期 key 不可用。
	past := time.Now().Add(-time.Minute)
	expiredRaw, expiredKey, err := d.CreateAPIKey("expired", "global", 0, &past)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteAPIKey(expiredKey.ID)
	if _, ok := d.AuthenticateAPIKey(expiredRaw); ok {
		t.Fatal("过期 key 不应通过")
	}

	// 项目级必须指定项目;全局 key 带 project_id 会被忽略(不报错)。
	if _, _, err := d.CreateAPIKey("bad", "project", 0, nil); err == nil {
		t.Fatal("project key 缺少 project_id 应报错")
	}
	_, badGlobal, err := d.CreateAPIKey("bad2", "global", p.ID, nil)
	if err != nil {
		t.Fatalf("global key 不应因 project_id 报错: %v", err)
	}
	defer d.DeleteAPIKey(badGlobal.ID)
	if badGlobal.ProjectID != nil {
		t.Fatal("global key 不应绑定项目")
	}

	if err := d.DeleteAPIKey(key.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.AuthenticateAPIKey(raw); ok {
		t.Fatal("删除后不应通过")
	}
}
