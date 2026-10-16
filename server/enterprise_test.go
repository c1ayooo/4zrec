package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/datasource"
	"github.com/c1ayooo/4zrec/enterprise"
)

// fakeEntProvider 最小 Provider 替身(BFS 上限与工具链路验证用)。
type fakeEntProvider struct{}

func (fakeEntProvider) Name() string { return "aqc" }
func (fakeEntProvider) Search(_ context.Context, kw string, _ int) ([]enterprise.CompanyRef, error) {
	return []enterprise.CompanyRef{{ExtID: "fake-1", Name: kw + "有限公司"}}, nil
}
func (fakeEntProvider) Detail(_ context.Context, _ string) (*enterprise.CompanyDetail, error) {
	return &enterprise.CompanyDetail{}, nil
}
func (fakeEntProvider) Branches(_ context.Context, _ string, _, _ int) ([]enterprise.CompanyRef, bool, error) {
	return nil, false, nil
}
func (fakeEntProvider) Investments(_ context.Context, _ string, _, _ int) ([]enterprise.CompanyRef, bool, error) {
	return nil, false, nil
}
func (fakeEntProvider) Domains(_ context.Context, extID string, _, _ int) ([]enterprise.DomainHit, bool, error) {
	return []enterprise.DomainHit{{Domain: fmt.Sprintf("ent-%s.example", extID), ICP: "京ICP备00000001号"}}, false, nil
}

// TestEnterpriseSearchToolSessionMissing 未配置会话:明确提示 ICP 替代路径。
func TestEnterpriseSearchToolSessionMissing(t *testing.T) {
	s := &Server{}
	in, _ := json.Marshal(map[string]any{"provider": "tyc", "keyword": "某集团"})
	res, err := s.toolEntSearch().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "icp_expand") {
		t.Fatalf("未配置会话应提示 ICP 替代路径: %s", res.Flatten())
	}
}

// TestEnterpriseVaultAndBFS 真库:vault 加密往返(明文不落库)+ BFS 深度/节点
// 上限 + 候选落池。无库跳过。
func TestEnterpriseVaultAndBFS(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stk, err := s.entStores()
	if err != nil {
		t.Fatal(err)
	}
	// vault:保存 → 元数据 Configured → 密文列不含明文 cookie。
	if _, err := stk.vault.Upsert(datasource.UpsertRequest{
		Owner: "platform", Provider: "aqc", Config: map[string]string{"cookie": "BIDUID=fake; BAIDUID=fake2"},
	}); err != nil {
		t.Fatal(err)
	}
	metas, _ := stk.vault.List("", "", true)
	found := false
	for _, mt := range metas {
		if mt.Provider == "aqc" && mt.Configured {
			found = true
		}
	}
	if !found {
		t.Fatal("vault 会话未保存")
	}
	var cipher string
	if err := m.pg.QueryRow(`SELECT config_ciphertext FROM datasource_sessions WHERE provider='aqc'`).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cipher, "BIDUID=fake") {
		t.Fatal("vault 明文泄漏:cookie 未加密")
	}

	// BFS 上限:depth=99/maxNodes=99999 → 钳到 3/store 上限。
	job, err := stk.collector.Start(context.Background(), fakeEntProvider{}, enterprise.Job{
		ProjectID: "0", Provider: "aqc", Depth: 99, MaxNodes: 99999,
	}, enterprise.CompanyRef{ExtID: "fake-1"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM enterprise_jobs`) }()
	if job.Depth != 3 || job.MaxNodes > 5000 {
		t.Fatalf("BFS 上限未生效: %+v", job)
	}
	// 收尾轮询(fake provider 秒级完成)。
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		j, err := stk.store.GetJob(context.Background(), job.ID)
		if err == nil && j.Status != "running" {
			if j.Domains < 1 {
				t.Fatalf("候选域名未落池: %+v", j)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("BFS 任务未在期限内完成")
}
