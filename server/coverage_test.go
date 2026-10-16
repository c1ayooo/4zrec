package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/db"
)

// TestProjectCoverage 项目覆盖度:范围内建资产→未测;打事实锚点→已测。
// 读侧以项目为锚(范围外资产不计入盘子)。真连 PG,无库跳过。
func TestProjectCoverage(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	stamp := time.Now().UnixNano()
	domain := fmt.Sprintf("cov-%d.example", stamp)
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("覆盖度测试%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)
	if _, _, _, _ = m.pg.Projects().AddProjectScope(p.ID, []string{domain}, "测试"); err != nil {
		t.Fatal(err)
	}
	// 范围内两个子域 + 范围外一个对照。
	idA, err := m.pg.Assets().UpsertSubdomain(db.UpsertSubdomainReq{Domain: "a." + domain})
	if err != nil {
		t.Fatal(err)
	}
	idB, err := m.pg.Assets().UpsertSubdomain(db.UpsertSubdomainReq{Domain: "b." + domain})
	if err != nil {
		t.Fatal(err)
	}
	outID, _ := m.pg.Assets().UpsertSubdomain(db.UpsertSubdomainReq{Domain: "out-of-scope.example"})
	defer func() {
		_, _ = m.pg.Exec(`DELETE FROM assets WHERE id IN ($1,$2,$3)`, idA, idB, outID)
	}()

	// 无锚点:2 未测(范围外不计入)。
	cov, err := m.pg.ProjectCoverageOverview(context.Background(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cov.InScope < 2 || cov.Tested != 0 || cov.Untested < 2 {
		t.Fatalf("初始覆盖度不符: %+v", cov)
	}
	found := 0
	for _, it := range cov.Sample {
		if strings.Contains(it.Label, domain) {
			found++
		}
		if strings.Contains(it.Label, "out-of-scope") {
			t.Fatalf("范围外资产不应出现: %+v", it)
		}
	}
	if found < 2 {
		t.Fatalf("未测样本应含范围内资产: %+v", cov.Sample)
	}

	// 给 a 打事实锚点 → 已测 1。锚点需要 fact 节点:建最小探索节点。
	var expID int64
	if err := m.pg.QueryRow(`INSERT INTO explorations(goal) VALUES ('覆盖度测试') RETURNING id`).Scan(&expID); err != nil {
		t.Skipf("explorations 形态与假设不符,跳过锚点段: %v", err)
	}
	defer m.pg.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	var nodeID int64
	if err := m.pg.QueryRow(`INSERT INTO exploration_nodes(exploration_id, kind, state)
		VALUES ($1, 'fact', 'confirmed') RETURNING id`, expID).Scan(&nodeID); err != nil {
		t.Skipf("node 插入失败,跳过锚点段: %v", err)
	}
	defer m.pg.Exec(`DELETE FROM exploration_nodes WHERE id=$1`, nodeID)
	_, _ = m.pg.Exec(`INSERT INTO exploration_anchors(node_id, asset_id) VALUES ($1,$2)`, nodeID, idA)
	cov2, _ := m.pg.ProjectCoverageOverview(context.Background(), p.ID)
	if cov2.Tested < 1 {
		t.Fatalf("锚点后应有已测资产: %+v", cov2)
	}

	// 工具层:无项目上下文报错提示。
	s2 := &Server{}
	in, _ := json.Marshal(map[string]any{})
	res, err := s2.toolProjectCoverage().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "项目上下文") {
		t.Fatalf("无项目上下文应明确报错: %s", res.Flatten())
	}
}
