package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/db"
)

// assetsBindCall 构造 HTTP 请求直调 handler,解析 JSON 返回。
func assetsBindCall(t *testing.T, s *Server, body []byte) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/assets/bind", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	s.assetsBind(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应解析失败: %v (%s)", err, rec.Body.String())
	}
	return out
}

// TestAssetsBind 手工批量认领:范围内 approved/范围外 pending/重绑幂等。
func TestAssetsBind(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	domain := fmt.Sprintf("bind-%d.example", stamp)
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("批量认领%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)
	if _, _, _, _ = m.pg.Projects().AddProjectScope(p.ID, []string{domain}, "测试"); err != nil {
		t.Fatal(err)
	}

	inID, _ := m.pg.Assets().UpsertSubdomain(db.UpsertSubdomainReq{Domain: "in." + domain})
	outID, _ := m.pg.Assets().UpsertSubdomain(db.UpsertSubdomainReq{Domain: "out.of.example"})
	defer func() { _, _ = m.pg.Exec(`DELETE FROM assets WHERE id IN ($1,$2)`, inID, outID) }()

	body, _ := json.Marshal(map[string]any{"project_id": p.ID, "ids": []int64{inID, outID}})
	res := assetsBindCall(t, s, body)
	// 手工归属 = 人工批准:直接 approved,不进待审批。
	if res["approved"].(float64) != 2 || res["pending"].(float64) != 0 {
		t.Fatalf("手工归属应直接 approved: %v", res)
	}
	// 幂等:重绑计数不变。子资产跟随:根域名下新子域自动归属(级联按 root_domain)。
	childID, _ := m.pg.Assets().UpsertSubdomain(db.UpsertSubdomainReq{Domain: "late." + domain})
	defer func() { _, _ = m.pg.Exec(`DELETE FROM assets WHERE id=$1`, childID) }()
	res2 := assetsBindCall(t, s, body)
	if res2["bound"].(float64) != 2 {
		t.Fatalf("重绑应幂等: %v", res2)
	}
	var childProj int64
	if err := m.pg.QueryRow(`SELECT COALESCE(project_id,0) FROM assets WHERE id=$1`, childID).Scan(&childProj); err != nil || childProj != p.ID {
		t.Fatalf("新子域应经级联归属: %v %d", err, childProj)
	}
}
