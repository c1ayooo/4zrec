package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/toolface/intercept"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// stubEngineServer 起一个 fofa 形态的引擎桩:按 icp/company 过滤值回行。
func stubEngineServer(t *testing.T, rows []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("qbase64")
		_ = q
		results := make([][]any, 0, len(rows))
		for _, row := range rows {
			results = append(results, []any{
				row["host"], row["ip"], float64(443), row["domain"], "标题", "https",
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": false, "size": len(results), "page": 1, "total": len(results), "results": results,
		})
	}))
}

// TestIcpExpandQueryAndAuthorize 端到端:配置 key→查询候选→关联键提取→
// (权限层 Ask)→authorize 写入项目范围并认领。真连 PostgreSQL,无库跳过。
func TestIcpExpandQueryAndAuthorize(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	stub := stubEngineServer(t, []map[string]any{
		{"host": fmt.Sprintf("www.icp-%d.example", stamp), "ip": "203.0.113.9", "domain": fmt.Sprintf("www.icp-%d.example", stamp)},
		{"host": fmt.Sprintf("api.icp-%d.example", stamp), "ip": "203.0.113.10", "domain": fmt.Sprintf("api.icp-%d.example", stamp)},
	})
	defer stub.Close()
	if err := m.pg.SetSetting("spacemap.key.fofa", "test-key"); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting("spacemap.baseurl.fofa", stub.URL); err != nil {
		t.Fatal(err)
	}

	tool := s.toolIcpExpand()
	// 1) 查询段:候选域名出现在输出。
	qin, _ := json.Marshal(map[string]any{"icp": "粤ICP备14006354号", "engines": []string{"fofa"}})
	res, err := tool.Call(context.Background(), qin, nil)
	if err != nil || res.IsError {
		t.Fatalf("查询段失败: err=%v res=%+v", err, res)
	}
	out := res.Flatten()
	if !strings.Contains(out, fmt.Sprintf("www.icp-%d.example", stamp)) {
		t.Fatalf("候选域名缺失:\n%s", out)
	}

	// 2) 授权段权限语义(2026-10-18 收紧后):
	//    a. 无任务/会话项目上下文 → 直接拒绝(不能借 authorize 自批任意项目);
	//    b. 有项目上下文 → 必须 Ask(人工确认),不得静默放行。
	ain, _ := json.Marshal(map[string]any{
		"authorize": true, "project_id": 0,
		"domains": []string{fmt.Sprintf("icp-%d.example", stamp)},
	})
	if d := tool.CheckPermissions(context.Background(), ain, actool.Context{}); d.Behavior != actool.Deny {
		t.Fatalf("无项目上下文的 authorize 必须拒绝,得到 %v", d.Behavior)
	}

	// 3) 授权执行:写入项目范围并认领(建项目→挂任务上下文→授权→范围规则存在)。
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("icp扩查测试%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)
	task, err := m.pg.CreateTask("icp扩查授权段", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Exec(`UPDATE tasks SET project_id=$1 WHERE id=$2`, p.ID, task.ID); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) }()
	taskCtx := intercept.WithTaskContext(context.Background(), strconv.FormatInt(task.ID, 10), "test", nil)
	if d := tool.CheckPermissions(taskCtx, ain, actool.Context{}); d.Behavior != actool.Ask {
		t.Fatalf("authorize 必须经人工确认,得到 %v", d.Behavior)
	}
	ain2, _ := json.Marshal(map[string]any{
		"authorize": true, "project_id": p.ID,
		"domains": []string{fmt.Sprintf("icp-%d.example", stamp)},
	})
	res2, err := tool.Call(taskCtx, ain2, nil)
	if err != nil || res2.IsError {
		t.Fatalf("授权段失败: err=%v res=%+v", err, res2.Flatten())
	}
	rules, err := m.pg.ProjectScopeRules(p.ID)
	if err != nil || len(rules) == 0 {
		t.Fatalf("范围规则未写入: %v %v", rules, err)
	}
	if _, ok := db.MatchProjectScope(rules, fmt.Sprintf("x.icp-%d.example", stamp), ""); !ok {
		t.Fatalf("范围规则未生效于子域: %+v", rules)
	}
}

// TestCertExpandGenericOrgBlocked 通用主体组织黑名单:无库也能跑(拒绝发生在
// 引擎调用之前)。
func TestCertExpandGenericOrgBlocked(t *testing.T) {
	s := &Server{}
	tool := s.toolCertExpand()
	in, _ := json.Marshal(map[string]any{"org": "Cloudflare, Inc."})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "通用主体") {
		t.Fatalf("通用主体组织应被拒: %s", res.Flatten())
	}
	// 权限层照常放行(只读查询语义,黑名单在业务层)。
	if d := tool.CheckPermissions(context.Background(), in, actool.Context{}); d.Behavior != actool.Allow {
		t.Fatalf("查询语义应在权限层放行: %v", d.Behavior)
	}
}
