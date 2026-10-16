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

// TestConnectionProjectBindAndMerge 项目绑定(硬前提)+幂等合并+自动捕获路径:
// 无项目上下文不落库并提示;登记→落库;重录(secret 空)→保留原 secret 不新建;
// autoCaptureConnection(有项目)→更新 source/status。
func TestConnectionProjectBindAndMerge(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	host := fmt.Sprintf("conn-%d.internal", stamp)
	defer func() { _, _ = m.pg.Exec(`DELETE FROM connections WHERE host=$1`, host) }()

	// 无项目 → 手工登记被拒(需要项目上下文)。
	inNoProj, _ := json.Marshal(map[string]any{"kind": "ssh", "host": host})
	res0, _ := s.toolCredentialRegister().Call(context.Background(), inNoProj, nil)
	if !res0.IsError || !strings.Contains(res0.Flatten(), "项目") {
		t.Fatalf("无项目应拒绝登记: %s", res0.Flatten())
	}

	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("连接台账测试%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)

	// 登记(手工)。
	in1, _ := json.Marshal(map[string]any{
		"kind": "ssh", "host": host, "username": "root", "secret": "pw1", "note": "任务发现", "project_id": p.ID,
	})
	res, err := s.toolCredentialRegister().Call(context.Background(), in1, nil)
	if err != nil || res.IsError {
		t.Fatalf("登记失败: %v %s", err, res.Flatten())
	}
	rows, err := m.pg.ListConnections(context.Background(), p.ID, "ssh", 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("应落 1 行: %v %v", rows, err)
	}
	if rows[0].Secret != "pw1" || rows[0].Port != 22 || rows[0].Status != "unknown" {
		t.Fatalf("字段不符(端口应默认22): %+v", rows[0])
	}

	// 重录(secret 空)→ 合并:保留 pw1,note 更新,行数不变。
	in2, _ := json.Marshal(map[string]any{
		"kind": "ssh", "host": host, "username": "root", "note": "二次确认", "project_id": p.ID,
	})
	if res2, _ := s.toolCredentialRegister().Call(context.Background(), in2, nil); res2.IsError {
		t.Fatalf("重录失败: %s", res2.Flatten())
	}
	rows2, _ := m.pg.ListConnections(context.Background(), p.ID, "ssh", 10)
	if len(rows2) != 1 || rows2[0].Secret != "pw1" || rows2[0].Note != "二次确认" {
		t.Fatalf("合并语义不符: %+v", rows2)
	}

	// 自动捕获(有项目上下文):用 task 上下文解析需要任务,直接注入验证核心路径——
	// autoCaptureConnection 在无任务/会话上下文时 roeProjectID 返回 0 → 提示不落库;
	// 这里以 UpsertConnection 直调验证 discovered 语义与状态回写。
	id, created, err := m.pg.UpsertConnection(context.Background(), &db.Connection{
		ProjectID: p.ID, Kind: "ssh", Host: host, Port: 22, Username: "root",
		Secret: "pw1", Source: "discovered", Status: "alive", Note: "credential_verify_ssh 验证成功",
	})
	if err != nil || created {
		t.Fatalf("同键应合并: created=%v %v", created, err)
	}
	rows3, _ := m.pg.ListConnections(context.Background(), p.ID, "ssh", 10)
	if len(rows3) != 1 || rows3[0].Status != "alive" || rows3[0].Source != "manual" {
		t.Fatalf("状态应回写 alive 且 source 手工优先不被降级: %+v", rows3[0])
	}
	_ = id
}
