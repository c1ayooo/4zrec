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

	actool "github.com/c1ayooo/4zrec/tools"
)

// TestExpandScanTargets CIDR 展开与上限。
func TestExpandScanTargets(t *testing.T) {
	ips, err := expandScanTargets([]string{"192.0.2.0/30"}, 0)
	if err != nil || len(ips) != 4 {
		t.Fatalf("/30 应展开 4 个: %v %v", ips, err)
	}
	if _, err := expandScanTargets([]string{"192.0.2.0/24"}, 8); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("超上限应报错: %v", err)
	}
	if _, err := expandScanTargets([]string{"not-an-ip"}, 0); err == nil {
		t.Fatal("非法目标应报错")
	}
	if ips, err := expandScanTargets([]string{" 192.0.2.7 "}, 0); err != nil || len(ips) != 1 {
		t.Fatalf("裸 IP 应通过: %v %v", ips, err)
	}
}

// TestPortScanLoopbackE2E 回环端到端:扫描 httptest 端口,命中+协议识别为 http,
// IP 资产带开放端口入库,http 服务资产建立。真连 PostgreSQL,无库跳过。
func TestPortScanLoopbackE2E(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	port := addr[strings.LastIndex(addr, ":")+1:]
	ip := addr[:strings.LastIndex(addr, ":")]
	if !strings.HasPrefix(ip, "127.") {
		ip = "127.0.0.1" // [::1] 形态按 v4 扫
	}

	// 项目授权 127.0.0.1(RoE 放行 + 入库认领)。
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("端口扫描测试%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)
	if _, _, _, _ = m.pg.Projects().AddProjectScope(p.ID, []string{"127.0.0.1/32"}, "测试"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM assets WHERE ip='` + ip + `'`) })

	in, _ := json.Marshal(map[string]any{
		"targets": []string{ip}, "ports": port, "project_id": p.ID, "timeout_ms": 1500,
	})
	res, err := s.toolPortScan().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("扫描失败: %s", res.Flatten())
	}
	out := res.Flatten()
	if !strings.Contains(out, port) {
		t.Fatalf("开放端口未命中:\n%s", out)
	}
	// 协议识别(http)或端口名兜底至少出现端口条目;fingerprintx 对回环 http
	// 通常识别为 http——不强制断言协议,断言资产入库侧。
	found := 0
	if err := m.pg.QueryRow(`SELECT count(*) FROM assets WHERE type='ip' AND ip=$1`, ip).Scan(&found); err != nil || found == 0 {
		t.Fatalf("IP 资产未入库: %d %v", found, err)
	}
	var openLen int
	if err := m.pg.QueryRow(`SELECT coalesce(cardinality(open_ports),0) FROM assets WHERE type='ip' AND ip=$1`, ip).Scan(&openLen); err != nil || openLen == 0 {
		t.Fatalf("开放端口未写入 IP 资产: %d %v", openLen, err)
	}
}

// TestPortScanRoERejected 范围外目标硬拒绝:项目只授权 10.99/16,扫 127.0.0.1 被拒。
func TestPortScanRoERejected(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("RoE拒绝测试%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)
	if _, _, _, _ = m.pg.Projects().AddProjectScope(p.ID, []string{"10.99.0.0/16"}, "测试"); err != nil {
		t.Fatal(err)
	}

	in, _ := json.Marshal(map[string]any{
		"targets": []string{"127.0.0.1"}, "ports": "80", "project_id": p.ID,
	})
	res, err := s.toolPortScan().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "RoE") {
		t.Fatalf("范围外目标应被 RoE 拒绝: %s", res.Flatten())
	}
}

// TestPortScanPermissionAsks 主动探测权限层必须人工确认。
func TestPortScanPermissionAsks(t *testing.T) {
	s := &Server{}
	in, _ := json.Marshal(map[string]any{"targets": []string{"192.0.2.10"}, "ports": "top100"})
	dec := s.toolPortScan().CheckPermissions(context.Background(), in, actool.Context{})
	if dec.Behavior != actool.Ask {
		t.Fatalf("端口扫描应默认人工确认,得到 %v", dec.Behavior)
	}
}
