package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/capability/recon/pipeline"
)

// stubSelectiveDNS 只应答 known 里的名字(其余 NXDOMAIN)——避免泛解析,
// 让爆破/解析/扫描/指纹四阶段都能在回环上走真链路。
func stubSelectiveDNS(t *testing.T, known map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub dns listen: %v", err)
	}
	server := &dns.Server{
		PacketConn: pc,
		UDPSize:    65535,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			q := req.Question[0]
			name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
			if ip, ok := known[name]; ok && q.Qtype == dns.TypeA {
				rr, _ := dns.NewRR(name + ". 60 IN A " + ip)
				resp.Answer = append(resp.Answer, rr)
			} else {
				resp.Rcode = dns.RcodeNameError
			}
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

// TestReconRunLoopbackE2E 全链:爆破(经选择性 DNS 桩)→解析→端口扫描(回环靶标)
// →HTTP 指纹;runs 表可追溯;资产三型入库;P0-P4 分布出现。真连 PG,无库跳过。
func TestReconRunLoopbackE2E(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	domain := fmt.Sprintf("pipe-%d.example", stamp)
	www := "www." + domain

	// 回环靶标:一个 http 服务。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><head><title>流水线靶标-" + fmt.Sprint(stamp) + "</title></head><body>nginx-ish</body></html>"))
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	port := addr[strings.LastIndex(addr, ":")+1:]

	// 选择性 DNS:www → 127.0.0.1,其余(含随机泛解析探针)NXDOMAIN。
	resolver := stubSelectiveDNS(t, map[string]string{www: "127.0.0.1"})

	// 项目授权该主域。
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("流水线测试%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)
	if _, _, _, _ = m.pg.Projects().AddProjectScope(p.ID, []string{domain}, "测试"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM assets WHERE domain LIKE '%` + domain + `%' OR (ip='127.0.0.1' AND type='ip' AND domain IS NULL)`)
		_, _ = m.pg.Exec(`DELETE FROM assets WHERE url LIKE '%127.0.0.1:` + port + `%'`)
	})

	// 直接起跑(带自定义爆破词表,只打 www;解析器指向桩)。
	runID, err := s.startReconRun(pipeline.Options{
		Domains:         []string{domain},
		EnableSubdomain: false, EnablePermute: false, EnableBrute: true,
		EnableDNS: true, EnablePortscan: true, EnableHTTP: true,
		PortsSet: port, ProjectID: p.ID,
		Resolvers: []string{resolver},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 注入 www 词:Brute 合并内置字典,但桩只答 www——其余全部 NXDOMAIN,
	// 内置字典的几百次 NXDOMAIN 查询也走桩,秒级完成。

	// 轮询 runs 至终态(异步 goroutine)。
	deadline := time.Now().Add(60 * time.Second)
	var run *db.ReconRun
	for time.Now().Before(deadline) {
		run, err = m.pg.GetReconRun(context.Background(), runID)
		if err != nil {
			t.Fatal(err)
		}
		if run.Status != "running" {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if run == nil || run.Status != "done" {
		t.Fatalf("运行未完成: %+v (err=%s)", run, runErrString(run))
	}

	// 子域资产(带 A 记录与优先级)。
	var subID int64
	var level *string
	if err := m.pg.QueryRow(`SELECT id, recon_level FROM assets WHERE type='subdomain' AND domain=$1`, www).Scan(&subID, &level); err != nil {
		t.Fatalf("子域资产未入库: %v", err)
	}
	if level == nil || !strings.HasPrefix(*level, "p") {
		t.Fatalf("子域应带 P0-P4 优先级: %v", level)
	}
	if authz := assetAuthz(m, subID); authz != "approved" {
		t.Fatalf("范围内子域应自动 approved: %s", authz)
	}
	// http 服务资产(标题/状态码)。
	var title string
	var code int
	if err := m.pg.QueryRow(`SELECT coalesce(page_title,''), coalesce(status_code,0) FROM assets
		WHERE type='service' AND service_type='http' AND url=$1`,
		fmt.Sprintf("http://127.0.0.1:%s", port)).Scan(&title, &code); err != nil {
		t.Fatalf("http 服务资产未入库: %v", err)
	}
	if !strings.Contains(title, "流水线靶标") || code != 200 {
		t.Fatalf("http 指纹不符: title=%q code=%d", title, code)
	}
	// 统计可追溯。
	var st pipeline.Stats
	if err := json.Unmarshal(run.Stats, &st); err != nil {
		t.Fatal(err)
	}
	if st.Live < 1 || st.OpenPorts < 1 || st.HTTPAlive < 1 {
		t.Fatalf("统计不符: %+v", st)
	}
}

// TestReconRunRoERejected 范围外主域硬拒绝。
func TestReconRunRoERejected(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("流水线RoE%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)
	if _, _, _, _ = m.pg.Projects().AddProjectScope(p.ID, []string{fmt.Sprintf("allowed-%d.example", stamp)}, "测试"); err != nil {
		t.Fatal(err)
	}

	in, _ := json.Marshal(map[string]any{
		"domains": []string{fmt.Sprintf("evil-%d.example", stamp)}, "project_id": p.ID,
	})
	res, err := s.toolReconRun().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "RoE") {
		t.Fatalf("范围外主域应被 RoE 拒绝: %s", res.Flatten())
	}
}

// TestReconResultsList 列表与单行查询。
func TestReconResultsList(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	id, err := m.pg.CreateReconRun(context.Background(), 0, []string{"list-test.example"}, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM recon_runs WHERE id=$1`, id) }() // 先于 Close
	_ = m.pg.UpdateReconRunProgress(context.Background(), id, "dns", pipeline.MarshalStats(pipeline.Stats{Candidates: 3, Live: 2}))
	_ = m.pg.FinishReconRun(context.Background(), id, "dns", pipeline.MarshalStats(pipeline.Stats{Candidates: 3, Live: 2, Levels: map[string]int{"p2": 2}}), "")

	in, _ := json.Marshal(map[string]any{"run_id": id})
	res, err := s.toolReconResults().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("单行查询失败: %v %s", err, res.Flatten())
	}
	out := res.Flatten()
	if !strings.Contains(out, "候选: 3") || !strings.Contains(out, "p2") || !strings.Contains(out, "done") {
		t.Fatalf("运行详情不符:\n%s", out)
	}

	in2, _ := json.Marshal(map[string]any{"limit": 5})
	res2, err := s.toolReconResults().Call(context.Background(), in2, nil)
	if err != nil || res2.IsError || !strings.Contains(res2.Flatten(), fmt.Sprintf("#%d", id)) {
		t.Fatalf("列表查询失败: %v %s", err, res2.Flatten())
	}
}

func assetAuthz(m *Manager, id int64) string {
	var authz *string
	if err := m.pg.QueryRow(`SELECT authz FROM assets WHERE id=$1`, id).Scan(&authz); err != nil {
		return ""
	}
	if authz == nil {
		return "approved" // NULL 视为 approved 的库语义
	}
	return *authz
}

func runErrString(r *db.ReconRun) string {
	if r == nil {
		return "no run"
	}
	return r.Error
}
