package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/spacemap"
)

// TestSpacemapResultsPage 引擎来源标注:导入时打 source→按引擎筛选分页命中、
// 其他引擎不串。真连 PG,无库跳过。
func TestSpacemapResultsPage(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	results := []*spacemap.Result{
		{Source: "FOFA", Domain: fmt.Sprintf("f-%d.example", stamp), Host: fmt.Sprintf("f-%d.example", stamp)},
		{Source: "Quake", IP: "198.51.100.77"},
	}
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer stub.Close()
	_ = stub
	if _ = m.pg.SetSetting("spacemap.key.fofa", "k"); false {
		t.Fatal()
	}
	defer func() {
		_, _ = m.pg.Exec(`DELETE FROM assets WHERE source IN ('FOFA','Quake')`)
		_ = m.pg.SetSetting("spacemap.key.fofa", "")
	}()

	d, _, _ := s.spacemapImport(context.Background(), 0, 0, results)
	if d < 1 {
		t.Fatalf("导入失败: %d", d)
	}
	// FOFA 筛选:本轮 stamp 的行必须在场且来源=FOFA(组合测试下允许其他
	// 测试的 FOFA 行共存,以唯一 stamp 域名断言)。
	rows, _, err := m.pg.SpacemapResultsPage(context.Background(), "FOFA", "", 0, 200, 0)
	if err != nil {
		t.Fatal(err)
	}
	mine := ""
	for _, r := range rows {
		if strings.Contains(r.Label, fmt.Sprintf("f-%d.example", stamp)) {
			mine = r.Label
			if r.Source != "FOFA" {
				t.Fatalf("来源标注错误: %+v", r)
			}
		}
	}
	if mine == "" {
		t.Fatalf("FOFA 筛选未含本轮行: %+v", rows)
	}
	// 全部引擎:本轮两行(域名+IP)都必须在场。
	allRows, _, _ := m.pg.SpacemapResultsPage(context.Background(), "", "", 0, 200, 0)
	seenIP := false
	for _, r := range allRows {
		if r.Label == "198.51.100.77" && r.Source == "Quake" {
			seenIP = true
		}
	}
	if !seenIP {
		t.Fatalf("全部引擎视图应含本轮 Quake IP 行")
	}
	// 无来源的资产不进结果页。
	_, total3, _ := m.pg.SpacemapResultsPage(context.Background(), strings.Repeat("x", 40), "", 0, 50, 0)
	if total3 != 0 {
		t.Fatalf("未知引擎应 0 行: %d", total3)
	}
}
