package successsignal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchFamiliesAndCap(t *testing.T) {
	// /admin/login 同时命中 admin-console 与 auth-entry（+/login），加 api-docs 共 3 族
	pts, hits := Match([]string{"/admin/login", "/swagger/index.html"})
	if pts != 10 { // 6+5+3=14 → 封顶 10
		t.Fatalf("期望封顶 10，得到 %d（hits=%v）", pts, hits)
	}
	if len(hits) != 3 {
		t.Fatalf("期望 3 族命中，得到 %v", hits)
	}

	pts, hits = Match([]string{"/index.html", "/static/app.js"})
	if pts != 0 || hits != nil {
		t.Fatalf("无命中应返回 0/nil，得到 %d/%v", pts, hits)
	}

	// 同族多路径只计一次
	pts, _ = Match([]string{"/actuator/env", "/actuator/heapdump"})
	if pts != 6 {
		t.Fatalf("同族去重应得 6，得到 %d", pts)
	}

	// 空入参
	if pts, _ = Match(nil); pts != 0 {
		t.Fatalf("nil 入参应 0 分，得到 %d", pts)
	}
}

func TestOverrideLoadAndMerge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "success-signals.yaml")
	body := "families:\n" +
		"  - name: admin-console\n    points: 9\n    patterns: [\"/inner-admin\"]\n" +
		"  - name: custom-family\n    points: 2\n    patterns: [\"/widget/\"]\n" +
		"  - name: bad-family\n    points: 0\n    patterns: []\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := LoadOverridesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(builtin)+1 { // 覆盖 1 个 + 新增 1 个（非法条目被剔除）
		t.Fatalf("生效族数 %d 不符（内置 %d + 新增 1）", n, len(builtin))
	}
	// 覆盖后的 admin-console 只认新模式、分值 9
	pts, hits := Match([]string{"/inner-admin/"})
	if pts != 9 || len(hits) != 1 {
		t.Fatalf("覆盖族未生效: pts=%d hits=%v", pts, hits)
	}
	if pts, _ = Match([]string{"/admin/panel"}); pts != 0 {
		t.Fatalf("被覆盖的内置模式不应再命中，得到 %d", pts)
	}
	// 新增族可命中
	if pts, _ = Match([]string{"/widget/preview"}); pts != 2 {
		t.Fatalf("新增族未生效，得到 %d", pts)
	}

	// 文件不存在：内置表兜底
	if n, err := LoadOverridesFile(filepath.Join(dir, "nope.yaml")); err != nil || n != 0 {
		t.Fatalf("缺失文件应 (0,nil)，得到 (%d,%v)", n, err)
	}
}
