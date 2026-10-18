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

	"github.com/c1ayooo/4zrec/internal/capability/web/webrecon"
	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// TestUnauthProbeTarget 未授权探测靶标:开放端点命中 + SPA 壳不误报 + 403 bypass。
func TestUnauthProbeTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// bypass 变体:请求打在 / 上,原路径在 X-Original-URL 头里。
		if r.Header.Get("X-Original-URL") == "/api/admin/users" {
			_, _ = w.Write([]byte(`{"users":[{"name":"admin"}]}`))
			return
		}
		switch {
		case r.URL.Path == "/actuator/env":
			_, _ = w.Write([]byte(`{"activeProfiles":["prod"]}`))
		case r.URL.Path == "/api/admin/users" && r.Header.Get("X-Original-URL") != "":
			// bypass 变体才放行:主请求 403。
			_, _ = w.Write([]byte(`{"users":[{"name":"admin"}]}`))
		case r.URL.Path == "/api/admin/users":
			w.WriteHeader(http.StatusForbidden)
		case r.URL.Path == "/":
			// SPA 壳:200 + html + root div —— 不应判命中。
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><div id="root"></div></body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	hits, truncated := webrecon.UnauthSweep(context.Background(), srv.URL, []string{"/actuator/env", "/api/admin/users", "/"}, nil, true)
	if truncated {
		t.Fatal("小字典不应耗尽 bypass 预算")
	}
	var hasEnv, hasBypass bool
	for _, h := range hits {
		if h.Path == "/actuator/env" && h.Status == 200 {
			hasEnv = true
		}
		if h.Path == "/api/admin/users" && h.Variant == "x-original-url" {
			hasBypass = true
		}
		if h.Path == "/" {
			t.Fatalf("SPA 壳不应命中: %+v", h)
		}
	}
	if !hasEnv || !hasBypass {
		t.Fatalf("命中不全: env=%v bypass=%v hits=%+v", hasEnv, hasBypass, hits)
	}
}

// TestJSReconTarget JS 侦察靶标:script src 拉取、API 路径提取、泄露提取。
func TestJSReconTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><head><script src="/static/app.9f2c.js"></script></head></html>`))
		case "/static/app.9f2c.js":
			_, _ = w.Write([]byte(`var c={"/api/user/list","/api/order/detail"};
fetch("/api/admin/config");var JWT_SECRET="hb-secret-2024";var dbUrl="postgres://u:p@10.0.0.1/x";
var AK="LTAI5tFakeKey12345678";`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	res := webrecon.JSReconFetch(srv.URL, nil)
	var hasAPI, hasSecret, hasConn bool
	for _, ep := range res.Endpoints {
		if strings.Contains(ep, "/api/user/list") || strings.Contains(ep, "/api/admin/config") {
			hasAPI = true
		}
	}
	for _, l := range res.Leaks {
		if strings.Contains(l.Key, "JWT") {
			hasSecret = true
		}
		if l.Key == "DB_CONN" {
			hasConn = true
		}
	}
	if !hasAPI || !hasSecret || !hasConn {
		t.Fatalf("提取不全: api=%v secret=%v conn=%v res=%+v", hasAPI, hasSecret, hasConn, res)
	}
}

// TestUnauthProbeRoERejected 挂项目上下文时范围外目标硬拒绝(真库,无库跳过)。
func TestUnauthProbeRoERejected(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	p, err := m.pg.Projects().CreateProject(fmt.Sprintf("webreconRoE%d", stamp), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.Projects().DeleteProject(p.ID)
	if _, _, _, _ = m.pg.Projects().AddProjectScope(p.ID, []string{fmt.Sprintf("ok-%d.example", stamp)}, "测试"); err != nil {
		t.Fatal(err)
	}

	in, _ := json.Marshal(map[string]any{
		"url": "http://evil.example:8080", "project_id": p.ID,
	})
	res, err := s.toolUnauthProbe().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "RoE") {
		t.Fatalf("范围外目标应被 RoE 拒绝: %s", res.Flatten())
	}

	// 范围内主机放行(404 靶标,零命中也算跑通)。
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ok.Close()
	in2, _ := json.Marshal(map[string]any{"url": ok.URL, "extra_paths": []string{"/x"}, "bypass": false})
	res2, err := s.toolUnauthProbe().Call(context.Background(), in2, nil)
	if err != nil || res2.IsError {
		t.Fatalf("无项目上下文应放行(权限层另管): %v %s", err, res2.Flatten())
	}
}

var _ = db.MatchProjectScope
