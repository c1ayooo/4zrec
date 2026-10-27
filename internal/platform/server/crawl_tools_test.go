package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCrawlSameHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/index.html":
			_, _ = w.Write([]byte(`<html><body>
				<a href="/about">关于</a>
				<a href="/static/app.js">js</a>
				<a href="https://external.example.com/page">外域</a>
				<a href="#top">锚点</a>
			</body></html>`))
		case "/about":
			// 回链首页:应被去重,不再入队
			_, _ = w.Write([]byte(`<html><body><a href="/">首页</a><a href="/contact">联系</a></body></html>`))
		case "/contact":
			_, _ = w.Write([]byte(`<html><body>contact</body></html>`))
		case "/static/app.js":
			t.Errorf("静态资源不应被抓取")
			_, _ = w.Write([]byte(`console.log(1)`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res := crawlSameHost(t.Context(), srv.Client(), srv.URL+"/", 30, 2)
	if res.fetched != 3 { // / /about /contact;static 被排除
		t.Fatalf("fetched = %d, want 3 (statuses=%v endpoints=%v)", res.fetched, res.statuses, res.endpoints)
	}
	if len(res.external) != 1 || !res.external["external.example.com"] {
		t.Fatalf("external = %v, want external.example.com", res.external)
	}
	for _, ep := range res.endpoints {
		if strings.Contains(ep, "static/app.js") {
			t.Fatalf("静态资源混入 endpoints: %v", res.endpoints)
		}
	}
}

func TestCrawlSameHostDepthCap(t *testing.T) {
	// 深度 0:只抓起点,不跟进链接
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><a href="/deep">deep</a></body></html>`))
	}))
	defer srv.Close()

	res := crawlSameHost(t.Context(), srv.Client(), srv.URL+"/", 30, 0)
	if res.fetched != 1 {
		t.Fatalf("depth=0 fetched = %d, want 1", res.fetched)
	}
}

func TestDirProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin panel"))
		case "/secret":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
		case "/gone":
			w.WriteHeader(http.StatusGone)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	paths := []string{"/admin", "/secret", "/gone", "/missing", "", "no-slash"}
	hits := dirProbe(t.Context(), srv.Client(), strings.TrimSuffix(srv.URL, "/"), paths)
	if len(hits) != 2 {
		t.Fatalf("hits = %+v, want 2 (/admin 200, /secret 403)", hits)
	}
	if hits[0].path != "/admin" || hits[0].status != 200 {
		t.Fatalf("first hit = %+v", hits[0])
	}
	if hits[1].path != "/secret" || hits[1].status != 403 {
		t.Fatalf("second hit = %+v", hits[1])
	}
}
