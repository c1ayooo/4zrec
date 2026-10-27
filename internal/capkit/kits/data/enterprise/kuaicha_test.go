package enterprise

import (
	"context"
	"strings"
	"testing"
)

func newKc(t *testing.T, ff *stubFetcher) *kuaichaProvider {
	t.Helper()
	p, err := NewKuaichaProvider(ff, "kcsid=abc", "")
	if err != nil {
		t.Fatalf("NewKuaichaProvider = %v", err)
	}
	return p.(*kuaichaProvider)
}

func TestNewKuaichaProvider(t *testing.T) {
	if _, err := NewKuaichaProvider(newStubFetcher(), "  ", ""); !IsSessionMissing(err) {
		t.Fatalf("空 cookie 应报会话缺失, got %v", err)
	}
	p := newKc(t, newStubFetcher())
	if p.Name() != "kuaicha" {
		t.Fatalf("Name = %q", p.Name())
	}
	if p.c.headers["Cookie"] != "kcsid=abc" || p.c.headers["Source"] != "PC" {
		t.Fatalf("头未设置: %#v", p.c.headers)
	}
}

func TestKcSearch(t *testing.T) {
	ctx := context.Background()

	t.Run("成功去高亮与字段回落", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "company_search_pc", resp: json200(
			`{"data":{"list":[` +
				`{"org_id":"1","name":"<em>某某</em>科技"},` +
				`{"orgId":"2","entName":"第二公司"},` +
				`{"id":"3","companyName":"第三公司"},` +
				`{"name":"无ID"}` +
				`]}}`)})
		refs, err := newKc(t, ff).Search(ctx, "某某", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 3 || refs[0].ExtID != "1" || refs[0].Name != "某某科技" || refs[2].ExtID != "3" {
			t.Fatalf("refs = %+v", refs)
		}
	})

	t.Run("limit 截断", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "company_search_pc", resp: json200(
			`{"data":{"list":[{"org_id":"1","name":"A"},{"org_id":"2","name":"B"}]}}`)})
		refs, err := newKc(t, ff).Search(ctx, "k", 1)
		if err != nil || len(refs) != 1 {
			t.Fatalf("refs=%+v err=%v", refs, err)
		}
	})

	t.Run("请登录映射会话失效", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "company_search_pc", resp: json200(`{"data":{},"msg":"请登录后使用"}`)})
		if _, err := newKc(t, ff).Search(ctx, "k", 10); !IsSessionMissing(err) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("缺 data 字段", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "company_search_pc", resp: json200(`{"foo":1}`)})
		if _, err := newKc(t, ff).Search(ctx, "k", 10); err == nil || !strings.Contains(err.Error(), "缺少 data") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("空结果", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "company_search_pc", resp: json200(`{"data":{"list":[]}}`)})
		if _, err := newKc(t, ff).Search(ctx, "k", 10); err == nil || !strings.Contains(err.Error(), "搜索无结果") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("HTTP 错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "company_search_pc", resp: statusResp(401, "unauth")})
		if _, err := newKc(t, ff).Search(ctx, "k", 10); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestKcDetail(t *testing.T) {
	ctx := context.Background()

	t.Run("成功解析字段", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "basic/info", resp: json200(
			`{"data":{"name":"<em>某某</em>科技","legal_person":"张三","state":"存续","telphone":" 010-1 ","email":" a@b.com "}}`)})
		d, err := newKc(t, ff).Detail(ctx, "O1")
		if err != nil {
			t.Fatal(err)
		}
		if d.ExtID != "O1" || d.Name != "某某科技" || d.LegalPerson != "张三" || d.OpenStatus != "存续" ||
			d.Phone != "010-1" || d.Email != "a@b.com" {
			t.Fatalf("detail = %+v", *d)
		}
	})

	t.Run("会话失效非致命只返回 ExtID", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "basic/info", resp: json200(`{"msg":"请重新登录"}`)})
		d, err := newKc(t, ff).Detail(ctx, "O2")
		if err != nil {
			t.Fatalf("应返回空详情而非错误: %v", err)
		}
		if d.ExtID != "O2" || d.Name != "" {
			t.Fatalf("detail = %+v", *d)
		}
	})

	t.Run("缺 data 也回落空详情", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "basic/info", resp: json200(`{"foo":1}`)})
		d, err := newKc(t, ff).Detail(ctx, "O3")
		if err != nil || d.ExtID != "O3" {
			t.Fatalf("detail=%+v err=%v", d, err)
		}
	})

	t.Run("传输错误返回错误", func(t *testing.T) {
		ff := newStubFetcher()
		ff.failWith(errNoRoute)
		if _, err := newKc(t, ff).Detail(ctx, "O4"); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestKcLists(t *testing.T) {
	ctx := context.Background()

	t.Run("Branches next_page=true", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branch_office/list", resp: json200(
			`{"data":{"list":[{"org_id":"1","org_name":"<em>分公司</em>"},{"id":"2","name":"分支二"}],"next_page":true}}`)})
		refs, more, err := newKc(t, ff).Branches(ctx, "O1", 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 2 || refs[0].Name != "分公司" || !more {
			t.Fatalf("refs=%+v more=%v", refs, more)
		}
		req := ff.routeFor(t, "branch_office/list")
		if !strings.Contains(req.URL, "org_id=O1") || !strings.Contains(req.URL, "page_size=10") {
			t.Fatalf("URL 参数错误: %q", req.URL)
		}
	})

	t.Run("Branches next_page=false", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branch_office/list", resp: json200(`{"data":{"list":[]}}`)})
		_, more, err := newKc(t, ff).Branches(ctx, "O1", 1, 10)
		if err != nil || more {
			t.Fatalf("more=%v err=%v", more, err)
		}
	})

	t.Run("Investments 附带 is_latest", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "invest_abroad/list", resp: json200(
			`{"data":{"list":[{"frgn_invest_corp_id":"9","frgn_invest_corp_name":"被投企业"}],"next_page":false}}`)})
		refs, more, err := newKc(t, ff).Investments(ctx, "O1", 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 1 || refs[0].ExtID != "9" || refs[0].Name != "被投企业" || more {
			t.Fatalf("refs=%+v more=%v", refs, more)
		}
		if req := ff.routeFor(t, "invest_abroad/list"); !strings.Contains(req.URL, "is_latest=1") {
			t.Fatalf("invest URL 缺 is_latest: %q", req.URL)
		}
	})

	t.Run("列表会话失效", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branch_office/list", resp: json200(`{"msg":"请登录"}`)})
		if _, _, err := newKc(t, ff).Branches(ctx, "O1", 1, 10); !IsSessionMissing(err) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("列表 HTTP 错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branch_office/list", resp: statusResp(500, "x")})
		if _, _, err := newKc(t, ff).Branches(ctx, "O1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})

	t.Run("Domains 未开放", func(t *testing.T) {
		if _, _, err := newKc(t, newStubFetcher()).Domains(ctx, "O1", 1, 10); err == nil || !strings.Contains(err.Error(), "未开放") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestKcCompanyRefs(t *testing.T) {
	// 与 Branches 调用形态一致：nameKey=org_name, idKey=org_id。
	hits := kcCompanyRefs(gjsonArray(t, `[`+
		`{"org_id":"1","org_name":"A"},`+
		`{"id":"2","name":"B"},`+
		`{"org_id":"3","org_name":""},`+
		`{"org_id":"","org_name":"D"}`+
		`]`), "org_name", "org_id")
	if len(hits) != 2 {
		t.Fatalf("hits = %+v", hits)
	}
	if hits[0].ExtID != "1" || hits[0].Name != "A" {
		t.Fatalf("hits[0] = %+v", hits[0])
	}
	if hits[1].ExtID != "2" || hits[1].Name != "B" {
		t.Fatalf("hits[1] = %+v", hits[1])
	}
}
