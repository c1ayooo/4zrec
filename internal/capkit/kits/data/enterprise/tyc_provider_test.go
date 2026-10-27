package enterprise

import (
	"context"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func newTyc(t *testing.T, ff *stubFetcher, cookie string) *tycProvider {
	t.Helper()
	p, err := NewTycProvider(ff, cookie, "")
	if err != nil {
		t.Fatalf("NewTycProvider = %v", err)
	}
	return p.(*tycProvider)
}

func gjsonArray(t *testing.T, s string) gjson.Result {
	t.Helper()
	r := gjson.Parse(s)
	if !r.IsArray() {
		t.Fatalf("gjsonArray: %q 不是数组", s)
	}
	return r
}

func TestNewTycProvider(t *testing.T) {
	if _, err := NewTycProvider(newStubFetcher(), "  ", ""); !IsSessionMissing(err) {
		t.Fatalf("空 cookie 应报会话缺失, got %v", err)
	}

	t.Run("完整 Cookie 形态保留 Cookie 头", func(t *testing.T) {
		p := newTyc(t, newStubFetcher(), "auth_token=tok; TYCID=tid; sid=1")
		if p.Name() != "tyc" {
			t.Fatalf("Name = %q", p.Name())
		}
		if p.authTk != "tok" || p.tycid != "tid" {
			t.Fatalf("auth=%q tycid=%q", p.authTk, p.tycid)
		}
		if p.c.headers["Cookie"] != "auth_token=tok; TYCID=tid; sid=1" {
			t.Fatalf("Cookie 头 = %q", p.c.headers["Cookie"])
		}
		if p.c.headers["Version"] != "TYC-Web" {
			t.Fatalf("Version 头 = %q", p.c.headers["Version"])
		}
	})

	t.Run("JWT 头形态不设置 Cookie", func(t *testing.T) {
		p := newTyc(t, newStubFetcher(), "eyJhbGciOiJIUzUxMiJ9.raw.sig")
		if p.authTk != "eyJhbGciOiJIUzUxMiJ9.raw.sig" || p.tycid != "" {
			t.Fatalf("auth=%q tycid=%q", p.authTk, p.tycid)
		}
		if _, ok := p.c.headers["Cookie"]; ok {
			t.Fatalf("JWT 形态不应设置 Cookie 头: %#v", p.c.headers)
		}
	})

	t.Run("capiHeaders", func(t *testing.T) {
		p := newTyc(t, newStubFetcher(), "auth_token=tok; TYCID=tid")
		h := p.capiHeaders()
		if h["X-Auth-Token"] != "tok" || h["X-Tycid"] != "tid" {
			t.Fatalf("capiHeaders = %#v", h)
		}
	})
}

func TestTycSearch(t *testing.T) {
	ctx := context.Background()

	t.Run("成功去高亮并过滤空字段", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "searchCompanyV4", resp: json200(
			`{"state":"ok","data":{"companyList":[` +
				`{"id":"100","name":"<em>某某</em>科技"},` +
				`{"graphId":"200","entName":"第二公司"},` +
				`{"id":"","name":"无ID"},` +
				`{"id":"300","name":""}` +
				`]}}`)})
		refs, err := newTyc(t, ff, "auth_token=tok").Search(ctx, "某某", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 2 || refs[0].ExtID != "100" || refs[0].Name != "某某科技" || refs[1].ExtID != "200" {
			t.Fatalf("refs = %+v", refs)
		}
		req := ff.routeFor(t, "searchCompanyV4")
		if req.Method != "POST" || req.Headers["X-Auth-Token"] != "tok" {
			t.Fatalf("请求未带 capi 头: %+v %#v", req.Method, req.Headers)
		}
	})

	t.Run("limit 截断", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "searchCompanyV4", resp: json200(
			`{"state":"ok","data":{"companyList":[{"id":"1","name":"A"},{"id":"2","name":"B"}]}}`)})
		refs, err := newTyc(t, ff, "auth_token=t").Search(ctx, "k", 1)
		if err != nil || len(refs) != 1 {
			t.Fatalf("refs=%+v err=%v", refs, err)
		}
	})

	t.Run("mustlogin 映射会话失效", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "searchCompanyV4", resp: json200(`{"message":"mustlogin"}`)})
		if _, err := newTyc(t, ff, "auth_token=t").Search(ctx, "k", 10); !IsSessionMissing(err) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("state 非 ok", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "searchCompanyV4", resp: json200(`{"state":"error"}`)})
		if _, err := newTyc(t, ff, "auth_token=t").Search(ctx, "k", 10); err == nil || !strings.Contains(err.Error(), "state=error") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("空列表", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "searchCompanyV4", resp: json200(`{"state":"ok","data":{"companyList":[]}}`)})
		if _, err := newTyc(t, ff, "auth_token=t").Search(ctx, "k", 10); err == nil || !strings.Contains(err.Error(), "搜索无结果") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("HTTP 错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "searchCompanyV4", resp: statusResp(302, "redirect")})
		if _, err := newTyc(t, ff, "auth_token=t").Search(ctx, "k", 10); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestTycDetail(t *testing.T) {
	ctx := context.Background()

	t.Run("成功解析字段", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "baseinfo/web", resp: json200(
			`{"state":"ok","data":{"name":"<em>某某</em>科技","legalPersonName":"张三","openStatus":"存续","phoneNumber":" 010-1 ","email":" a@b.com "}}`)})
		d, err := newTyc(t, ff, "auth_token=t").Detail(ctx, "G1")
		if err != nil {
			t.Fatal(err)
		}
		if d.ExtID != "G1" || d.Name != "某某科技" || d.LegalPerson != "张三" || d.OpenStatus != "存续" ||
			d.Phone != "010-1" || d.Email != "a@b.com" {
			t.Fatalf("detail = %+v", *d)
		}
	})

	t.Run("会话失效非致命只返回 ExtID", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "baseinfo/web", resp: json200(`{"message":"mustlogin"}`)})
		d, err := newTyc(t, ff, "auth_token=t").Detail(ctx, "G2")
		if err != nil {
			t.Fatalf("detail 失败不应返回错误: %v", err)
		}
		if d.ExtID != "G2" || d.Name != "" {
			t.Fatalf("detail = %+v", *d)
		}
	})

	t.Run("传输错误返回错误", func(t *testing.T) {
		ff := newStubFetcher()
		ff.failWith(errNoRoute)
		if _, err := newTyc(t, ff, "auth_token=t").Detail(ctx, "G3"); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestTycLists(t *testing.T) {
	ctx := context.Background()

	t.Run("Branches 解析 result 与 itemTotal", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branchList", resp: json200(
			`{"state":"ok","data":{"result":[{"id":"1","name":"<em>分公司</em>"},{"graphId":"2","branchName":"分支二"}],"itemTotal":25}}`)})
		refs, more, err := newTyc(t, ff, "auth_token=t").Branches(ctx, "G1", 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 2 || refs[0].Name != "分公司" || refs[1].ExtID != "2" {
			t.Fatalf("refs = %+v", refs)
		}
		if !more {
			t.Fatal("10*1 < 25 应有下一页")
		}
	})

	t.Run("Branches 末页 more=false", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branchList", resp: json200(`{"state":"ok","data":{"result":[],"count":3}}`)})
		_, more, err := newTyc(t, ff, "auth_token=t").Branches(ctx, "G1", 2, 10)
		if err != nil || more {
			t.Fatalf("more=%v err=%v", more, err)
		}
	})

	t.Run("Branches 业务错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branchList", resp: json200(`{"state":"fail"}`)})
		if _, _, err := newTyc(t, ff, "auth_token=t").Branches(ctx, "G1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})

	t.Run("Investments POST 解析 total", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "investListV2", resp: json200(
			`{"state":"ok","data":{"result":[{"id":"7","entName":"被投企业"}],"total":4}}`)})
		refs, more, err := newTyc(t, ff, "auth_token=t").Investments(ctx, "G1", 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 1 || refs[0].ExtID != "7" || more {
			t.Fatalf("refs=%+v more=%v", refs, more)
		}
		req := ff.routeFor(t, "investListV2")
		if req.Method != "POST" || !strings.Contains(string(req.Body), `"gid":"G1"`) {
			t.Fatalf("invest 请求错误: %s %s", req.Method, req.Body)
		}
	})

	t.Run("Investments 回落 pageBean.total", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "investListV2", resp: json200(
			`{"state":"ok","data":{"result":[],"pageBean":{"total":30}}}`)})
		_, more, err := newTyc(t, ff, "auth_token=t").Investments(ctx, "G1", 1, 10)
		if err != nil || !more {
			t.Fatalf("more=%v err=%v", more, err)
		}
	})

	t.Run("Investments 业务错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "investListV2", resp: json200(`{"message":"mustlogin"}`)})
		if _, _, err := newTyc(t, ff, "auth_token=t").Investments(ctx, "G1", 1, 10); !IsSessionMissing(err) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestTycDomains(t *testing.T) {
	ctx := context.Background()

	t.Run("归一化与字段回落", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "icpRecordList", resp: json200(
			`{"state":"ok","data":{"item":[` +
				`{"domain":"https://A.com/x","webName":"官网","icpNo":"京ICP1"},` +
				`{"ym":"b.com","siteName":"商城","icp":"京ICP2"},` +
				`{"homeSite":"localhost"},` +
				`{"webSite":"c.com","webSiteName":"门户","impNumber":"京ICP3"}` +
				`],"total":100}}`)})
		hits, more, err := newTyc(t, ff, "auth_token=t").Domains(ctx, "G1", 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 3 {
			t.Fatalf("hits = %+v", hits)
		}
		if hits[0].Domain != "a.com" || hits[0].Site != "官网" || hits[0].ICP != "京ICP1" {
			t.Fatalf("hits[0] = %+v", hits[0])
		}
		if hits[2].Domain != "c.com" || hits[2].Site != "门户" || hits[2].ICP != "京ICP3" {
			t.Fatalf("hits[2] = %+v", hits[2])
		}
		if !more {
			t.Fatal("10 < 100 应有下一页")
		}
	})

	t.Run("全无效域名 more=false", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "icpRecordList", resp: json200(
			`{"state":"ok","data":{"item":[{"domain":"nope"}],"total":100}}`)})
		hits, more, err := newTyc(t, ff, "auth_token=t").Domains(ctx, "G1", 1, 10)
		if err != nil || len(hits) != 0 || more {
			t.Fatalf("hits=%+v more=%v err=%v", hits, more, err)
		}
	})

	t.Run("业务错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "icpRecordList", resp: json200(`{"state":"err"}`)})
		if _, _, err := newTyc(t, ff, "auth_token=t").Domains(ctx, "G1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestTycCompanyRefs(t *testing.T) {
	// 直接单测解析辅助，覆盖字段回落顺序。
	hits := tycCompanyRefs(gjsonArray(t, `[`+
		`{"id":"1","name":"A"},`+
		`{"graphId":"2","entName":"B"},`+
		`{"pid":"3","branchName":"C"},`+
		`{"id":"","name":"D"},`+
		`{"pid":"4"}`+
		`]`))
	if len(hits) != 3 {
		t.Fatalf("hits = %+v", hits)
	}
	if hits[1].ExtID != "2" || hits[2].Name != "C" {
		t.Fatalf("hits = %+v", hits)
	}
}
