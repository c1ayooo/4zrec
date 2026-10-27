package enterprise

import (
	"context"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

func loginResponse(body string, setCookies ...string) *core.Response {
	h := map[string][]string{}
	if len(setCookies) > 0 {
		h["Set-Cookie"] = setCookies
	}
	return &core.Response{Status: 200, Body: []byte(body), Headers: h}
}

func newFn(t *testing.T, ff *stubFetcher) *fengniaoProvider {
	t.Helper()
	p, err := NewFengniaoProvider(ff, "fncookie=1", "")
	if err != nil {
		t.Fatalf("NewFengniaoProvider = %v", err)
	}
	return p.(*fengniaoProvider)
}

func TestNewFengniaoProvider(t *testing.T) {
	if _, err := NewFengniaoProvider(newStubFetcher(), "  ", ""); !IsSessionMissing(err) {
		t.Fatalf("空 cookie 应报会话缺失, got %v", err)
	}
	p := newFn(t, newStubFetcher())
	if p.Name() != "fengniao" {
		t.Fatalf("Name = %q", p.Name())
	}
	if p.c.headers["Cookie"] != "fncookie=1" || p.c.headers["App-Device"] != "WEB" {
		t.Fatalf("头未设置: %#v", p.c.headers)
	}
}

func TestNewFengniaoAccountProvider(t *testing.T) {
	t.Run("缺账号或密码", func(t *testing.T) {
		if _, err := NewFengniaoAccountProvider(newStubFetcher(), "", "pw", ""); !IsSessionMissing(err) {
			t.Fatalf("空账号应报会话缺失, got %v", err)
		}
		if _, err := NewFengniaoAccountProvider(newStubFetcher(), "138", "", ""); !IsSessionMissing(err) {
			t.Fatalf("空密码应报会话缺失, got %v", err)
		}
	})

	t.Run("success=true 且下发 Cookie", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/api/auth/login", resp: loginResponse(`{"success":true}`, "sid=abc; Path=/", "token=xyz; HttpOnly")})
		p, err := NewFengniaoAccountProvider(ff, " 13800000000 ", "pw", "")
		if err != nil {
			t.Fatalf("login = %v", err)
		}
		fp := p.(*fengniaoProvider)
		if fp.c.headers["Cookie"] != "sid=abc; token=xyz" {
			t.Fatalf("会话 Cookie 未注入: %q", fp.c.headers["Cookie"])
		}
		req := ff.routeFor(t, "/api/auth/login")
		if req.Method != "POST" || !strings.Contains(string(req.Body), `"mobile":"13800000000"`) {
			t.Fatalf("登录请求错误: %s %s", req.Method, req.Body)
		}
	})

	t.Run("code=20000 亦视为成功", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/api/auth/login", resp: loginResponse(`{"code":"20000"}`, "sid=1")})
		if _, err := NewFengniaoAccountProvider(ff, "138", "pw", ""); err != nil {
			t.Fatalf("login = %v", err)
		}
	})

	t.Run("业务失败带 msg", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/api/auth/login", resp: loginResponse(`{"success":false,"code":"8888","msg":"账号或密码错误"}`)})
		_, err := NewFengniaoAccountProvider(ff, "138", "pw", "")
		if err == nil || !strings.Contains(err.Error(), "账号或密码错误") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("业务失败无 msg 用原始响应", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/api/auth/login", resp: loginResponse(`{"success":false}`)})
		_, err := NewFengniaoAccountProvider(ff, "138", "pw", "")
		if err == nil || !strings.Contains(err.Error(), `{"success":false}`) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("成功但未下发 Cookie", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/api/auth/login", resp: loginResponse(`{"success":true}`)})
		_, err := NewFengniaoAccountProvider(ff, "138", "pw", "")
		if err == nil || !strings.Contains(err.Error(), "未下发会话 Cookie") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("传输错误", func(t *testing.T) {
		ff := newStubFetcher()
		ff.failWith(errNoRoute)
		if _, err := NewFengniaoAccountProvider(ff, "138", "pw", ""); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestFnSearch(t *testing.T) {
	ctx := context.Background()

	t.Run("成功字段回落", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "newSearch", resp: json200(
			`{"code":"20000","data":{"list":[` +
				`{"entid":"1","ENTNAME":"<em>甲</em>公司"},` +
				`{"entId":"2","entName":"乙公司"},` +
				`{"id":"3","name":"丙公司"},` +
				`{"entid":"4"}` +
				`]}}`)})
		refs, err := newFn(t, ff).Search(ctx, "公司", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 3 || refs[0].ExtID != "1" || refs[0].Name != "甲公司" || refs[2].ExtID != "3" {
			t.Fatalf("refs = %+v", refs)
		}
	})

	t.Run("limit 截断", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "newSearch", resp: json200(
			`{"code":"20000","data":{"list":[{"entid":"1","ENTNAME":"A"},{"entid":"2","ENTNAME":"B"}]}}`)})
		refs, err := newFn(t, ff).Search(ctx, "k", 1)
		if err != nil || len(refs) != 1 {
			t.Fatalf("refs=%+v err=%v", refs, err)
		}
	})

	t.Run("业务码错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "newSearch", resp: json200(`{"code":"8888","msg":"参数错误"}`)})
		if _, err := newFn(t, ff).Search(ctx, "k", 10); err == nil || !strings.Contains(err.Error(), "参数错误") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("会话失效", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "newSearch", resp: json200(`{"code":"40001","msg":"please login"}`)})
		if _, err := newFn(t, ff).Search(ctx, "k", 10); !IsSessionMissing(err) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("空结果", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "newSearch", resp: json200(`{"code":"20000","data":{"list":[]}}`)})
		if _, err := newFn(t, ff).Search(ctx, "k", 10); err == nil || !strings.Contains(err.Error(), "搜索无结果") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("HTTP 错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "newSearch", resp: statusResp(401, "x")})
		if _, err := newFn(t, ff).Search(ctx, "k", 10); err == nil {
			t.Fatal("应报错")
		}
	})
}

const fnDetailBody = `{"code":"20000","orderNo":"ON-1","basicResult":{"apiData":{"list":{"jbxxInfo":{` +
	`"entName":"<em>甲</em>公司","personName":"张三","entStatus":"存续","telList":" 010-1 ","emailList":" a@b.com "}}}}}`

func TestFnDetail(t *testing.T) {
	ctx := context.Background()

	t.Run("成功并缓存 orderNo", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/api/ent/query", resp: json200(fnDetailBody)})
		p := newFn(t, ff)
		d, err := p.Detail(ctx, "E1")
		if err != nil {
			t.Fatal(err)
		}
		if d.ExtID != "E1" || d.Name != "甲公司" || d.LegalPerson != "张三" || d.OpenStatus != "存续" ||
			d.Phone != "010-1" || d.Email != "a@b.com" {
			t.Fatalf("detail = %+v", *d)
		}
		if p.orderNos["E1"] != "ON-1" {
			t.Fatalf("orderNo 未缓存: %#v", p.orderNos)
		}
	})

	t.Run("业务码错误直接返回", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/api/ent/query", resp: json200(`{"code":"500","msg":"boom"}`)})
		if _, err := newFn(t, ff).Detail(ctx, "E2"); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("传输错误", func(t *testing.T) {
		ff := newStubFetcher()
		ff.failWith(errNoRoute)
		if _, err := newFn(t, ff).Detail(ctx, "E3"); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestFnOrderNoOf(t *testing.T) {
	ctx := context.Background()

	t.Run("缓存命中不重复查详情", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/api/ent/query", resp: json200(fnDetailBody)})
		p := newFn(t, ff)
		if _, err := p.Detail(ctx, "E1"); err != nil { // 预热缓存
			t.Fatal(err)
		}
		before := ff.countFor("/api/ent/query")
		on, err := p.orderNoOf(ctx, "E1")
		if err != nil || on != "ON-1" {
			t.Fatalf("orderNoOf = %q, %v", on, err)
		}
		if ff.countFor("/api/ent/query") != before {
			t.Fatal("缓存命中却重新请求了详情")
		}
	})

	t.Run("缓存未命中现查详情", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/api/ent/query", resp: json200(fnDetailBody)})
		p := newFn(t, ff)
		on, err := p.orderNoOf(ctx, "E9")
		if err != nil || on != "ON-1" {
			t.Fatalf("orderNoOf = %q, %v", on, err)
		}
		if ff.countFor("/api/ent/query") != 1 {
			t.Fatalf("应查一次详情, got %d", ff.countFor("/api/ent/query"))
		}
	})

	t.Run("详情未返回 orderNo 报错", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/api/ent/query", resp: json200(
			`{"code":"20000","basicResult":{"apiData":{"list":{"jbxxInfo":{"entName":"甲"}}}}}`)})
		if _, err := newFn(t, ff).orderNoOf(ctx, "E5"); err == nil || !strings.Contains(err.Error(), "未返回 orderNo") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("详情失败向上传递", func(t *testing.T) {
		ff := newStubFetcher()
		ff.failWith(errNoRoute)
		if _, err := newFn(t, ff).orderNoOf(ctx, "E6"); err == nil {
			t.Fatal("应报错")
		}
	})
}

// fnWithList 构造已预热 orderNo 的 provider，便于直接测列表接口。
func fnWithList(t *testing.T, listRoute stubRoute) *fengniaoProvider {
	t.Helper()
	ff := newStubFetcher(stubRoute{sub: "/api/ent/query", resp: json200(fnDetailBody)}, listRoute)
	p := newFn(t, ff)
	if _, err := p.Detail(context.Background(), "E1"); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFnBranches(t *testing.T) {
	ctx := context.Background()
	p := fnWithList(t, stubRoute{sub: "companyInfo/list", resp: json200(
		`{"code":"20000","data":{"apiData":[` +
			`{"entid":"1","brName":"<em>分公司</em>"},` +
			`{"entId":"2","entName":"分支二"},` +
			`{"entid":"3"}` +
			`],"totalCount":25}}`)})
	refs, more, err := p.Branches(ctx, "E1", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || refs[0].Name != "分公司" || refs[1].ExtID != "2" || !more {
		t.Fatalf("refs=%+v more=%v", refs, more)
	}
	req := p.c.fetcher.(*stubFetcher).routeFor(t, "companyInfo/list")
	if !strings.Contains(string(req.Body), `"extractType":"companyBranch"`) || !strings.Contains(string(req.Body), `"orderNo":"ON-1"`) {
		t.Fatalf("列表请求体错误: %s", req.Body)
	}
}

func TestFnInvestments(t *testing.T) {
	ctx := context.Background()
	p := fnWithList(t, stubRoute{sub: "companyInfo/list", resp: json200(
		`{"code":"20000","data":{"apiData":[{"entid":"9","entName":"被投企业"}],"totalCount":3}}`)})
	refs, more, err := p.Investments(ctx, "E1", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].ExtID != "9" || more {
		t.Fatalf("refs=%+v more=%v", refs, more)
	}
}

func TestFnDomains(t *testing.T) {
	ctx := context.Background()

	t.Run("归一化与 more", func(t *testing.T) {
		p := fnWithList(t, stubRoute{sub: "companyInfo/list", resp: json200(
			`{"code":"20000","data":{"apiData":[` +
				`{"hostname":"https://A.com/x","webname":"官网","icpnum":"京ICP1"},` +
				`{"hostname":"localhost"},` +
				`{"hostname":"b.com","webname":"商城","icpnum":"京ICP2"}` +
				`],"totalCount":50}}`)})
		hits, more, err := p.Domains(ctx, "E1", 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 2 || hits[0].Domain != "a.com" || hits[0].Site != "官网" || hits[1].Domain != "b.com" {
			t.Fatalf("hits = %+v", hits)
		}
		if !more {
			t.Fatal("10 < 50 应有下一页")
		}
	})

	t.Run("无有效域名 more=false", func(t *testing.T) {
		p := fnWithList(t, stubRoute{sub: "companyInfo/list", resp: json200(
			`{"code":"20000","data":{"apiData":[{"hostname":"nope"}],"totalCount":50}}`)})
		hits, more, err := p.Domains(ctx, "E1", 1, 10)
		if err != nil || len(hits) != 0 || more {
			t.Fatalf("hits=%+v more=%v err=%v", hits, more, err)
		}
	})

	t.Run("列表业务错误", func(t *testing.T) {
		p := fnWithList(t, stubRoute{sub: "companyInfo/list", resp: json200(`{"code":"8888","msg":"x"}`)})
		if _, _, err := p.Domains(ctx, "E1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestFnCompanyRefs(t *testing.T) {
	// nameKey 只回落到 entName/brName，不含裸 name。
	hits := fnCompanyRefs(gjsonArray(t, `[`+
		`{"entid":"1","brName":"A"},`+
		`{"entId":"2","entName":"B"},`+
		`{"entid":"3","name":"C"},`+
		`{"entid":""}`+
		`]`), "brName")
	if len(hits) != 2 {
		t.Fatalf("hits = %+v", hits)
	}
	if hits[0].Name != "A" || hits[1].ExtID != "2" {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestFnRbListDirect(t *testing.T) {
	ctx := context.Background()
	t.Run("orderNoOf 失败直接返回", func(t *testing.T) {
		ff := newStubFetcher()
		ff.failWith(errNoRoute)
		p := newFn(t, ff)
		if _, _, err := p.rbList(ctx, "companyBranch", "E9", 1, 10); err == nil {
			t.Fatal("应返回 orderNoOf 错误")
		}
	})
	t.Run("success 路径解析 totalCount", func(t *testing.T) {
		ff := newStubFetcher(
			stubRoute{sub: "/api/ent/query", resp: json200(fnDetailBody)},
			stubRoute{sub: "companyInfo/list", resp: json200(`{"code":"20000","data":{"apiData":[{"entid":"1","brName":"A"}],"totalCount":7}}`)})
		p := newFn(t, ff)
		if _, err := p.Detail(ctx, "E1"); err != nil {
			t.Fatal(err)
		}
		data, total, err := p.rbList(ctx, "companyBranch", "E1", 1, 10)
		if err != nil || total != 7 || !data.Get("apiData").IsArray() {
			t.Fatalf("rbList = %v %d %v", data.Raw, total, err)
		}
	})
}
