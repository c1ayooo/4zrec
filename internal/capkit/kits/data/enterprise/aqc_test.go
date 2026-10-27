package enterprise

import (
	"context"
	"strings"
	"testing"
)

func newAqc(t *testing.T, ff *stubFetcher) *aqcProvider {
	t.Helper()
	p, err := NewAqcProvider(ff, "BIDUUID=abc; sid=1", "")
	if err != nil {
		t.Fatalf("NewAqcProvider = %v", err)
	}
	return p.(*aqcProvider)
}

func TestNewAqcProvider(t *testing.T) {
	if _, err := NewAqcProvider(newStubFetcher(), "   ", ""); !IsSessionMissing(err) {
		t.Fatalf("空 cookie 应报会话缺失, got %v", err)
	}
	p := newAqc(t, newStubFetcher())
	if p.Name() != "aqc" {
		t.Fatalf("Name = %q", p.Name())
	}
	if p.c.headers["Cookie"] != "BIDUUID=abc; sid=1" {
		t.Fatalf("Cookie 头未设置: %q", p.c.headers["Cookie"])
	}
	if p.c.headers["Referer"] != aqcBase+"/" {
		t.Fatalf("Referer 头错误: %q", p.c.headers["Referer"])
	}
}

func TestAqcSearch(t *testing.T) {
	ctx := context.Background()

	t.Run("成功反混淆并去高亮", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/s/advanceFilterAjax", resp: json200(
			`{"ddw":1,"status":0,"data":{"resultList":[` +
				`{"pid":"1234","entName":"<em>某某</em>科技有限公司"},` +
				`{"pid":"5678","entName":"第二公司"}` +
				`]}}`)})
		p := newAqc(t, ff)
		refs, err := p.Search(ctx, "北京 公司", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 2 {
			t.Fatalf("结果数 = %d", len(refs))
		}
		// ddw=1 置换表：1→1, 2→2, 3→3, 4→5。
		if refs[0].ExtID != "1235" {
			t.Fatalf("pid 未按 ddw=1 反混淆: %q", refs[0].ExtID)
		}
		if refs[0].Name != "某某科技有限公司" {
			t.Fatalf("entName 高亮未去除: %q", refs[0].Name)
		}
		if refs[1].ExtID != "4769" || refs[1].Name != "第二公司" {
			t.Fatalf("第二条 = %+v", refs[1])
		}
		req := ff.routeFor(t, "advanceFilterAjax")
		if !strings.Contains(req.URL, "q="+urlQueryEscape("北京 公司")) {
			t.Fatalf("关键词未转义进 URL: %q", req.URL)
		}
	})

	t.Run("limit 截断", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "advanceFilterAjax", resp: json200(
			`{"ddw":0,"status":0,"data":{"resultList":[` +
				`{"pid":"1","entName":"A"},{"pid":"2","entName":"B"},{"pid":"3","entName":"C"}]}}`)})
		refs, err := newAqc(t, ff).Search(ctx, "k", 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 2 || refs[1].ExtID != "2" {
			t.Fatalf("limit 未生效: %+v", refs)
		}
	})

	t.Run("缺失 pid 或名称的条目被跳过", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "advanceFilterAjax", resp: json200(
			`{"ddw":0,"status":0,"data":{"resultList":[` +
				`{"pid":"1","entName":""},{"pid":"","entName":"B"},{"pid":"3","entName":"C"}]}}`)})
		refs, err := newAqc(t, ff).Search(ctx, "k", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 1 || refs[0].ExtID != "3" {
			t.Fatalf("空字段条目未过滤: %+v", refs)
		}
	})

	t.Run("触发安全验证", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "advanceFilterAjax", resp: json200(`{"msg":"百度安全验证"}`)})
		_, err := newAqc(t, ff).Search(ctx, "k", 10)
		if err == nil || !strings.Contains(err.Error(), "安全验证") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("业务码非零", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "advanceFilterAjax", resp: json200(`{"status":5,"message":"上游错误"}`)})
		if _, err := newAqc(t, ff).Search(ctx, "k", 10); err == nil || !strings.Contains(err.Error(), "上游错误") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("空结果", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "advanceFilterAjax", resp: json200(`{"ddw":1,"status":0,"data":{"resultList":[]}}`)})
		_, err := newAqc(t, ff).Search(ctx, "k", 10)
		if err == nil || !strings.Contains(err.Error(), "搜索无结果") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("HTTP 层错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "advanceFilterAjax", resp: statusResp(401, "unauthorized")})
		if _, err := newAqc(t, ff).Search(ctx, "k", 10); err == nil || !strings.Contains(err.Error(), "401") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestAqcDetail(t *testing.T) {
	ctx := context.Background()

	t.Run("成功解析字段", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/detail/basicAllDataAjax", resp: json200(
			`{"status":0,"data":{"basicData":{"entName":"<em>某某</em>科技","legalPerson":"张三","openStatus":"存续","telephone":" 010-1 ","email":" a@b.com "}}}`)})
		d, err := newAqc(t, ff).Detail(ctx, "P123")
		if err != nil {
			t.Fatal(err)
		}
		want := CompanyDetail{ExtID: "P123", Name: "某某科技", LegalPerson: "张三", OpenStatus: "存续", Phone: "010-1", Email: "a@b.com"}
		if d.ExtID != want.ExtID || d.Name != want.Name || d.LegalPerson != want.LegalPerson ||
			d.OpenStatus != want.OpenStatus || d.Phone != want.Phone || d.Email != want.Email || d.Domains != nil {
			t.Fatalf("detail = %+v, want %+v", *d, want)
		}
		if got := ff.routeFor(t, "basicAllDataAjax").URL; !strings.Contains(got, "pid=P123") {
			t.Fatalf("pid 未进 URL: %q", got)
		}
	})

	t.Run("会话失效回落空详情字段", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "basicAllDataAjax", resp: json200(`{"status":0,"data":{}}`)})
		d, err := newAqc(t, ff).Detail(ctx, "P1")
		if err != nil {
			t.Fatal(err)
		}
		if d.ExtID != "P1" || d.Name != "" {
			t.Fatalf("detail = %+v", *d)
		}
	})

	t.Run("业务错误直接返回", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "basicAllDataAjax", resp: json200(`{"status":9,"message":"挂了"}`)})
		if _, err := newAqc(t, ff).Detail(ctx, "P1"); err == nil || !strings.Contains(err.Error(), "挂了") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("传输错误直接返回", func(t *testing.T) {
		ff := newStubFetcher()
		ff.failWith(errNoRoute)
		if _, err := newAqc(t, ff).Detail(ctx, "P1"); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestAqcListPages(t *testing.T) {
	ctx := context.Background()

	t.Run("Branches 满页返回 more", func(t *testing.T) {
		items := make([]string, 0, 10)
		for i := 0; i < 10; i++ {
			items = append(items, `{"pid":"`+string(rune('0'+i))+`","entName":"分`+string(rune('0'+i))+`"}`)
		}
		ff := newStubFetcher(stubRoute{sub: "detail/branchajax", resp: json200(
			`{"status":0,"data":{"list":[` + strings.Join(items, ",") + `]}}`)})
		refs, more, err := newAqc(t, ff).Branches(ctx, "P1", 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 10 || !more {
			t.Fatalf("refs=%d more=%v", len(refs), more)
		}
		req := ff.routeFor(t, "branchajax")
		if !strings.Contains(req.URL, "size=10") || !strings.Contains(req.URL, "pid=P1") || !strings.Contains(req.URL, "p=1") {
			t.Fatalf("URL 参数错误: %q", req.URL)
		}
	})

	t.Run("Investments 不满页 more=false", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "detail/investajax", resp: json200(
			`{"status":0,"data":{"list":[{"pid":"9","entName":"投资A"}]}}`)})
		refs, more, err := newAqc(t, ff).Investments(ctx, "P1", 2, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 1 || more {
			t.Fatalf("refs=%+v more=%v", refs, more)
		}
	})

	t.Run("跳过空字段", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branchajax", resp: json200(
			`{"status":0,"data":{"list":[{"pid":"","entName":"A"},{"pid":"1","entName":""},{"pid":"2","entName":"B"}]}}`)})
		refs, _, err := newAqc(t, ff).Branches(ctx, "P1", 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 1 || refs[0].ExtID != "2" {
			t.Fatalf("refs = %+v", refs)
		}
	})

	t.Run("业务错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branchajax", resp: json200(`{"status":1,"message":"boom"}`)})
		if _, _, err := newAqc(t, ff).Branches(ctx, "P1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})

	t.Run("HTTP 错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branchajax", resp: statusResp(500, "err")})
		if _, _, err := newAqc(t, ff).Investments(ctx, "P1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestAqcDomains(t *testing.T) {
	ctx := context.Background()

	t.Run("多站点多域名归一化", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "/detail/icpinfoAjax", resp: json200(
			`{"status":0,"data":{"list":[` +
				`{"siteName":"官网","icpNo":"京ICP备1","domain":["https://A.com/x","", "  "]},` +
				`{"siteName":"商城","icpNo":"京ICP备2","domain":["b.com","c.com"]}` +
				`]}}`)})
		hits, more, err := newAqc(t, ff).Domains(ctx, "P1", 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 3 {
			t.Fatalf("hits = %+v", hits)
		}
		if hits[0].Domain != "a.com" || hits[0].Site != "官网" || hits[0].ICP != "京ICP备1" {
			t.Fatalf("hits[0] = %+v", hits[0])
		}
		if hits[2].Domain != "c.com" || hits[2].Site != "商城" {
			t.Fatalf("hits[2] = %+v", hits[2])
		}
		if more {
			t.Fatal("不满 10 条不应有下一页")
		}
	})

	t.Run("无效域名被跳过", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "icpinfoAjax", resp: json200(
			`{"status":0,"data":{"list":[{"siteName":"S","icpNo":"N","domain":["localhost","*.x.com"]}]}}`)})
		hits, _, err := newAqc(t, ff).Domains(ctx, "P1", 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 0 {
			t.Fatalf("hits = %+v", hits)
		}
	})

	t.Run("达到 size 时 more=true", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "icpinfoAjax", resp: json200(
			`{"status":0,"data":{"list":[{"domain":["a.com","b.com","c.com"]}]}}`)})
		hits, more, err := newAqc(t, ff).Domains(ctx, "P1", 1, 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 3 || !more {
			t.Fatalf("hits=%+v more=%v", hits, more)
		}
	})

	t.Run("业务错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "icpinfoAjax", resp: json200(`{"status":3,"message":"x"}`)})
		if _, _, err := newAqc(t, ff).Domains(ctx, "P1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})
}
