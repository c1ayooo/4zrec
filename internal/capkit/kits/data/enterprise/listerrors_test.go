package enterprise

import (
	"context"
	"testing"
)

// TestListErrorBranches 覆盖各 adapter 列表接口的 HTTP 错误早退分支。
func TestListErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("kuaicha Invest HTTP 错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "invest_abroad/list", resp: statusResp(500, "x")})
		if _, _, err := newKc(t, ff).Investments(ctx, "O1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})

	t.Run("tyc Branches HTTP 错误", func(t *testing.T) {
		ff := newStubFetcher(stubRoute{sub: "branchList", resp: statusResp(502, "x")})
		if _, _, err := newTyc(t, ff, "auth_token=t").Branches(ctx, "G1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})

	t.Run("tyc Invest 传输错误", func(t *testing.T) {
		ff := newStubFetcher()
		ff.failWith(errNoRoute)
		if _, _, err := newTyc(t, ff, "auth_token=t").Investments(ctx, "G1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})

	t.Run("aqc Domains 传输错误", func(t *testing.T) {
		ff := newStubFetcher()
		ff.failWith(errNoRoute)
		if _, _, err := newAqc(t, ff).Domains(ctx, "P1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})

	t.Run("fengniao Branches 列表 HTTP 错误", func(t *testing.T) {
		ff := newStubFetcher(
			stubRoute{sub: "/api/ent/query", resp: json200(fnDetailBody)},
			stubRoute{sub: "companyInfo/list", resp: statusResp(503, "x")},
		)
		p := newFn(t, ff)
		if _, err := p.Detail(ctx, "E1"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.Branches(ctx, "E1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})

	t.Run("fengniao Investments 列表传输错误", func(t *testing.T) {
		ff := newStubFetcher(
			stubRoute{sub: "/api/ent/query", resp: json200(fnDetailBody)},
			stubRoute{sub: "companyInfo/list", resp: statusResp(500, "x")},
		)
		p := newFn(t, ff)
		if _, err := p.Detail(ctx, "E1"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.Investments(ctx, "E1", 1, 10); err == nil {
			t.Fatal("应报错")
		}
	})
}
