package enterprise

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// funcProvider 用函数钩子构造可控 provider（用于错误注入与参数断言）。
type funcProvider struct {
	name     string
	searchFn func(ctx context.Context, keyword string, limit int) ([]CompanyRef, error)
	detailFn func(ctx context.Context, extID string) (*CompanyDetail, error)
}

func (p funcProvider) Name() string { return p.name }

func (p funcProvider) Search(ctx context.Context, keyword string, limit int) ([]CompanyRef, error) {
	if p.searchFn == nil {
		return nil, nil
	}
	return p.searchFn(ctx, keyword, limit)
}

func (p funcProvider) Detail(ctx context.Context, extID string) (*CompanyDetail, error) {
	if p.detailFn == nil {
		return &CompanyDetail{ExtID: extID}, nil
	}
	return p.detailFn(ctx, extID)
}

func (p funcProvider) Branches(context.Context, string, int, int) ([]CompanyRef, bool, error) {
	return nil, false, nil
}
func (p funcProvider) Investments(context.Context, string, int, int) ([]CompanyRef, bool, error) {
	return nil, false, nil
}
func (p funcProvider) Domains(context.Context, string, int, int) ([]DomainHit, bool, error) {
	return nil, false, nil
}

// resolver 返回固定 provider 的解析器。
func resolver(p Provider) ProviderResolver {
	return ResolverFunc(func(context.Context, string) (Provider, error) { return p, nil })
}

func TestKitManifest(t *testing.T) {
	m := NewKit(nil).Manifest()
	if m.Name != "enterprisekit" || m.Version == "" || m.APIVersion != "v1" {
		t.Fatalf("manifest = %+v", m)
	}
	want := map[string]bool{"enterprise_search": false, "enterprise_detail": false, "enterprise_providers": false}
	for _, tool := range m.Tools {
		if _, ok := want[tool.Name]; !ok {
			t.Fatalf("意外工具 %q", tool.Name)
		}
		want[tool.Name] = true
		if len(tool.InputSchema) == 0 {
			t.Fatalf("工具 %q 缺 schema", tool.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("缺少工具 %q", name)
		}
	}
}

func TestKitCallUnknownTool(t *testing.T) {
	res, err := NewKit(nil).Call(context.Background(), core.Call{Tool: "nope"})
	if err != nil {
		t.Fatalf("Call err = %v", err)
	}
	if res.OK || !strings.Contains(res.Summary, "unknown tool") {
		t.Fatalf("res = %+v", res)
	}
}

func TestKitProviders(t *testing.T) {
	res, err := NewKit(nil).Call(context.Background(), core.Call{Tool: "enterprise_providers"})
	if err != nil || !res.OK {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	var payload struct {
		Count     int            `json:"count"`
		Providers []ProviderKind `json:"providers"`
	}
	if err := json.Unmarshal(res.Data, &payload); err != nil {
		t.Fatalf("unmarshal = %v", err)
	}
	if len(payload.Providers) != len(Registry) || payload.Count != len(Registry) {
		t.Fatalf("providers = %d/%d, want %d", len(payload.Providers), payload.Count, len(Registry))
	}
}

func TestKitNilResolver(t *testing.T) {
	var nilKit *Kit
	res, err := nilKit.Call(context.Background(), core.Call{
		Tool:  "enterprise_search",
		Input: []byte(`{"provider":"aqc","keyword":"x"}`),
	})
	if err != nil {
		t.Fatalf("Call err = %v", err)
	}
	if res.OK || !strings.Contains(res.Summary, "resolver 未配置") {
		t.Fatalf("res = %+v", res)
	}

	// Resolver 已配置但显式返回错误。
	failing := ResolverFunc(func(context.Context, string) (Provider, error) { return nil, errors.New("no session") })
	res, err = NewKit(failing).Call(context.Background(), core.Call{
		Tool:  "enterprise_detail",
		Input: []byte(`{"provider":"tyc","ext_id":"1"}`),
	})
	if err != nil || res.OK {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestKitSearchBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("非法输入 JSON", func(t *testing.T) {
		res, err := NewKit(resolver(fakeProvider{name: "fake"})).Call(ctx, core.Call{
			Tool: "enterprise_search", Input: []byte(`{bad`),
		})
		if err != nil || res.OK || res.Error == nil || res.Error.Code != core.CodeInvalidInput {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})

	t.Run("limit<=0 回落 10", func(t *testing.T) {
		var gotLimit int
		p := funcProvider{name: "cap", searchFn: func(_ context.Context, _ string, limit int) ([]CompanyRef, error) {
			gotLimit = limit
			return []CompanyRef{{ExtID: "1", Name: "A"}}, nil
		}}
		res, err := NewKit(resolver(p)).Call(ctx, core.Call{
			Tool: "enterprise_search", Input: []byte(`{"provider":"cap","keyword":"k"}`),
		})
		if err != nil || !res.OK {
			t.Fatalf("res=%+v err=%v", res, err)
		}
		if gotLimit != 10 {
			t.Fatalf("默认 limit = %d, want 10", gotLimit)
		}
	})

	t.Run("搜索失败", func(t *testing.T) {
		p := funcProvider{name: "cap", searchFn: func(context.Context, string, int) ([]CompanyRef, error) {
			return nil, errors.New("upstream down")
		}}
		res, err := NewKit(resolver(p)).Call(ctx, core.Call{
			Tool: "enterprise_search", Input: []byte(`{"provider":"cap","keyword":"k","limit":3}`),
		})
		if err != nil || res.OK || !strings.Contains(res.Summary, "upstream down") {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})

	t.Run("空 provider 名仍走解析器", func(t *testing.T) {
		res, err := NewKit(ResolverFunc(func(_ context.Context, name string) (Provider, error) {
			if strings.TrimSpace(name) != "" {
				t.Fatalf("provider 名应被裁剪，得到 %q", name)
			}
			return fakeProvider{name: "fake"}, nil
		})).Call(ctx, core.Call{Tool: "enterprise_search", Input: []byte(`{"provider":"  ","keyword":"k"}`)})
		if err != nil || !res.OK {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})
}

func TestKitDetailBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("非法输入 JSON", func(t *testing.T) {
		res, err := NewKit(resolver(fakeProvider{name: "fake"})).Call(ctx, core.Call{
			Tool: "enterprise_detail", Input: []byte(`[]`),
		})
		if err != nil || res.OK {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})

	t.Run("详情失败", func(t *testing.T) {
		p := funcProvider{name: "cap", detailFn: func(context.Context, string) (*CompanyDetail, error) {
			return nil, errors.New("detail boom")
		}}
		res, err := NewKit(resolver(p)).Call(ctx, core.Call{
			Tool: "enterprise_detail", Input: []byte(`{"provider":"cap","ext_id":"e1"}`),
		})
		if err != nil || res.OK || !strings.Contains(res.Summary, "detail boom") {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})
}
