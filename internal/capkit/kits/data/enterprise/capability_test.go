package enterprise

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type fakeProvider struct{ name string }

func (f fakeProvider) Name() string { return f.name }
func (f fakeProvider) Search(context.Context, string, int) ([]CompanyRef, error) {
	return []CompanyRef{{ExtID: "e1", Name: "Example Co"}}, nil
}
func (f fakeProvider) Detail(context.Context, string) (*CompanyDetail, error) {
	return &CompanyDetail{ExtID: "e1", Name: "Example Co"}, nil
}
func (f fakeProvider) Branches(context.Context, string, int, int) ([]CompanyRef, bool, error) {
	return nil, false, nil
}
func (f fakeProvider) Investments(context.Context, string, int, int) ([]CompanyRef, bool, error) {
	return nil, false, nil
}
func (f fakeProvider) Domains(context.Context, string, int, int) ([]DomainHit, bool, error) {
	return nil, false, nil
}

func TestKitSearchAndDetail(t *testing.T) {
	kit := NewKit(ResolverFunc(func(context.Context, string) (Provider, error) {
		return fakeProvider{name: "fake"}, nil
	}))
	res, err := kit.Call(context.Background(), core.Call{Tool: "enterprise_search", Input: []byte(`{"provider":"fake","keyword":"example"}`)})
	if err != nil || !res.OK {
		t.Fatalf("search = %#v err=%v", res, err)
	}
	var out struct {
		Count int          `json:"count"`
		Items []CompanyRef `json:"items"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil || out.Count != 1 || out.Items[0].ExtID != "e1" {
		t.Fatalf("search data=%s err=%v", res.Data, err)
	}
	res, err = kit.Call(context.Background(), core.Call{Tool: "enterprise_detail", Input: []byte(`{"provider":"fake","ext_id":"e1"}`)})
	if err != nil || !res.OK {
		t.Fatalf("detail = %#v err=%v", res, err)
	}
}
