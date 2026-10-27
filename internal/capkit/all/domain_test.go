package all_test

// 域聚合与 RegisterFull 的集合等价性门禁：
// RegisterFull 注册的 kit 集合必须恰好等于五个域聚合的并集——
// 两边任一侧加了新 kit 而另一侧没跟上，这条测试直接红。
// 顺序刻意不比（RegisterFull 保持历史注册顺序；聚合按域内逻辑序），
// 比的是集合。

import (
	"sort"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

func kitNames(t *testing.T, reg *core.Registry) []string {
	t.Helper()
	out := []string{}
	for _, spec := range reg.Specs() {
		out = append(out, spec.Manifest.Name)
	}
	sort.Strings(out)
	return out
}

func registerAggregates(t *testing.T) *core.Registry {
	t.Helper()
	reg := core.NewRegistry()
	for name, f := range map[string]func(*core.Registry) error{
		"RegisterRecon":  all.RegisterRecon,
		"RegisterVuln":   all.RegisterVuln,
		"RegisterPostex": all.RegisterPostex,
		"RegisterData":   all.RegisterData,
		"RegisterFlow":   all.RegisterFlow,
	} {
		if err := f(reg); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	return reg
}

func TestDomainsCoverRegisterFull(t *testing.T) {
	full := core.NewRegistry()
	if err := all.RegisterFull(full); err != nil {
		t.Fatalf("RegisterFull: %v", err)
	}
	union := registerAggregates(t)

	fullKits, unionKits := kitNames(t, full), kitNames(t, union)
	if len(fullKits) != len(unionKits) {
		t.Fatalf("kit 数不一致: RegisterFull=%d 五域并集=%d\nfull=%v\nunion=%v",
			len(fullKits), len(unionKits), fullKits, unionKits)
	}
	for i := range fullKits {
		if fullKits[i] != unionKits[i] {
			t.Fatalf("第 %d 个 kit 不一致: full=%q union=%q\nfull=%v\nunion=%v",
				i, fullKits[i], unionKits[i], fullKits, unionKits)
		}
	}
}

// 五域聚合之间不得重叠：同一 kit 出现在两个域里，宿主按域组合时会在
// registry.Add 上撞名。
func TestDomainsAreDisjoint(t *testing.T) {
	// core.Registry 没有 Reset（core 只读），逐域新建。
	domains := map[string]func(*core.Registry) error{
		"recon":  all.RegisterRecon,
		"vuln":   all.RegisterVuln,
		"postex": all.RegisterPostex,
		"data":   all.RegisterData,
		"flow":   all.RegisterFlow,
	}
	seen := map[string]string{} // kit -> domain
	for domain, f := range domains {
		reg := core.NewRegistry()
		if err := f(reg); err != nil {
			t.Fatalf("%s: %v", domain, err)
		}
		for _, name := range kitNames(t, reg) {
			if prev, ok := seen[name]; ok {
				t.Errorf("kit %q 同时出现在 %s 与 %s", name, prev, domain)
			}
			seen[name] = domain
		}
	}
}
