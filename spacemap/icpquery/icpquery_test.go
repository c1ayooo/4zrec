package icpquery

import (
	"reflect"
	"testing"
)

func TestQuerySyntaxPerEngine(t *testing.T) {
	cases := []struct {
		engine string
		kind   KeyKind
		value  string
		want   string
		ok     bool
	}{
		{"quake", KindICP, "粤ICP备14006354号", `icp:"粤ICP备14006354号"`, true},
		{"fofa", KindICP, "粤ICP备14006354号", `icp="粤ICP备14006354号"`, true},
		{"fofa", KindCompany, "某某科技", `company="某某科技"`, true},
		{"hunter", KindICP, "粤ICP备14006354号", `icp.number="粤ICP备14006354号"`, true},
		{"hunter", KindCompany, "某某科技", `icp.name="某某科技"`, true},
		{"zoomeye", KindICP, "粤ICP备14006354号", "", false},
		{"shodan", KindICP, "粤ICP备14006354号", "", false},
		{"quake", KindCompany, "某某科技", "", false}, // quake 无主办单位过滤器
	}
	for _, c := range cases {
		got, ok := QueryFor(c.engine, c.kind, c.value)
		if ok != c.ok || got != c.want {
			t.Errorf("QueryFor(%s,%s) = %q,%v; want %q,%v", c.engine, c.kind, got, ok, c.want, c.ok)
		}
	}
}

func TestKeysFromRows(t *testing.T) {
	rows := []map[string]interface{}{
		{"icp": "粤ICP备14006354号-1", "domain": "a.example.com"},
		{"icp": "", "domain": "b.example.com", "company": "某某科技有限公司"},
	}
	// quake：只提 icp（主号归一化）
	quakeKeys := KeysFromRows("quake", rows)
	want := []Key{{Kind: KindICP, Value: "粤ICP备14006354号"}}
	if !reflect.DeepEqual(quakeKeys, want) {
		t.Fatalf("quake keys = %v", quakeKeys)
	}
	// fofa：icp + company
	fofaKeys := KeysFromRows("fofa", rows)
	if len(fofaKeys) != 2 || fofaKeys[0].Kind != KindICP || fofaKeys[1].Kind != KindCompany {
		t.Fatalf("fofa keys = %v", fofaKeys)
	}
	// zoomeye：无键
	if keys := KeysFromRows("zoomeye", rows); len(keys) != 0 {
		t.Fatalf("zoomeye 应无键，得到 %v", keys)
	}
	// hunter：number 字段提取 + company
	hunterRows := []map[string]interface{}{
		{"number": "京ICP备2021000001号-5", "company": "北京某公司", "url": "https://x.example.com/path"},
	}
	hunterKeys := KeysFromRows("hunter", hunterRows)
	if len(hunterKeys) != 2 || hunterKeys[0].Value != "京ICP备2021000001号" {
		t.Fatalf("hunter keys = %v", hunterKeys)
	}
}

func TestDomainsFromRow(t *testing.T) {
	if got := DomainsFromRow("quake", map[string]interface{}{"domain": "A.Example.com"}); !reflect.DeepEqual(got, []string{"a.example.com"}) {
		t.Fatalf("quake domains = %v", got)
	}
	// hunter domain 为空回退 url 主机提取
	if got := DomainsFromRow("hunter", map[string]interface{}{"url": "https://x.example.com/p"}); !reflect.DeepEqual(got, []string{"x.example.com"}) {
		t.Fatalf("hunter domains = %v", got)
	}
	// 域名剥 scheme/路径/端口
	if got := DomainsFromRow("fofa", map[string]interface{}{"host": "https://y.example.com:8443/root"}); !reflect.DeepEqual(got, []string{"y.example.com"}) {
		t.Fatalf("fofa domains = %v", got)
	}
}

func TestSupportedEngines(t *testing.T) {
	engines := SupportedEngines()
	want := []string{"quake", "fofa", "hunter"}
	if !reflect.DeepEqual(engines, want) {
		t.Fatalf("SupportedEngines = %v", engines)
	}
}
