package icp

import "sort"

// 查询类型。普通备案对应 queryByCondition，黑名单（违法违规）对应
// blackListDomain/queryByCondition。
const (
	TypeWeb   = "web"  // 网站
	TypeApp   = "app"  // App
	TypeMapp  = "mapp" // 小程序
	TypeKapp  = "kapp" // 快应用
	TypeBWeb  = "bweb"
	TypeBApp  = "bapp"
	TypeBMapp = "bmapp"
	TypeBKapp = "bkapp"
)

// typeMeta 描述一种查询类型：sp 为上游内部序号，黑名单标记、含义文案。
type typeMeta struct {
	Code   string // 别名，与字符串常量一致
	SP     int    // 上游 serviceType 序号：web/bweb=0, app/bapp=1, mapp/bmapp=2, kapp/bkapp=3
	Black  bool
	Label  string
	Detail bool // 是否需要并发补齐 App/小程序/快应用详情
}

var typeTable = map[string]typeMeta{
	TypeWeb:   {TypeWeb, 0, false, "网站备案", false},
	TypeApp:   {TypeApp, 1, false, "App 备案", true},
	TypeMapp:  {TypeMapp, 2, false, "小程序备案", true},
	TypeKapp:  {TypeKapp, 3, false, "快应用备案", true},
	TypeBWeb:  {TypeBWeb, 0, true, "网站黑名单", false},
	TypeBApp:  {TypeBApp, 1, true, "App 黑名单", false},
	TypeBMapp: {TypeBMapp, 2, true, "小程序黑名单", false},
	TypeBKapp: {TypeBKapp, 3, true, "快应用黑名单", false},
}

// IsSupportedType reports whether qtype is a known query type.
func IsSupportedType(qtype string) bool {
	_, ok := typeTable[qtype]
	return ok
}

// IsBlackType reports whether qtype targets the blacklist endpoints.
func IsBlackType(qtype string) bool {
	m, ok := typeTable[qtype]
	return ok && m.Black
}

// serviceTypeCode 把上游序号映射为查询接口的 serviceType（0->1,1->6,2->7,3->8）。
func serviceTypeCode(sp int) int {
	switch sp {
	case 0:
		return 1
	case 1:
		return 6
	case 2:
		return 7
	case 3:
		return 8
	default:
		return 1
	}
}

// TypeInfo 是 icp_types 的输出项。
type TypeInfo struct {
	Type  string `json:"type"`
	Label string `json:"label"`
	Black bool   `json:"black"`
}

// TypeCatalog 返回全部查询类型，顺序稳定，便于展示与测试。
func TypeCatalog() []TypeInfo {
	out := make([]TypeInfo, 0, len(typeTable))
	for code, m := range typeTable {
		out = append(out, TypeInfo{Type: code, Label: m.Label, Black: m.Black})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Black != out[j].Black {
			return !out[i].Black // 普通类型在前
		}
		return out[i].Type < out[j].Type
	})
	return out
}
