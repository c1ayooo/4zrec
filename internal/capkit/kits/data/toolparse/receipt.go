package toolparse

import (
	"encoding/json"
	"strings"
)

// receipt 模型可见回执的结构（§4.6）。字段名即回执字段，模型据此消费。
type receipt struct {
	OK            bool           `json:"ok"`
	Tool          string         `json:"tool"`
	Fields        map[string]any `json:"structured"`            // 只放标量与计数（防上下文回涨）
	FactsRecorded int            `json:"facts_recorded"`        // 本次成功落库条数
	FactsIndex    []string       `json:"facts_index"`           // 已落库的事实键（定长截断）
	RawRef        string         `json:"raw_ref,omitempty"`     // 原始证据绝对路径
	ParseError    bool           `json:"parse_error,omitempty"` // true = 已回退原文（§4.7）
	Truncated     bool           `json:"truncated,omitempty"`
}

// MaxReceiptBytes 回执硬上限（§4.6：2KB）。
const MaxReceiptBytes = 2048

// MaxFactsIndexEntries facts_index 展示条数上限（超限截断 + 计数兜底，§5.5 双写率口径依赖它存在）。
const MaxFactsIndexEntries = 12

// RenderReceipt 渲染模型可见回执文本（Content[0].Text 用）。
// 规则：超出 MaxReceiptBytes 时先裁 facts_index，再整体截断加尾注。
func RenderReceipt(res *Result, recorded int) string {
	r := &receipt{
		OK:            res.OK,
		Tool:          res.Tool,
		Fields:        res.Fields,
		FactsRecorded: recorded,
		RawRef:        res.RawRef,
		ParseError:    !res.OK,
	}
	for _, f := range res.Facts {
		r.FactsIndex = append(r.FactsIndex, f.FactKey)
	}
	truncated := len(r.FactsIndex) > MaxFactsIndexEntries
	if truncated {
		r.FactsIndex = r.FactsIndex[:MaxFactsIndexEntries]
	}
	b, err := json.Marshal(r)
	if err != nil {
		// 极端兜底（字段含不可序列化值时）
		return `{"ok":false,"tool":"` + res.Tool + `","parse_error":true}`
	}
	out := string(b)
	if len(out) > MaxReceiptBytes {
		// 先裁 fields（保留 facts_index 与关键计数）再整体截断
		r.Fields = map[string]any{}
		r.Truncated = true
		if nb, err := json.Marshal(r); err == nil {
			out = string(nb)
		}
		if len(out) > MaxReceiptBytes {
			room := MaxReceiptBytes - 3
			if room < 1 {
				room = 1
			}
			out = out[:room] + "..."
		}
	}
	return out
}

// RenderParseError 解析失败回退时的回执（§4.7：标 parse_error，模型据此知道该次未落库）。
func RenderParseError(tool string) string {
	return `{"ok":false,"tool":"` + strings.ToLower(tool) + `","parse_error":true,"facts_recorded":0}`
}
