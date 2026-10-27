package core

import (
	"strconv"
	"strings"
	"time"
)

// Small shared helpers. They live in the root package because kits may only
// import the root (docs §3.2: kits → capkit 根), so this is the one place a
// helper can be defined once instead of copied into every kit. They are
// plumbing, not part of the wire contract.

// FirstNonEmpty returns the first value that is not empty after trimming
// surrounding whitespace.
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// TimeoutFromMS converts a millisecond budget into a duration, falling back to
// def when the budget is unset and clamping anything larger than max.
func TimeoutFromMS(ms int, def, max time.Duration) time.Duration {
	if ms <= 0 {
		return def
	}
	d := time.Duration(ms) * time.Millisecond
	if max > 0 && d > max {
		d = max
	}
	return d
}

// FirstPositive returns v when it is positive, otherwise fallback.
func FirstPositive(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

// Truncate cuts s to at most n bytes, appending an ellipsis when it had to.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// CursorFor renders the opaque cursor that addresses item offset, for tools to
// hand back in Page.Cursor.
func CursorFor(offset int) string {
	if offset <= 0 {
		return ""
	}
	return "off:" + strconv.Itoa(offset)
}

// PageWindow resolves a list request into the [start,end) window of a list of
// total items, plus the Page describing it. Tools whose list can exceed
// MaxListItems call this so rows are never silently dropped (docs §5.5.4:
// "列表类结果…超过 100 条必须分页，用 Cursor 续取"). pageSize <= 0 means
// MaxListItems.
//
// An unusable cursor is an error rather than a silent restart at zero: an agent
// that paged past the end must be told, not handed the first page again.
func PageWindow(total int, cursor string, pageSize int) (start, end int, page *Page, err error) {
	if pageSize <= 0 {
		pageSize = MaxListItems
	}
	offset := 0
	if c := strings.TrimSpace(cursor); c != "" {
		if !strings.HasPrefix(c, "off:") {
			return 0, 0, nil, InvalidInput("cursor 非法，需使用上一次返回的 page.cursor")
		}
		n, cerr := strconv.Atoi(strings.TrimPrefix(c, "off:"))
		if cerr != nil || n < 0 {
			return 0, 0, nil, InvalidInput("cursor 非法，需使用上一次返回的 page.cursor")
		}
		offset = n
	}
	if total < 0 {
		total = 0
	}
	if offset > total {
		offset = total
	}
	start = offset
	end = offset + pageSize
	if end > total {
		end = total
	}
	page = &Page{Total: total, HasMore: end < total}
	if page.HasMore {
		page.Cursor = CursorFor(end)
	}
	return start, end, page, nil
}

// PreviewRunes returns at most n runes of s, for an EvidenceRef preview
// (docs §5.5.4: the preview is <=200 characters, and runes — not bytes — are
// what "characters" means for a Chinese target).
func PreviewRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// EvidenceRefs collects one reference per distinct evidence id, in the order the
// outputs were produced, so a result can point at its stored command output.
func EvidenceRefs(outs ...Output) []EvidenceRef {
	var refs []EvidenceRef
	seen := map[string]bool{}
	for _, o := range outs {
		if o.EvidenceID == "" || seen[o.EvidenceID] {
			continue
		}
		seen[o.EvidenceID] = true
		refs = append(refs, EvidenceRef{ID: o.EvidenceID, Kind: "command_output", Size: len(o.Stdout)})
	}
	return refs
}
