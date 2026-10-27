package intel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// ---- 阿里云漏洞库 (avd.aliyun.com): NOT implemented here ----
//
// AVD has no built-in source in this kit on purpose. Every path on the site —
// list, detail and the guessed /api/* endpoints — answers with the same ~27KB
// obfuscated JavaScript page. The real content is assembled in the browser
// from a signed ?timestamp__NNNN= parameter that the script computes, so a
// plain HTTP client can never read the data (verified live, 2026-10-20).
//
// Clearing that needs a JavaScript engine. That is a runtime dependency and a
// remote-code-execution surface the library should not carry for one source,
// so the host supplies it: implement core.IntelSource (4zrec runs the page's
// script in goja and parses the resulting URL) and pass it in
// core.Deps.ExtraIntel. The kit then polls it through the same store, severity
// gate and dedup key as everything else.

// ---- Seebug ----

// seebugListURL is the advisory table page. One page is fetched per poll: the
// list is newest-first and the poll is periodic, so paging adds traffic without
// adding advisories the next poll will not surface anyway.
const seebugListURL = "https://www.seebug.org/vuldb/vulnerabilities?page=1"

type seebugSource struct{ c *client }

func newSeebugSource(c *client) Source { return &seebugSource{c: c} }

func (s *seebugSource) Info() Info {
	return Info{
		Name:        "seebug",
		DisplayName: "Seebug 漏洞平台",
		Link:        "https://www.seebug.org",
	}
}

func (s *seebugSource) Fetch(ctx context.Context, limit int) ([]core.IntelItem, error) {
	if limit <= 0 {
		limit = 20
	}
	raw, err := s.c.get(ctx, seebugListURL, map[string]string{
		"Accept":  "text/html,application/xhtml+xml",
		"Referer": "https://www.seebug.org/",
	})
	if err != nil {
		return nil, upstreamError("seebug", err)
	}
	rows := parseSeebugRows(raw)
	out := make([]core.IntelItem, 0, len(rows))
	for _, r := range rows {
		if r.Link == "" || r.Title == "" {
			continue
		}
		out = append(out, core.IntelItem{
			Source:      s.Info().Name,
			UniqueKey:   uniqueKey(r.Link, "seebug"),
			Title:       r.Title,
			Severity:    NormalizeSeverity(r.Level),
			CVE:         r.CVE,
			Disclosure:  r.Date,
			SourceURL:   "https://www.seebug.org" + r.Link,
			Tags:        nonEmpty(r.Tags),
			Description: r.Description,
		})
		if len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		return nil, upstreamError("seebug", fmt.Errorf("列表页未解析到漏洞条目（页面结构可能已变更）"))
	}
	return out, nil
}

type seebugRow struct {
	Link        string
	Title       string
	Level       string
	Date        string
	CVE         string
	Tags        []string
	Description string
}

// parseSeebugRows reads the advisory table rows.
//
// Each <tr> holds two anchors pointing at the same advisory: the first carries
// the SSV id (`/vuldb/ssvid-99969` → "SSV-99969"), the second carries the
// human-readable title (class="vul-title"). The severity is on a div as
// `class="vul-level high"` and spelled out in data-original-title="高危", and
// the CVE — when there is one — is in `data-original-title` on the id-card
// icon. Two icons also advertise PoC and detail presence, which are the only
// per-advisory facts the list page exposes about them.
func parseSeebugRows(page []byte) []seebugRow {
	text := string(page)
	var out []seebugRow
	for _, raw := range strings.Split(text, "<tr") {
		link := firstAttr(raw, `/vuldb/ssvid-`)
		if link == "" {
			continue
		}
		row := seebugRow{Link: link}
		// The title is the anchor text after class="vul-title", not an attribute
		// value: skip to the tag's closing '>' first, then read to </a>.
		if i := strings.Index(raw, `class="vul-title"`); i >= 0 {
			if gt := strings.IndexByte(raw[i:], '>'); gt >= 0 {
				rest := raw[i+gt+1:]
				if end := strings.Index(rest, "</a>"); end > 0 {
					row.Title = strings.TrimSpace(stripTags(rest[:end]))
				}
			}
		}
		// Priority: the spelled-out level, then the CSS class on the level div.
		if lv := attrValue(raw, "vul-level ", `data-original-title="`); lv != "" {
			row.Level = lv
		} else if lv := levelFromSeebugClass(raw); lv != "" {
			row.Level = lv
		}
		if cve := attrValue(raw, `id-card`, `data-original-title="`); cve != "" && reCVE.MatchString(cve) {
			row.CVE = reCVE.FindString(cve)
		}
		if strings.Contains(raw, `data-original-title="有 PoC"`) {
			row.Tags = append(row.Tags, "有Poc")
		}
		if strings.Contains(raw, `data-original-title="有详情"`) {
			row.Tags = append(row.Tags, "有详情")
		}
		if date := findDateIn(raw); date != "" {
			row.Date = date
		}
		out = append(out, row)
	}
	return out
}

// firstAttr returns the attribute value that starts with valuePrefix. The
// prefix is part of the returned value, e.g.
// firstAttr(`href="/vuldb/ssvid-99969"`, `/vuldb/ssvid-`) → "/vuldb/ssvid-99969".
// Returns "" when the prefix is absent or unterminated. Values never contain a
// raw quote in the markup this scrapes, so the closing delimiter is enough.
func firstAttr(raw, valuePrefix string) string {
	i := strings.Index(raw, valuePrefix)
	if i < 0 {
		return ""
	}
	start := i + len(valuePrefix)
	end := strings.IndexByte(raw[start:], '"')
	if end < 0 {
		return ""
	}
	return valuePrefix + raw[start:start+end]
}

// attrValue finds `needle` in raw, then returns the quoted value that follows
// the next occurrence of `attrPrefix` (typically `data-original-title="`).
// It is used to pull a value that sits on the same element as a distinctive
// marker: the level div is identified by "vul-level ", its label by the
// adjacent data-original-title.
func attrValue(raw, needle, attrPrefix string) string {
	i := strings.Index(raw, needle)
	if i < 0 {
		return ""
	}
	rest := raw[i:]
	j := strings.Index(rest, attrPrefix)
	if j < 0 {
		return ""
	}
	// Only accept it on the same tag: stop at the first '>' after the marker.
	if gt := strings.IndexByte(rest, '>'); gt >= 0 && gt < j {
		return ""
	}
	start := j + len(attrPrefix)
	end := strings.IndexByte(rest[start:], '"')
	if end < 0 {
		return ""
	}
	return rest[start : start+end]
}

// levelFromSeebugClass reads the severity from `class="vul-level <level>"`.
func levelFromSeebugClass(row string) string {
	i := strings.Index(row, `class="vul-level`)
	if i < 0 {
		return ""
	}
	rest := row[i+len(`class="`):]
	if end := strings.IndexByte(rest, '"'); end > 0 {
		for _, level := range []string{"high", "medium", "low"} {
			if strings.Contains(rest[:end], level) {
				switch level {
				case "high":
					return "高危"
				case "medium":
					return "中危"
				case "low":
					return "低危"
				}
			}
		}
	}
	return ""
}

func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '<':
			depth++
		case r == '>':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func findDateIn(s string) string {
	for _, layout := range []string{"2006-01-02", "2006/01/02"} {
		if t, err := time.Parse(layout, firstDateToken(s)); err == nil {
			return t.Format("2006-01-02")
		}
	}
	return ""
}

// firstDateToken scans for the first YYYY-MM-DD or YYYY/MM/DD substring.
func firstDateToken(s string) string {
	for _, sep := range []byte{'-', '/'} {
		for i := 0; i+9 < len(s); i++ {
			tok := s[i : i+10]
			if tok[4] == sep && tok[7] == sep && isDigits(tok[:4]) && isDigits(tok[5:7]) && isDigits(tok[8:10]) {
				return tok
			}
		}
	}
	return ""
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
