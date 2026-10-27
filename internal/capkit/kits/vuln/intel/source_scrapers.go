package intel

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// ---- 启明星辰漏洞通告 (venustech.com.cn) ----
//
// The advisory list is a CMS page of <li><a href="/new_type/aqtg/<file>.html">
// rows; the detail page carries a two-column 表 with 漏洞名称 / CVEID /
// 发现时间 / 漏洞等级. Both are extracted by shape, not by the site's CSS
// class chain, which changes on every CMS upgrade.
const (
	venustechListURL = "https://www.venustech.com.cn/new_type/aqtg/"
	venustechMax     = 20
)

type venustechSource struct{ c *client }

func newVenustechSource(c *client) Source { return &venustechSource{c: c} }

func (s *venustechSource) Info() Info {
	return Info{
		Name:        "venustech",
		DisplayName: "启明星辰漏洞通告",
		Link:        "https://www.venustech.com.cn/new_type/aqtg/",
	}
}

func (s *venustechSource) Fetch(ctx context.Context, limit int) ([]core.IntelItem, error) {
	if limit <= 0 || limit > venustechMax {
		limit = venustechMax
	}
	raw, err := s.c.get(ctx, venustechListURL, map[string]string{
		"Accept": "text/html,application/xhtml+xml",
	})
	if err != nil {
		return nil, upstreamError("venustech", err)
	}
	links := parseVenustechList(raw)
	if len(links) == 0 {
		return nil, upstreamError("venustech", fmt.Errorf("列表页未解析到通告条目（页面结构可能已变更）"))
	}
	if len(links) > limit {
		links = links[:limit]
	}
	out := make([]core.IntelItem, 0, len(links))
	for _, link := range links {
		item, err := s.detail(ctx, link)
		if err != nil {
			// The list page already carries the title and the date, so a
			// throttled detail degrades the advisory instead of dropping it.
			// Losing rows to a 403 would make the source look quiet when it is
			// actually being rate-limited.
			if link.Title != "" {
				out = append(out, core.IntelItem{
					Source:     "venustech",
					UniqueKey:  uniqueKey(link.Path, "venustech"),
					Title:      link.Title,
					Severity:   SeverityUnknown,
					Disclosure: link.Date,
					SourceURL:  "https://www.venustech.com.cn" + link.Path,
				})
			}
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *venustechSource) detail(ctx context.Context, link venustechLink) (core.IntelItem, error) {
	var item core.IntelItem
	url := "https://www.venustech.com.cn" + link.Path
	raw, err := s.c.get(ctx, url, map[string]string{"Accept": "text/html,application/xhtml+xml"})
	if err != nil {
		return item, err
	}
	title := firstNonEmpty(firstHeading(raw), link.Title)
	if title == "" {
		return item, fmt.Errorf("%s 无标题", link.Path)
	}
	// The detail page used to carry a 漏洞名称/CVEID/漏洞等级 table; it is now
	// prose in sections (一、漏洞描述 / 二、影响范围 / 三、安全措施) with no
	// severity field anywhere. Severity is therefore reported as unknown rather
	// than guessed from wording, and the CVE comes from the title or body text.
	body := normalizeCell(string(raw))
	return core.IntelItem{
		Source:      s.Info().Name,
		UniqueKey:   uniqueKey(link.Path, "venustech"),
		Title:       title,
		Description: trimDescription(raw),
		Severity:    SeverityUnknown,
		CVE:         firstCVE(title + " " + firstParagraph(body)),
		Disclosure:  firstNonEmpty(link.Date, firstDateToken(body)),
		SourceURL:   url,
	}, nil
}

// firstParagraph returns the leading prose of the advisory body, used as the
// CVE search space when the title does not name one.
func firstParagraph(body string) string {
	if i := strings.Index(body, "二、"); i > 0 {
		return body[:i]
	}
	if len([]rune(body)) > 2000 {
		return string([]rune(body)[:2000])
	}
	return body
}

var (
	// reVenustechItem captures the link and the anchor text only. The date is
	// read from the window between this row and the next one, so a row's date
	// can never be attributed to the row before it.
	reVenustechItem = regexp.MustCompile(`href="(/new_type/aqtg/[^"#]+\.html)"[^>]*>(.*?)</a>`)
	reCellPair      = regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`)
	reHeading       = regexp.MustCompile(`(?s)<h3[^>]*>(.*?)</h3>`)
	reTagBlock      = regexp.MustCompile(`(?s)<[^>]+>`)
	reWhitespaceRun = regexp.MustCompile(`[\s\x{00A0}]+`)
	reCVE           = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	// reDate pulls the date that trails each list anchor:
	// <a href="...">title</a><span>2026-10-08</span>.
	reDate = regexp.MustCompile(`\d{4}[-/]\d{2}[-/]\d{2}`)
)

// venustechLink is one row of the advisory list: everything the list page
// proves on its own, so a detail page that cannot be fetched still yields a
// usable advisory instead of dropping the row.
type venustechLink struct {
	Path  string
	Title string
	Date  string
}

// parseVenustechList reads the list rows. The metadata lives on the returned
// values rather than in package state: two polls in one process must not share
// a mutable map.
func parseVenustechList(page []byte) []venustechLink {
	var out []venustechLink
	seen := map[string]bool{}
	idxs := reVenustechItem.FindAllSubmatchIndex(page, -1)
	for i, idx := range idxs {
		path := string(page[idx[2]:idx[3]])
		if seen[path] {
			continue
		}
		seen[path] = true
		link := venustechLink{
			Path:  path,
			Title: strings.TrimSpace(normalizeCell(string(page[idx[4]:idx[5]]))),
		}
		// The date sits after </a>, before the next row. Reading to the next
		// match (rather than a fixed window) keeps one row's date from being
		// attributed to the row above it.
		windowEnd := len(page)
		if i+1 < len(idxs) {
			windowEnd = idxs[i+1][0]
		}
		if windowEnd > idx[1] {
			if d := reDate.FindString(string(page[idx[1]:windowEnd])); d != "" {
				link.Date = dayOnly(parseTime(d))
			}
		}
		out = append(out, link)
	}
	return out
}

// parseTwoColumnTable reads a label/value table into a map. The advisory 表
// alternates label and value cells, so pairs are read two at a time.
func parseTwoColumnTable(page []byte) map[string]string {
	cells := reCellPair.FindAllSubmatch(page, -1)
	out := map[string]string{}
	for i := 0; i+1 < len(cells); i += 2 {
		key := normalizeCell(string(cells[i][1]))
		val := normalizeCell(string(cells[i+1][1]))
		if key == "" || val == "" {
			continue
		}
		if _, exists := out[key]; !exists {
			out[key] = val
		}
	}
	return out
}

func normalizeCell(s string) string {
	s = reTagBlock.ReplaceAllString(s, " ")
	s = reWhitespaceRun.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

func firstHeading(page []byte) string {
	if m := reHeading.FindSubmatch(page); m != nil {
		return normalizeCell(string(m[1]))
	}
	return ""
}

// firstCVE keeps only the first CVE of a 顿号-separated list: an advisory
// listing several CVEs is still one entry, and the host has one cve column.
func firstCVE(raw string) string {
	if m := reCVE.FindString(raw); m != "" {
		return m
	}
	if i := strings.IndexAny(raw, "、,;"); i > 0 {
		return strings.TrimSpace(raw[:i])
	}
	return strings.TrimSpace(raw)
}

// trimDescription takes the first non-empty paragraph after the 表.
func trimDescription(page []byte) string {
	body := reTagBlock.ReplaceAllString(string(page), "\n")
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if len([]rune(line)) >= 40 {
			return line
		}
	}
	return ""
}

// ---- Apache Struts2 Security Bulletins (cwiki.apache.org) ----

const (
	struts2URL  = "https://cwiki.apache.org/confluence/display/WW/Security+Bulletins"
	struts2Base = "https://cwiki.apache.org"
	struts2Max  = 5 // every bulletin costs one detail request
)

type struts2Source struct{ c *client }

func newStruts2Source(c *client) Source { return &struts2Source{c: c} }

func (s *struts2Source) Info() Info {
	return Info{
		Name:        "struts2",
		DisplayName: "Apache Struts2 Security Bulletins",
		Link:        struts2URL,
	}
}

func (s *struts2Source) Fetch(ctx context.Context, limit int) ([]core.IntelItem, error) {
	if limit <= 0 || limit > struts2Max {
		limit = struts2Max
	}
	raw, err := s.c.get(ctx, struts2URL, map[string]string{
		"Accept":  "text/html,application/xhtml+xml",
		"Referer": "https://cwiki.apache.org/",
	})
	if err != nil {
		return nil, upstreamError("struts2", err)
	}
	entries := parseStruts2List(raw)
	if len(entries) == 0 {
		return nil, upstreamError("struts2", fmt.Errorf("公告页未解析到条目（页面结构可能已变更）"))
	}
	// The page lists oldest first: the newest bulletins are at the end.
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	out := make([]core.IntelItem, 0, len(entries))
	for _, e := range entries {
		// The list page carries only the id since Confluence moved to the
		// spaces/pages markup, so the title, CVE and severity live on the
		// bulletin page itself.
		detail, derr := s.c.get(ctx, struts2Base+e.URL, map[string]string{
			"Accept":  "text/html,application/xhtml+xml",
			"Referer": struts2URL,
		})
		title, cve, impact := e.Title, "", ""
		if derr != nil {
			// A bulletin that cannot be read is still an advisory: keep the id
			// and the page link, and let the host see an unknown severity
			// rather than silently dropping the row.
			title = firstNonEmpty(e.Title, e.ID)
		} else {
			title, cve, impact = parseStruts2Detail(detail)
			if title == "" {
				title = firstNonEmpty(e.Title, e.ID)
			}
		}
		out = append(out, core.IntelItem{
			Source:    s.Info().Name,
			UniqueKey: uniqueKey(e.ID, "Struts2"),
			Title:     title,
			CVE:       cve,
			Severity:  struts2Severity(impact),
			SourceURL: struts2Base + e.URL,
		})
	}
	return out, nil
}

type struts2Entry struct {
	ID    string
	Title string
	// URL is the site-relative bulletin path, e.g.
	// /confluence/spaces/WW/pages/61776/S2-001.
	URL string
}

var (
	// The child-page list is the one place the page ids live. Confluence's
	// current markup is
	//   <li class="child-item" data-page-id="61776">
	//     <a href="/confluence/spaces/WW/pages/61776/S2-001" ...>
	// and the older /confluence/display/WW/S2-001 form still appears on some
	// pages, so both are accepted.
	reStruts2Item = regexp.MustCompile(`<a[^>]+href="(/confluence/(?:spaces/WW/pages/\d+|display/WW)/S2-\d{3})"[^>]*>`)
	reS2ID        = regexp.MustCompile(`S2-\d{3}`)
	reCVEInText   = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
)

// parseStruts2List collects the bulletin links. The list page no longer carries
// titles, CVEs or severities — only the link — so this returns id + path and
// the caller reads the bulletin page.
func parseStruts2List(page []byte) []struts2Entry {
	var out []struts2Entry
	seen := map[string]bool{}
	for _, m := range reStruts2Item.FindAllSubmatch(page, -1) {
		href := string(m[1])
		id := reS2ID.FindString(href)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, struts2Entry{ID: id, URL: href})
	}
	return out
}

// parseStruts2Detail reads the title, CVE and impact line from a bulletin page.
// The page renders a two-column table; the impact row is labelled
// "Maximum security rating" and the value is Critical/Important/Moderate/Low.
func parseStruts2Detail(page []byte) (title, cve, impact string) {
	text := string(page)
	if m := regexp.MustCompile(`(?s)<title>(.*?)</title>`).FindStringSubmatch(text); m != nil {
		title = normalizeCell(m[1])
		// Confluence appends the space name: "S2-001 - Apache Struts 2 Wiki -
		// ..." — but normalizeCell collapses whitespace, so the separator is
		// "-Apache" by the time we see it.
		if i := strings.Index(title, "-Apache"); i > 0 {
			title = strings.TrimSpace(title[:i])
		}
	}
	cve = reCVEInText.FindString(normalizeCell(text))
	if i := strings.Index(text, "Maximum security rating"); i >= 0 {
		impact = normalizeCell(text[i:])
		if len([]rune(impact)) > 300 {
			impact = string([]rune(impact)[:300])
		}
	}
	return title, cve, impact
}

// struts2Severity maps the bulletin's Apache severity wording onto the scale.
// Struts bulletins publish "Critical/Important/Moderate/Low" in the impact
// line rather than a numeric score.
func struts2Severity(impact string) string {
	lower := strings.ToLower(impact)
	switch {
	case strings.Contains(lower, "critical"):
		return SeverityCritical
	case strings.Contains(lower, "important"):
		return SeverityHigh
	case strings.Contains(lower, "moderate"):
		return SeverityMedium
	case strings.Contains(lower, "low"):
		return SeverityLow
	}
	return SeverityUnknown
}
