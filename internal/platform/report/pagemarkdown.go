package report

import (
	"html"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	mdHeadingRe = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
	mdImageRe   = regexp.MustCompile(`^!\[(.*?)\]\((.*?)\)\s*$`)
	mdBulletRe  = regexp.MustCompile(`^[-*]\s+(.*)$`)
	mdNumberRe  = regexp.MustCompile(`^\d+[.)]\s+(.*)$`)
	mdLinkRe    = regexp.MustCompile(`\[([^\]]*)\]\(([^)]+)\)`)
)

// markdownToBlocks renders the finding detail report (findings.report) into the
// block model shared with the docx/PDF renderers. It covers the subset of
// Markdown the reports actually use: headings, paragraphs, fenced code, GFM
// tables, blockquotes, lists and images. Raw HTML is escaped.
func markdownToBlocks(md, dataDir string) []procBlock {
	md = strings.ReplaceAll(md, "\r\n", "\n")
	lines := strings.Split(md, "\n")
	var out []procBlock
	sawTitle := false
	for i := 0; i < len(lines); {
		trim := strings.TrimSpace(lines[i])
		if trim == "" {
			i++
			continue
		}
		if strings.HasPrefix(trim, "```") || strings.HasPrefix(trim, "~~~") {
			fence := trim[:3]
			i++
			var code []string
			for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), fence) {
				code = append(code, lines[i])
				i++
			}
			if i < len(lines) {
				i++
			}
			out = append(out, procBlock{Type: "code", Content: strings.Join(code, "\n")})
			continue
		}
		if m := mdHeadingRe.FindStringSubmatch(trim); m != nil {
			level := len(m[1])
			text := cleanInline(m[2])
			if level == 1 && !sawTitle {
				sawTitle = true
				i++
				continue // page title; the docx/PDF header already carries it
			}
			out = append(out, procBlock{Type: "heading", Content: text, Level: level})
			i++
			continue
		}
		if m := mdImageRe.FindStringSubmatch(trim); m != nil {
			alt, src := cleanInline(m[1]), strings.TrimSpace(m[2])
			if p := localReportAsset(src, dataDir); p != "" {
				out = append(out, procBlock{Type: "image", Path: p, Caption: alt})
			} else {
				out = append(out, procBlock{Type: "text", Content: "（图片未找到：" + alt + "）"})
			}
			i++
			continue
		}
		if strings.HasPrefix(trim, "|") {
			var rows [][]string
			for i < len(lines) {
				t := strings.TrimSpace(lines[i])
				if !strings.HasPrefix(t, "|") {
					break
				}
				row := splitTableRow(t)
				if !isTableSeparator(row) {
					rows = append(rows, row)
				}
				i++
			}
			if len(rows) > 0 {
				out = append(out, procBlock{Type: "table", Rows: rows})
			}
			continue
		}
		if strings.HasPrefix(trim, ">") {
			var quote []string
			for i < len(lines) {
				t := strings.TrimSpace(lines[i])
				if !strings.HasPrefix(t, ">") {
					break
				}
				quote = append(quote, cleanInline(strings.TrimSpace(strings.TrimPrefix(t, ">"))))
				i++
			}
			out = append(out, procBlock{Type: "quote", Content: strings.Join(quote, "\n")})
			continue
		}
		if m := mdBulletRe.FindStringSubmatch(trim); m != nil {
			out = append(out, procBlock{Type: "bullet", Content: cleanInline(m[1])})
			i++
			continue
		}
		if m := mdNumberRe.FindStringSubmatch(trim); m != nil {
			out = append(out, procBlock{Type: "numbered", Content: cleanInline(m[1])})
			i++
			continue
		}
		// paragraph: gather until a blank line or another block type
		var para []string
		for i < len(lines) {
			t := strings.TrimSpace(lines[i])
			if t == "" || strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") ||
				strings.HasPrefix(t, "|") || strings.HasPrefix(t, ">") ||
				mdHeadingRe.MatchString(t) || mdImageRe.MatchString(t) ||
				mdBulletRe.MatchString(t) || mdNumberRe.MatchString(t) {
				break
			}
			para = append(para, cleanInline(t))
			i++
		}
		out = append(out, procBlock{Type: "text", Content: strings.Join(para, "\n")})
	}
	return out
}

func cleanInline(s string) string {
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "__", "")
	s = strings.ReplaceAll(s, "`", "")
	s = mdLinkRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := mdLinkRe.FindStringSubmatch(m)
		text, link := sub[1], sub[2]
		if text == "" || text == link {
			return text
		}
		return text + "（" + link + "）"
	})
	return strings.TrimSpace(s)
}

func splitTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	for i := range parts {
		parts[i] = cleanInline(parts[i])
	}
	return parts
}

func isTableSeparator(row []string) bool {
	if len(row) == 0 {
		return false
	}
	for _, c := range row {
		c = strings.ReplaceAll(c, " ", "")
		if len(c) < 3 {
			return false
		}
		c = strings.TrimPrefix(c, ":")
		c = strings.TrimSuffix(c, ":")
		if strings.Trim(c, "-") != "" {
			return false
		}
	}
	return true
}

// localReportAsset maps a report image URL to the local report-assets file.
// External/data URLs are rejected so exports never fetch remote content.
func localReportAsset(src, dataDir string) string {
	if dataDir == "" || src == "" {
		return ""
	}
	if strings.HasPrefix(src, "data:") || strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return ""
	}
	u, err := url.Parse(src)
	if err != nil {
		return ""
	}
	if !strings.HasPrefix(u.Path, "/api/report-assets/") {
		return ""
	}
	name := filepath.Base(u.Path)
	if name == "." || name == "/" || name == "" {
		return ""
	}
	path := filepath.Join(dataDir, "report_assets", name)
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		return path
	}
	return ""
}
