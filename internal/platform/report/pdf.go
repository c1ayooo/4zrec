package report

// Single-finding PDF export. Renders the same content the finding detail page
// shows (summary + evidence + the stored detailed report) into a print-friendly
// HTML document and converts it with headless Chromium. Images referenced via
// /api/report-assets are embedded as data URIs so the PDF is self-contained.

import (
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PDFTrafficRow is one bound traffic-evidence row shown in the export appendix.
type PDFTrafficRow struct {
	Role    string
	Method  string
	URL     string
	Status  int
	RespLen int64
	Note    string
}

// PDFInput is the page content for a single finding PDF export.
type PDFInput struct {
	FindingID   int64
	Title       string
	Severity    string
	Status      string
	Target      string
	FoundDate   string
	Summary     string
	Evidence    string
	Report      string // detailed report Markdown (findings.report)
	DataDir     string
	Traffic     []PDFTrafficRow
	GeneratedAt time.Time
}

// GeneratePDF renders in to a .pdf under workDir and returns its absolute path.
func GeneratePDF(ctx context.Context, in *PDFInput, workDir string) (string, error) {
	chromium := findChromium()
	if chromium == "" {
		return "", fmt.Errorf("未找到 Chromium/Chrome（PDF 导出需要 chromium 或 google-chrome）")
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return "", fmt.Errorf("创建 PDF 目录失败: %w", err)
	}
	doc := buildFindingHTML(in)
	htmlPath := filepath.Join(workDir, fmt.Sprintf("finding-%d.html", in.FindingID))
	if err := os.WriteFile(htmlPath, []byte(doc), 0o600); err != nil {
		return "", fmt.Errorf("写 HTML 失败: %w", err)
	}
	outPath := filepath.Join(workDir, fmt.Sprintf("finding-%d.pdf", in.FindingID))
	profile := filepath.Join(workDir, "chromium-profile")
	base := []string{
		"--headless", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
		"--user-data-dir=" + profile, "--no-pdf-header-footer",
		"--print-to-pdf=" + outPath, "file://" + htmlPath,
	}
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, chromium, base...).CombinedOutput()
	if err == nil {
		if fi, statErr := os.Stat(outPath); statErr == nil && fi.Size() > 0 {
			_ = os.Chmod(outPath, 0o600)
			return outPath, nil
		}
	}
	// Chrome's CLI print-to-pdf can hang on large data-URI images. Playwright's
	// page.pdf() uses the same engine through a stable CDP session, so use it as
	// the fallback before giving up.
	_ = os.Remove(outPath)
	if pyErr := generatePDFWithPlaywright(ctx, htmlPath, outPath, workDir); pyErr != nil {
		return "", fmt.Errorf("Chrome 生成 PDF 失败: %v: %s; Playwright 兜底失败: %v",
			err, strings.TrimSpace(string(out)), pyErr)
	}
	if fi, statErr := os.Stat(outPath); statErr != nil || fi.Size() == 0 {
		return "", fmt.Errorf("未生成有效 PDF: %v", statErr)
	}
	_ = os.Chmod(outPath, 0o600)
	return outPath, nil
}

func generatePDFWithPlaywright(ctx context.Context, htmlPath, outPath, workDir string) error {
	py := findPython()
	if py == "" {
		return fmt.Errorf("未找到 python3")
	}
	if exec.Command(py, "-c", "import playwright").Run() != nil {
		return fmt.Errorf("python3 未安装 playwright")
	}
	script := `import sys
from playwright.sync_api import sync_playwright
html, out = sys.argv[1], sys.argv[2]
with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    page.goto('file://' + html, wait_until='load')
    page.pdf(path=out, format='A4', print_background=True,
             margin={'top': '16mm', 'bottom': '18mm', 'left': '15mm', 'right': '15mm'})
    b.close()
`
	scriptPath := filepath.Join(workDir, "render_pdf.py")
	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		return fmt.Errorf("写 Playwright 脚本失败: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, py, scriptPath, htmlPath, outPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func findChromium() string {
	candidates := []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"}
	// Playwright-managed browsers live outside PATH. Both the Node and Python
	// Playwright installs default to ~/.cache/ms-playwright; honor an explicit
	// PLAYWRIGHT_BROWSERS_PATH too.
	var cacheDirs []string
	if home, err := os.UserHomeDir(); err == nil {
		cacheDirs = append(cacheDirs, filepath.Join(home, ".cache", "ms-playwright"))
	}
	if p := strings.TrimSpace(os.Getenv("PLAYWRIGHT_BROWSERS_PATH")); p != "" {
		cacheDirs = append(cacheDirs, p)
	}
	for _, dir := range cacheDirs {
		for _, pattern := range []string{
			filepath.Join(dir, "chromium-*", "chrome-linux*", "chrome"),
			filepath.Join(dir, "chromium-*", "chrome-linux*", "headless_shell"),
		} {
			if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
				candidates = append(candidates, matches...)
			}
		}
	}
	for _, name := range candidates {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		// A distro wrapper (e.g. /usr/bin/chromium-browser without the snap)
		// exists on PATH but cannot run; verify before selecting it. Chromium's
		// version string is "Chromium ...", not "Chrome ...", so match "chrom".
		out, err := exec.Command(p, "--version").CombinedOutput()
		if err == nil && strings.Contains(strings.ToLower(string(out)), "chrom") {
			return p
		}
	}
	return ""
}

func buildFindingHTML(in *PDFInput) string {
	var b strings.Builder
	title := html.EscapeString(in.Title)
	b.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">`)
	b.WriteString(`<title>` + title + `</title><style>`)
	b.WriteString(`
@page { size: A4; margin: 16mm 15mm 18mm; }
* { box-sizing: border-box; }
body { margin: 0; color: #111827; font-family: "Noto Sans CJK SC", "Microsoft YaHei", "PingFang SC", sans-serif; font-size: 10.5pt; line-height: 1.65; }
h1 { font-size: 19pt; line-height: 1.35; margin: 0 0 8px; color: #1f3a68; }
h2 { font-size: 13pt; margin: 18px 0 8px; color: #1f3a68; border-bottom: 1px solid #dbe3ef; padding-bottom: 3px; }
h3 { font-size: 11.5pt; margin: 14px 0 6px; color: #1f3a68; }
h4 { font-size: 10.8pt; margin: 12px 0 5px; color: #1f3a68; }
p { margin: 5px 0; }
ul, ol { margin: 5px 0 5px 20px; padding: 0; }
li { margin: 2px 0; }
pre { background: #f5f6f8; border: 1px solid #d9dee7; border-radius: 4px; padding: 8px 10px; white-space: pre-wrap; word-break: break-all; font-family: Consolas, "Courier New", monospace; font-size: 8.6pt; line-height: 1.45; }
code { font-family: Consolas, "Courier New", monospace; font-size: 8.8pt; }
blockquote { margin: 8px 0; padding: 6px 10px; border-left: 3px solid #cbd5e1; color: #4b5563; background: #f8fafc; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 8.8pt; table-layout: fixed; }
th, td { border: 1px solid #9aa4b2; padding: 4px 6px; vertical-align: top; text-align: left; word-break: break-all; overflow-wrap: anywhere; }
th { background: #e8eef7; font-weight: 700; }
figure { margin: 10px 0; page-break-inside: avoid; }
figure img { max-width: 100%; max-height: 22cm; width: auto; height: auto; border: 1px solid #cbd5e1; }
figcaption { font-size: 8.8pt; color: #4b5563; margin-top: 4px; }
.meta { color: #4b5563; font-size: 9.2pt; margin-bottom: 12px; }
.badge { display: inline-block; border: 1px solid #9aa4b2; border-radius: 10px; padding: 1px 8px; margin-right: 6px; font-size: 9pt; }
.head { border-bottom: 2px solid #e36c2a; padding-bottom: 10px; margin-bottom: 14px; }
.evidence { white-space: pre-wrap; word-break: break-all; }
.small { color: #6b7280; font-size: 8.6pt; }
`)
	b.WriteString(`</style></head><body>`)
	b.WriteString(`<div class="head"><h1>` + title + `</h1><div class="meta">`)
	b.WriteString(fmt.Sprintf(`<span class="badge">严重等级：%s</span>`, html.EscapeString(in.Severity)))
	if in.Target != "" {
		b.WriteString(`<span class="badge">目标：` + html.EscapeString(in.Target) + `</span>`)
	}
	if in.FoundDate != "" {
		b.WriteString(`<span class="badge">发现时间：` + html.EscapeString(in.FoundDate) + `</span>`)
	}
	b.WriteString(`</div></div>`)

	if strings.TrimSpace(in.Report) != "" {
		// The stored report already follows the SRC template (1–4 + appendix);
		// render it directly instead of wrapping it in摘要/证据/详细报告.
		b.WriteString(blocksHTML(PageBlocks(in.Report, in.DataDir)))
	} else {
		b.WriteString(`<h2>摘要</h2><p>` + strings.ReplaceAll(html.EscapeString(in.Summary), "\n", "<br>") + `</p>`)
		if strings.TrimSpace(in.Evidence) != "" {
			b.WriteString(`<h2>证据 / PoC</h2><pre class="evidence">` + html.EscapeString(in.Evidence) + `</pre>`)
		}
	}

	if len(in.Traffic) > 0 {
		b.WriteString(`<h2>关键请求与响应</h2><table><colgroup><col style="width:12%"><col style="width:46%"><col style="width:9%"><col style="width:11%"><col style="width:22%"></colgroup><thead><tr><th>用途</th><th>请求</th><th>响应</th><th>响应长度</th><th>说明</th></tr></thead><tbody>`)
		for _, t := range in.Traffic {
			role := map[string]string{"proof": "漏洞证明", "baseline": "正常对照", "verification": "补充验证", "supporting": "辅助证据"}[t.Role]
			if role == "" {
				role = t.Role
			}
			b.WriteString(`<tr><td>` + html.EscapeString(role) + `</td><td><code>` +
				html.EscapeString(t.Method+" "+t.URL) + `</code></td><td>` +
				fmt.Sprintf("%d", t.Status) + `</td><td>` + fmt.Sprintf("%d", t.RespLen) +
				`</td><td>` + html.EscapeString(t.Note) + `</td></tr>`)
		}
		b.WriteString(`</tbody></table>`)
	}
	b.WriteString(`</body></html>`)
	return b.String()
}

// PageBlocks exposes the page Markdown parser to callers outside this package.
func PageBlocks(markdown, dataDir string) []procBlock {
	return markdownToBlocks(markdown, dataDir)
}

func blocksHTML(blocks []procBlock) string {
	var b strings.Builder
	list := "" // "ul" | "ol"
	closeList := func() {
		if list != "" {
			b.WriteString("</" + list + ">")
			list = ""
		}
	}
	for _, blk := range blocks {
		switch blk.Type {
		case "heading":
			closeList()
			level := blk.Level + 1
			if level < 2 {
				level = 2
			}
			if level > 4 {
				level = 4
			}
			fmt.Fprintf(&b, "<h%d>%s</h%d>", level, html.EscapeString(blk.Content), level)
		case "code":
			closeList()
			b.WriteString(`<pre><code>` + html.EscapeString(blk.Content) + `</code></pre>`)
		case "image":
			closeList()
			if src := imageDataURI(blk.Path); src != "" {
				b.WriteString(`<figure><img src="` + src + `" alt="` + html.EscapeString(blk.Caption) + `">`)
				if blk.Caption != "" {
					b.WriteString(`<figcaption>` + html.EscapeString(blk.Caption) + `</figcaption>`)
				}
				b.WriteString(`</figure>`)
			}
		case "table":
			closeList()
			if len(blk.Rows) == 0 {
				continue
			}
			ncols := len(blk.Rows[0])
			if ncols == 0 {
				continue
			}
			b.WriteString(`<table><colgroup>`)
			for i := 0; i < ncols; i++ {
				fmt.Fprintf(&b, `<col style="width:%.2f%%">`, 100.0/float64(ncols))
			}
			b.WriteString(`</colgroup><thead><tr>`)
			for _, c := range blk.Rows[0] {
				b.WriteString(`<th>` + html.EscapeString(c) + `</th>`)
			}
			b.WriteString(`</tr></thead><tbody>`)
			for _, row := range blk.Rows[1:] {
				b.WriteString(`<tr>`)
				for _, c := range row {
					b.WriteString(`<td>` + html.EscapeString(c) + `</td>`)
				}
				b.WriteString(`</tr>`)
			}
			b.WriteString(`</tbody></table>`)
		case "quote":
			closeList()
			b.WriteString(`<blockquote>` + strings.ReplaceAll(html.EscapeString(blk.Content), "\n", "<br>") + `</blockquote>`)
		case "bullet", "numbered":
			want := "ul"
			if blk.Type == "numbered" {
				want = "ol"
			}
			if list != want {
				closeList()
				b.WriteString("<" + want + ">")
				list = want
			}
			b.WriteString(`<li>` + html.EscapeString(blk.Content) + `</li>`)
		default:
			closeList()
			b.WriteString(`<p>` + strings.ReplaceAll(html.EscapeString(blk.Content), "\n", "<br>") + `</p>`)
		}
	}
	closeList()
	return b.String()
}

func imageDataURI(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	mime := "image/png"
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jpg", ".jpeg":
		mime = "image/jpeg"
	case ".webp":
		mime = "image/webp"
	case ".gif":
		mime = "image/gif"
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
}
