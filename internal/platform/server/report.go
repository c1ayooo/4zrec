package server

// Human-grade .docx report: async pipeline (AI narrative + python-docx) layered
// on top of the existing Markdown quick-view. POST /generate kicks off generation,
// GET /status polls, GET /download serves the finished file. All per-task, in-memory.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/platform/notify"
	"github.com/c1ayooo/4zrec/internal/platform/report"
)

type reportJob struct {
	Status    string    `json:"status"` // generating | done | failed
	Filename  string    `json:"filename,omitempty"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`
	path      string    // absolute path (not serialized)
}

// reportLogoPath resolves a stored logo_path to an absolute file, but only when
// it stays inside data/report_assets. Otherwise the report builder would open
// any host file readable by the service user (e.g. ../../etc/passwd) and embed it.
func (s *Server) reportLogoPath(rel string) string {
	rel = strings.TrimSpace(rel)
	if rel == "" || filepath.IsAbs(rel) {
		return ""
	}
	root := filepath.Join(s.dataDir, "report_assets")
	abs := filepath.Join(s.dataDir, filepath.Clean(rel))
	if !pathWithin(root, abs) {
		return ""
	}
	return abs
}

// POST /api/report/generate?task=&company=&client=&title= — start async docx build.
func (s *Server) generateReport(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no active task")
		return
	}
	s.reportMu.Lock()
	if j := s.reportJobs[t.ID]; j != nil && j.Status == "generating" {
		snap := *j // copy under lock; the goroutine mutates *j concurrently
		s.reportMu.Unlock()
		writeJSON(w, 200, snap)
		return
	}
	job := &reportJob{Status: "generating", StartedAt: time.Now()}
	s.reportJobs[t.ID] = job
	snap := *job
	s.reportMu.Unlock()

	in := s.buildSRCReportInput(t, r.URL.Query())
	taskID := t.ID
	taskDesc := t.Description
	tid, _ := strconv.ParseInt(taskID, 10, 64)
	go func() {
		// A panic in the builder must not leave the job stuck in "generating" forever.
		defer func() {
			if rec := recover(); rec != nil {
				msg := fmt.Sprintf("报告生成异常：%v", rec)
				s.reportMu.Lock()
				job.Status = "failed"
				job.Error = msg
				s.reportMu.Unlock()
				s.notifyReportResult(tid, taskDesc, false, msg)
			}
		}()
		outPath, err := report.GenerateDocx(s.ctx, s.m.pg, in, filepath.Join(s.dataDir, "reports"), taskID)
		s.reportMu.Lock()
		if err != nil {
			job.Status = "failed"
			job.Error = err.Error()
			s.reportMu.Unlock()
			s.notifyReportResult(tid, taskDesc, false, err.Error())
			return
		}
		job.Status = "done"
		job.path = outPath
		job.Filename = filepath.Base(outPath)
		s.reportMu.Unlock()
		// persist to the reports list (report management page)
		var size int64
		if fi, e := os.Stat(outPath); e == nil {
			size = fi.Size()
		}
		_, _ = s.m.pg.AddReport(tid, taskDesc, filepath.Base(outPath), outPath, size, in.CompanyName)
		s.notifyReportResult(tid, taskDesc, true, filepath.Base(outPath))
	}()
	writeJSON(w, 202, snap)
}

func (s *Server) notifyReportResult(taskID int64, taskDesc string, ok bool, detail string) {
	kind, title, severity := notify.EventReportReady, "报告生成完成", "info"
	if !ok {
		kind, title, severity = notify.EventReportFailed, "报告生成失败", "high"
	}
	if strings.TrimSpace(taskDesc) != "" {
		title += "：" + taskDesc
	}
	_, _ = s.m.pg.AddNotificationEvent(s.ctx, kind, 0, notify.Snapshot{
		Kind: kind, Title: title, Category: "报告", Severity: severity,
		Summary: detail, TaskID: taskID, ActionURL: "/system/reports",
	})
}

// GET /api/report/status?task= — poll async generation state.
func (s *Server) reportStatus(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no active task")
		return
	}
	s.reportMu.Lock()
	job := s.reportJobs[t.ID]
	if job == nil {
		s.reportMu.Unlock()
		writeJSON(w, 200, map[string]any{"status": "idle"})
		return
	}
	snap := *job // copy under lock; the goroutine may be mutating *job
	s.reportMu.Unlock()
	writeJSON(w, 200, snap)
}

// GET /api/report/download?task= — stream the finished .docx.
func (s *Server) downloadReport(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no active task")
		return
	}
	s.reportMu.Lock()
	job := s.reportJobs[t.ID]
	var status, path, filename string
	if job != nil {
		status, path, filename = job.Status, job.path, job.Filename
	}
	s.reportMu.Unlock()
	if job == nil || status != "done" || path == "" {
		writeErr(w, 404, "报告尚未生成")
		return
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	http.ServeFile(w, r, path)
}

// buildSRCReportInput builds the consolidated SRC report document for a task.
// All report formats now use the SRC layout; the legacy 5-chapter pentest input
// builder is kept only for older code paths/tests.
func (s *Server) buildSRCReportInput(t *Task, q map[string][]string) *report.GenInput {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	title := get("title")
	if title == "" {
		title = defaultStrSrv(t.Name, "SRC") + " SRC 漏洞挖掘报告"
	}
	fs, _ := s.m.pg.ListFindingsForExport(db.FindingFilter{TaskID: t.ID}, nil)
	assets, flow := s.srcReportContext(fs)
	assetTypes := s.srcAssetTypes(fs)
	assetLabels := s.srcAssetLabels(fs)
	chains := report.GenerateSRCChainsWithAssets(s.ctx, s.m.pg, fs, assetTypes, assetLabels)
	md := report.BuildSRCMarkdownWithChains(fs, title, assets, flow, chains)
	company := get("company")
	if company == "" {
		company = "安全服务团队"
	}
	return &report.GenInput{
		CompanyName: company, ProjectName: title, ReportTitle: title,
		Locale: "zh-CN", CVSSVersion: "3.1",
		Findings: []report.FindingInput{{Name: title, PageMarkdown: md, CreatedAt: time.Now()}},
		SkillDir: s.skillDir, DataDir: s.dataDir, NoAI: true, PageOnly: true,
	}
}

// buildReportInput flattens the task's confirmed findings + global asset counts
// into the report input, with optional query overrides for the cover metadata.
func (s *Server) buildReportInput(t *Task, q map[string][]string) *report.GenInput {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	// Optional named template: preset cover/org metadata + default language.
	var tmpl *db.ReportTemplate
	if tid, _ := strconv.ParseInt(get("template_id"), 10, 64); tid > 0 {
		tmpl, _ = s.m.pg.GetReportTemplate(tid)
	}
	locale := get("locale") // "" | zh-CN | zh-TW | en-US
	if locale == "" && tmpl != nil {
		locale = tmpl.Locale
	}
	// Only reuse the persisted (Chinese) enrichment for zh-CN reports; for zh-TW/
	// en-US we regenerate per-finding so the whole report is in the target language.
	reuseEnrichment := locale == "" || strings.EqualFold(locale, "zh-CN")
	// Optional subset: ?finding_ids=12,15,18 selects specific findings (node IDs).
	idFilter := parseInt64Set(get("finding_ids"))

	nodes, _ := t.Store.ListByKind(db.KindFinding, 500)
	findings := make([]report.FindingInput, 0, len(nodes))
	for _, n := range nodes {
		if idFilter != nil && !idFilter[n.ID] {
			continue
		}
		var p struct {
			VulnClass string `json:"vulnclass"`
			Severity  string `json:"severity"`
			Summary   string `json:"summary"`
			Evidence  struct {
				PoC string `json:"poc"`
			} `json:"evidence"`
			Reproduction json.RawMessage `json:"reproduction"` // 就地记录的结构化复现过程(可空)
		}
		_ = json.Unmarshal(n.Payload, &p)
		fi := report.FindingInput{
			VulnClass: p.VulnClass, Severity: p.Severity, Summary: p.Summary,
			PoC: p.Evidence.PoC, CreatedAt: n.CreatedAt,
			Reproduction: p.Reproduction, // authoritative test_process — rendered verbatim, AI skips rebuild
		}
		// Reuse persisted enrichment (from the findings page "AI 分析") so the report
		// is consistent with what the user reviewed and skips a redundant LLM call.
		if enr, _ := s.m.pg.GetFindingEnrichment(n.ID); enr != nil {
			if reuseEnrichment {
				fi.Enrichment = reportEnrichmentFromDB(enr)
			}
			if strings.TrimSpace(enr.Severity) != "" {
				fi.Severity = enr.Severity // honor human severity override (language-agnostic)
			}
		}
		// No persisted enrichment to reuse (fresh finding, or zh-TW/en-US
		// regeneration) → ground the on-the-fly narrative in the real work
		// transcript, same as the findings-page "AI 分析".
		if fi.Enrichment == nil {
			fi.Transcript = s.m.pg.FindingSourceTranscript(n.ID, 40000)
		}
		findings = append(findings, fi)
	}
	counts := map[string]int{}
	if a := s.m.Assets(); a != nil {
		if c, err := a.CountsByType(); err == nil {
			counts = c
		}
	}
	// 项目名(封面/标题)用【短任务名】，绝不用整段描述——否则用户把目标系统清单写进
	// 描述时会被灌进封面"项目名称"、撑爆封面。完整描述另经 Scope 喂 AI。
	project := defaultStrSrv(t.Name, "渗透测试项目")
	if len([]rune(project)) > 40 { // 名称异常长(误填清单)→ 回退,别撑爆封面
		project = "渗透测试项目"
	}

	// Resolve org-level cover metadata. Precedence: explicit query param >
	// selected template > singleton report settings > built-in default.
	rs, _ := s.m.pg.GetReportSettings()
	var personnel []report.PersonInput
	companyName, companyEn, cvss, logoRel := "", "", "3.1", ""
	if rs != nil {
		_ = json.Unmarshal(rs.Personnel, &personnel)
		companyName, companyEn = rs.CompanyName, rs.CompanyNameEn
		cvss = defaultStrSrv(rs.CVSSVersion, "3.1")
		logoRel = rs.LogoPath
	}
	if tmpl != nil {
		if strings.TrimSpace(tmpl.CompanyName) != "" {
			companyName = tmpl.CompanyName
		}
		if strings.TrimSpace(tmpl.CompanyNameEn) != "" {
			companyEn = tmpl.CompanyNameEn
		}
		cvss = defaultStrSrv(tmpl.CVSSVersion, cvss)
		if strings.TrimSpace(tmpl.LogoPath) != "" {
			logoRel = tmpl.LogoPath
		}
		var tp []report.PersonInput
		if json.Unmarshal(tmpl.Personnel, &tp) == nil && len(tp) > 0 {
			personnel = tp
		}
	}
	logoPath := ""
	if strings.TrimSpace(logoRel) != "" {
		logoPath = s.reportLogoPath(logoRel)
	}
	return &report.GenInput{
		CompanyName:   defaultStrSrv(get("company"), companyName),
		CompanyNameEn: companyEn,
		ClientName:    get("client"),
		ProjectName:   defaultStrSrv(get("project"), project),
		Scope:         strings.TrimSpace(t.Description), // 完整目标系统清单/范围→喂 AI 叙述,不上封面

		ReportTitle: get("title"), // empty → BuildDoc applies locale-aware "<project> <报告词>"
		Version:     defaultStrSrv(get("version"), "V1.0"),
		Locale:      defaultStrSrv(locale, "zh-CN"),
		CVSSVersion: cvss,
		LogoPath:    logoPath,
		Personnel:   personnel,
		Findings:    findings,
		AssetCounts: counts,
		SkillDir:    s.skillDir,
		DataDir:     s.dataDir, // 用于客户报告脱敏内部 scratch 路径
	}
}

func defaultStrSrv(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

// parseInt64Set parses "12,15,18" into a set. Returns nil when empty so callers
// treat "no filter" as "all findings".
func parseInt64Set(csv string) map[int64]bool {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil
	}
	set := map[int64]bool{}
	for _, p := range strings.Split(csv, ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil {
			set[id] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// exportFindingName sanitizes a finding name into a download-friendly file stem.
func exportFindingName(name, vulnclass string) string {
	s := strings.TrimSpace(name)
	if s == "" {
		s = strings.TrimSpace(vulnclass)
	}
	if s == "" {
		s = "finding"
	}
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`/\:*?"<>|`, r) || r < 0x20 {
			r = '-'
		}
		b.WriteRune(r)
	}
	s = strings.Trim(strings.TrimSpace(b.String()), "-. ")
	if s == "" {
		s = "finding"
	}
	if runes := []rune(s); len(runes) > 60 {
		s = string(runes[:60])
	}
	return s
}

// GET /api/exploration/findings/{id}/export?format=md|docx — 发现页单条漏洞导出
// (id 与详情接口 /api/exploration/findings/{id} 同语义:findings 表行 id)。
// md 复用列表导出的渲染;docx 走任务报告同一套 python-docx 管线但 NoAI:正文
// 只用已持久化的 AI 富化(若有),复现过程优先结构化 reproduction,其余确定性
// 兜底——同步秒级返回,不调 LLM,也不写入报告管理列表。
func (s *Server) exportFinding(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "无效的 finding id")
		return
	}
	if !s.checkFindingScope(w, r, id) {
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "未找到漏洞")
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "md"
	}
	stem := exportFindingName(f.Name, f.VulnClass)
	disposition := func(ext, ctype string) {
		w.Header().Set("Content-Type", ctype)
		w.Header().Set(
			"Content-Disposition",
			fmt.Sprintf("attachment; filename=%q; filename*=UTF-8''%s", fmt.Sprintf("finding-%d%s", id, ext), url.PathEscape(stem+ext)),
		)
	}
	switch format {
	case "md":
		disposition(".md", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte(report.FindingsMarkdown([]*db.DBFinding{f}, time.Now())))
	case "docx":
		fi := report.FindingInput{
			Name: f.Name, VulnClass: f.VulnClass, Severity: f.Severity, Summary: f.Summary,
			PoC: f.Evidence, CreatedAt: f.CreatedAt, Reproduction: f.Reproduction,
			Status: f.Status, PageMarkdown: report.SanitizeForExport(f.Report),
		}
		// Target 用第一个绑定资产的展示 label(富化里 AI 提取的目标在 Enrichment 中优先)。
		if assets := s.resolveAssetIDs(f.AssetIDs); assets != nil && len(f.AssetIDs) > 0 {
			if a := assets[f.AssetIDs[0]]; a != nil {
				fi.Target = assetLabel(a)
			}
		}
		// 复用持久化富化(发现页「AI 分析」的成果),并尊重人工等级覆盖。
		if f.NodeID != nil {
			if enr, _ := s.m.pg.GetFindingEnrichment(*f.NodeID); enr != nil {
				fi.Enrichment = reportEnrichmentFromDB(enr)
				if strings.TrimSpace(enr.Severity) != "" {
					fi.Severity = enr.Severity
				}
			}
		}
		// 封面元数据沿用报告设置,与任务级报告一致。
		rs, _ := s.m.pg.GetReportSettings()
		var personnel []report.PersonInput
		companyName, cvss, logoRel := "", "", "3.1"
		if rs != nil {
			_ = json.Unmarshal(rs.Personnel, &personnel)
			companyName, cvss, logoRel = rs.CompanyName, defaultStrSrv(rs.CVSSVersion, "3.1"), rs.LogoPath
		}
		logoPath := ""
		if strings.TrimSpace(logoRel) != "" {
			logoPath = s.reportLogoPath(logoRel)
		}
		title := strings.TrimSpace(f.Name)
		if title == "" {
			title = strings.TrimSpace(f.VulnClass)
		}
		in := &report.GenInput{
			CompanyName: companyName, // empty → BuildDoc applies locale default
			ProjectName: title,
			ReportTitle: title,
			Locale:      "zh-CN",
			CVSSVersion: cvss,
			LogoPath:    logoPath,
			Personnel:   personnel,
			Findings:    []report.FindingInput{fi},
			SkillDir:    s.skillDir,
			DataDir:     s.dataDir,
			NoAI:        true,
			PageOnly:    true,
		}
		stage, err := os.MkdirTemp("", "4zrec-finding-docx-")
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		defer os.RemoveAll(stage)
		path, err := report.GenerateDocx(r.Context(), s.m.pg, in, stage, strconv.FormatInt(id, 10))
		if err != nil {
			writeErr(w, 500, "docx 生成失败:"+err.Error())
			return
		}
		file, err := os.Open(path)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		defer file.Close()
		disposition(".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		http.ServeContent(w, r, filepath.Base(path), time.Now(), file)
	case "pdf":
		target := ""
		if assets := s.resolveAssetIDs(f.AssetIDs); assets != nil && len(f.AssetIDs) > 0 {
			if a := assets[f.AssetIDs[0]]; a != nil {
				target = assetLabel(a)
			}
		}
		rows := []report.PDFTrafficRow{}
		if ft, terr := s.m.pg.GetFindingTraffic(r.Context(), id); terr == nil && ft != nil {
			for _, b := range ft.Bindings {
				rows = append(rows, report.PDFTrafficRow{
					Role: b.Role, Method: b.Snapshot.Method, URL: b.Snapshot.URL,
					Status: b.Snapshot.Status, RespLen: b.Snapshot.RespLen, Note: b.Note,
				})
			}
		}
		title := strings.TrimSpace(f.Name)
		if title == "" {
			title = strings.TrimSpace(f.VulnClass)
		}
		stage, err := os.MkdirTemp("", "4zrec-finding-pdf-")
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		defer os.RemoveAll(stage)
		path, err := report.GeneratePDF(r.Context(), &report.PDFInput{
			FindingID: id, Title: title, Severity: f.Severity, Status: f.Status,
			Target: target, FoundDate: f.CreatedAt.Format("2006-01-02"),
			Summary: f.Summary, Evidence: f.Evidence, Report: report.SanitizeForExport(f.Report),
			DataDir: s.dataDir, Traffic: rows, GeneratedAt: time.Now(),
		}, stage)
		if err != nil {
			writeErr(w, 500, "pdf 生成失败:"+err.Error())
			return
		}
		file, err := os.Open(path)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		defer file.Close()
		disposition(".pdf", "application/pdf")
		http.ServeContent(w, r, filepath.Base(path), time.Now(), file)
	default:
		writeErr(w, 400, "不支持的格式:"+format)
	}
}

// srcReportContext builds the business-context table and flow line for a
// consolidated SRC report from the findings' linked assets.
func (s *Server) srcReportContext(fs []*db.DBFinding) ([]report.SRCAsset, string) {
	resolved := s.resolveFindingAssets(fs)
	seen := map[string]bool{}
	var rows []report.SRCAsset
	storage, gateway, preview := false, false, false
	for _, f := range fs {
		for _, id := range f.AssetIDs {
			a := resolved[id]
			if a == nil {
				continue
			}
			label := srcAssetLabel(a)
			if label == "" || seen[label] {
				continue
			}
			seen[label] = true
			l := strings.ToLower(label)
			role := "关联资产"
			switch {
			case strings.Contains(l, "minio") || strings.Contains(l, "oss") || strings.Contains(l, "s3"):
				role = "对象存储"
				storage = true
			case strings.Contains(l, "api") || strings.Contains(l, "finance"):
				role = "业务 API 网关"
				gateway = true
			case strings.Contains(l, "preview") || strings.Contains(l, "info"):
				role = "预览/前端服务"
				preview = true
			case a.Type == "service":
				role = "业务服务"
			case a.Type == "domain" || a.Type == "root_domain":
				role = "业务域名"
			}
			rows = append(rows, report.SRCAsset{Label: label, Type: a.Type, Role: role})
		}
	}
	flow := ""
	switch {
	case storage && gateway && preview:
		flow = "业务前端/客户端 → 业务 API 网关（上传、预览等接口）→ 对象存储；预览接口跳转预览服务。"
	case storage && gateway:
		flow = "业务前端/客户端 → 业务 API 网关 → 对象存储。"
	}
	return rows, flow
}

func (s *Server) srcAssetTypes(fs []*db.DBFinding) map[int64]string {
	resolved := s.resolveFindingAssets(fs)
	out := map[int64]string{}
	for id, a := range resolved {
		if a != nil {
			out[id] = a.Type
		}
	}
	return out
}

func (s *Server) srcAssetLabels(fs []*db.DBFinding) map[int64]string {
	resolved := s.resolveFindingAssets(fs)
	out := map[int64]string{}
	for id, a := range resolved {
		if a != nil {
			out[id] = srcAssetLabel(a)
		}
	}
	return out
}

func srcAssetLabel(a *db.Asset) string {
	if a.Domain != "" {
		return a.Domain
	}
	if a.URL != "" {
		if u, err := url.Parse(a.URL); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return assetLabel(a)
}
