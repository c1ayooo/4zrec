package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/vulnintel"
	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// pgListVulnIntel 分页列出情报流。severity 精确,q 模糊匹配标题/CVE/来源。
func (s *Server) pgListVulnIntel(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 0)
	size := atoiDefault(q.Get("size"), 50)
	entries, total, err := s.m.PG().ListVulnIntel(q.Get("q"), q.Get("severity"), page, size)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: "search", Source: "web", Status: "error",
			Query: q.Get("q"), Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 500, err.Error())
		return
	}
	if q.Get("q") != "" || q.Get("severity") != "" {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: "search", Source: "web",
			Query:      q.Get("q"),
			Summary:    fmt.Sprintf("情报流搜索命中 %d 条", total),
			Result:     featureJSON(map[string]any{"total": total, "severity": q.Get("severity")}),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
	}
	writeJSON(w, 200, map[string]any{"entries": entries, "total": total})
}

// pgGetVulnIntel 返回单条完整情报（统一漏洞库详情用）。
func (s *Server) pgGetVulnIntel(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	entry, err := s.m.PG().GetVulnIntel(id)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: "view", Source: "web", Status: "error",
			RefType: "vuln_intel", RefID: strconv.FormatInt(id, 10), Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 404, "not found")
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureVulnKB, Action: "view", Source: "web",
		RefType: "vuln_intel", RefID: strconv.FormatInt(id, 10),
		Summary:    fmt.Sprintf("查看漏洞情报「%s」", entry.Title),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, map[string]any{"entry": entry})
}

// pgVulnIntelRefresh 触发一次立即轮询(非阻塞,后台执行)。
func (s *Server) pgVulnIntelRefresh(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s.m.vulnIntel.Refresh()
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureVulnKB, Action: "refresh", Source: "web",
		Summary:    "触发漏洞情报刷新（后台执行）",
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// pgVulnIntelStatus 轮询状态(是否在跑、上次结果、源数量)。
func (s *Server) pgVulnIntelStatus(w http.ResponseWriter, _ *http.Request) {
	polling, last, res, sources := s.m.vulnIntel.Status()
	writeJSON(w, 200, map[string]any{
		"polling": polling,
		"last":    last.Format(time.RFC3339),
		"result":  res,
		"sources": sources,
	})
}

// pgVulnIntelPipeline 返回分析流水线的开关与进度(漏洞库页「流水线」tab)。
func (s *Server) pgVulnIntelPipeline(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"pipeline": s.m.vulnIntel.PipelineStatus()})
}

// pgVulnIntelPipelinePut 写入四个流水线开关(分析/中文化/自动模板/通知)。
// 都是 settings 键,分析 worker 每轮重新读取,改完即时生效。
func (s *Server) pgVulnIntelPipelinePut(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.putPipelineSettings(req); err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: "update", Source: "web", Status: "error",
			Summary: "更新情报流水线设置", Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 500, err.Error())
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureVulnKB, Action: "update", Source: "web",
		Summary:    "更新情报流水线设置",
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, map[string]any{"ok": true, "pipeline": s.m.vulnIntel.PipelineStatus()})
}

// pgVulnIntelAnalyze 对单条情报立即跑 AI 分析(后台执行,前端轮询详情)。
// 分析含一次 LLM 调用,可能耗时数十秒,因此不阻塞请求。
func (s *Server) pgVulnIntelAnalyze(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	entry, err := s.m.PG().GetVulnIntel(id)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureVulnKB, Action: "analyze", Source: "web",
		RefType: "vuln_intel", RefID: strconv.FormatInt(id, 10),
		Summary:    fmt.Sprintf("AI 分析漏洞情报「%s」", entry.Title),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	go func(id int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		defer cancel()
		if err := s.m.vulnIntel.AnalyzeIntel(ctx, id); err != nil {
			log.Printf("[vulnintel] 手动分析 %d 失败: %v", id, err)
		}
	}(id)
	writeJSON(w, 202, map[string]any{"ok": true})
}

// pgVulnIntelNuclei 把一条情报的模板草稿**确认入库**。自动分析只产草稿
// (vuln_intel_analysis.nuclei_tpl),这里才是人工确认后写进项目模板库的动作。
func (s *Server) pgVulnIntelNuclei(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	entry, err := s.m.PG().GetVulnIntel(id)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	tplID, err := s.m.vulnIntel.ConfirmTemplate(r.Context(), *entry)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: "create", Source: "web", Status: "error",
			RefType: "vuln_intel", RefID: strconv.FormatInt(id, 10),
			Summary: "确认 nuclei 模板入库", Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 500, err.Error())
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureVulnKB, Action: "create", Source: "web",
		RefType: "vuln_intel", RefID: strconv.FormatInt(id, 10),
		Summary:    fmt.Sprintf("确认 nuclei 模板入库 %s", tplID),
		Result:     featureJSON(map[string]any{"template_id": tplID}),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, map[string]any{"ok": true, "template_id": tplID})
}

// pgVulnIntelNucleiDraft 为单条情报生成模板**草稿**(不写模板库),供前端
// 预览与人工确认。
func (s *Server) pgVulnIntelNucleiDraft(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	entry, err := s.m.PG().GetVulnIntel(id)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	tplID, yamlText, err := s.m.vulnIntel.GenerateTemplateDraft(r.Context(), *entry)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "template_id": tplID, "yaml": yamlText})
}

// intelDraftOut 是待确认产物的对外结构:模板 YAML + 指纹规则 + 各自的
// 有效性判定(前端据此给"不可用,需重新生成"的提示)。
type intelDraftOut struct {
	db.IntelDraft
	NucleiUsable          bool   `json:"nuclei_usable"`
	NucleiIssue           string `json:"nuclei_issue,omitempty"`
	FingerprintName       string `json:"fingerprint_name,omitempty"`
	FingerprintCategory   string `json:"fingerprint_category,omitempty"`
	FingerprintExpression string `json:"fingerprint_expression,omitempty"`
	FingerprintUsable     bool   `json:"fingerprint_usable"`
	FingerprintIssue      string `json:"fingerprint_issue,omitempty"`
}

// pgVulnIntelDrafts 列出待人工确认的产物草稿(nuclei 模板 / 指纹规则)。
func (s *Server) pgVulnIntelDrafts(w http.ResponseWriter, r *http.Request) {
	drafts, err := s.m.PG().ListIntelDrafts(atoiDefault(r.URL.Query().Get("limit"), 50))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]intelDraftOut, 0, len(drafts))
	for _, d := range drafts {
		item := intelDraftOut{IntelDraft: d}
		if d.NucleiYAML != "" {
			if err := vulnintel.CheckNucleiTemplate(d.NucleiYAML); err != nil {
				item.NucleiIssue = err.Error()
			} else {
				item.NucleiUsable = true
			}
		}
		if d.Fingerprint != "" {
			fd, perr := vulnintel.ParseFingerprintDraft(d.Fingerprint)
			if perr != nil {
				item.FingerprintIssue = perr.Error()
			} else {
				item.FingerprintName = fd.Name
				item.FingerprintCategory = fd.Category
				item.FingerprintExpression = fd.Expression
				if verr := vulnintel.ValidateFingerprintExpression(fd.Expression); verr != nil {
					item.FingerprintIssue = verr.Error()
				} else {
					item.FingerprintUsable = true
				}
			}
		}
		out = append(out, item)
	}
	writeJSON(w, 200, map[string]any{"drafts": out})
}

// pgVulnIntelFingerprintDraft 为单条情报生成指纹规则**草稿**(不写指纹库),
// 供前端预览与人工确认。
func (s *Server) pgVulnIntelFingerprintDraft(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	entry, err := s.m.PG().GetVulnIntel(id)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	text, err := s.m.vulnIntel.GenerateFingerprintDraft(r.Context(), *entry)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: "analyze", Source: "web", Status: "error",
			RefType: "vuln_intel", RefID: strconv.FormatInt(id, 10),
			Summary: "生成指纹规则草稿", Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 500, err.Error())
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureVulnKB, Action: "analyze", Source: "web",
		RefType: "vuln_intel", RefID: strconv.FormatInt(id, 10),
		Summary:    "生成指纹规则草稿",
		Result:     featureJSON(map[string]any{"draft": text}),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, map[string]any{"ok": true, "draft": text})
}

// pgVulnIntelFingerprint 把一条情报的指纹草稿**确认入库**(写指纹规则库)。
func (s *Server) pgVulnIntelFingerprint(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	entry, err := s.m.PG().GetVulnIntel(id)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	ruleID, err := s.m.vulnIntel.ConfirmFingerprint(r.Context(), *entry)
	if err != nil {
		s.recordFeatureCall(r.Context(), db.FeatureCall{
			Feature: FeatureVulnKB, Action: "create", Source: "web", Status: "error",
			RefType: "vuln_intel", RefID: strconv.FormatInt(id, 10),
			Summary: "确认指纹规则入库", Error: err.Error(),
			DurationMS: int(time.Since(start).Milliseconds()),
		})
		writeErr(w, 500, err.Error())
		return
	}
	s.recordFeatureCall(r.Context(), db.FeatureCall{
		Feature: FeatureVulnKB, Action: "create", Source: "web",
		RefType: "vuln_intel", RefID: strconv.FormatInt(id, 10),
		Summary:    fmt.Sprintf("确认指纹规则入库 %s", ruleID),
		Result:     featureJSON(map[string]any{"rule_id": ruleID}),
		DurationMS: int(time.Since(start).Milliseconds()),
	})
	writeJSON(w, 200, map[string]any{"ok": true, "rule_id": ruleID})
}

// pgVulnIntelDiscardFingerprint 丢弃一条未入库的指纹草稿。
func (s *Server) pgVulnIntelDiscardFingerprint(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	if err := s.m.vulnIntel.DiscardFingerprint(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// pgVulnIntelDiscardDraft 丢弃一条未入库的模板草稿。
func (s *Server) pgVulnIntelDiscardDraft(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	if err := s.m.vulnIntel.DiscardTemplate(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
