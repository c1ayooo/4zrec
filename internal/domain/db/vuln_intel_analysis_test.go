package db

import (
	"fmt"
	"testing"
	"time"
)

// TestVulnIntelAnalysisRoundTrip 覆盖情报分析旁表与阶段位的读写契约:整行 upsert、
// 「只补缺」语义、阶段时间戳、错误清除、以及待分析筛选。需要真库(未配置则跳过)。
func TestVulnIntelAnalysisRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	key := fmt.Sprintf("db-test:analysis:%d", time.Now().UnixNano())
	inserted, err := d.UpsertVulnIntel(VulnIntel{
		UniqueKey:   key,
		Title:       "Apache Struts2 RCE (CVE-2024-53677)",
		Description: "Remote code execution via OGNL injection in file upload.",
		Severity:    "严重",
		CVE:         "CVE-2024-53677",
		Source:      "测试源",
		Tags:        `["Struts2"]`,
		Refs:        `[]`,
	})
	if err != nil {
		t.Fatalf("upsert vuln_intel: %v", err)
	}
	if !inserted {
		t.Fatalf("首次写入应返回 inserted=true")
	}
	var id int64
	if err := d.QueryRow(`SELECT id FROM vuln_intel WHERE unique_key=$1`, key).Scan(&id); err != nil {
		t.Fatalf("查 id: %v", err)
	}
	defer func() { _, _ = d.Exec(`DELETE FROM vuln_intel WHERE id=$1`, id) }()

	// 未分析时:详情不报错,analysis 为空;并出现在待分析列表里。
	entry, err := d.GetVulnIntel(id)
	if err != nil {
		t.Fatalf("GetVulnIntel(未分析): %v", err)
	}
	if entry.Analysis != nil {
		t.Fatalf("未分析时 analysis 应为 nil,得到 %+v", entry.Analysis)
	}
	if entry.AnalyzedAt != nil {
		t.Fatalf("未分析时 analyzed_at 应为空")
	}
	pending, err := d.PendingIntelAnalysis(50)
	if err != nil {
		t.Fatalf("PendingIntelAnalysis: %v", err)
	}
	if !containsIntel(pending, id) {
		t.Fatalf("新入库情报应出现在待分析列表")
	}

	// 阶段一:分析。principle / PoC 落旁表,analyzed_at 置位。
	if err := d.SaveIntelAnalysisStage(VulnIntelAnalysisStage{
		VulnIntelID:   id,
		TitleZh:       "Apache Struts2 文件上传远程代码执行漏洞",
		DescriptionZh: "攻击者可通过构造 OGNL 表达式在目标上执行任意代码。",
		Principle:     "文件上传参数未做白名单校验,OGNL 表达式被求值。",
		AttackScope:   "Struts 2.0.0 - 2.3.37",
		PocCode:       "import requests\nprint(requests.get('http://x'))",
		PocLang:       "python",
		PocOrigin:     "ai",
		Model:         "test-model",
		Analyzed:      true,
	}); err != nil {
		t.Fatalf("SaveIntelAnalysisStage(analyze): %v", err)
	}
	a, err := d.GetIntelAnalysis(id)
	if err != nil {
		t.Fatalf("GetIntelAnalysis: %v", err)
	}
	if a.Principle == "" || a.PocCode == "" || a.PocOrigin != "ai" || a.Model != "test-model" {
		t.Fatalf("分析产物不完整: %+v", a)
	}
	entry, err = d.GetVulnIntel(id)
	if err != nil {
		t.Fatalf("GetVulnIntel(已分析): %v", err)
	}
	if entry.TitleZh == "" || entry.AnalyzedAt == nil {
		t.Fatalf("主表阶段位未置位: title_zh=%q analyzed_at=%v", entry.TitleZh, entry.AnalyzedAt)
	}
	if entry.Analysis == nil || entry.Analysis.Principle == "" {
		t.Fatalf("详情应携带 analysis 旁表内容")
	}

	// 阶段二:只写中文化。已落库的 principle 不能被空值覆盖(只补缺语义)。
	if err := d.SaveIntelAnalysisStage(VulnIntelAnalysisStage{
		VulnIntelID: id,
		Localized:   true,
	}); err != nil {
		t.Fatalf("SaveIntelAnalysisStage(localize): %v", err)
	}
	a2, err := d.GetIntelAnalysis(id)
	if err != nil {
		t.Fatalf("GetIntelAnalysis(第二阶段): %v", err)
	}
	if a2.Principle != a.Principle || a2.PocCode != a.PocCode {
		t.Fatalf("第二阶段不该清掉已分析产物: %+v", a2)
	}
	entry, _ = d.GetVulnIntel(id)
	if entry.LocalizedAt == nil {
		t.Fatalf("localized_at 未置位")
	}

	// 阶段三:模板化。
	if err := d.SaveIntelAnalysisStage(VulnIntelAnalysisStage{
		VulnIntelID:    id,
		NucleiTemplate: "id: 4zrec-cve-2024-53677\n",
		Templated:      true,
	}); err != nil {
		t.Fatalf("SaveIntelAnalysisStage(template): %v", err)
	}
	entry, _ = d.GetVulnIntel(id)
	if entry.NucleiTplAt == nil || entry.Analysis == nil || entry.Analysis.NucleiTemplate == "" {
		t.Fatalf("模板阶段未落库: tpl_at=%v", entry.NucleiTplAt)
	}

	// 失败重试契约:刚分析完的条目不该马上重试;但一旦分析产物过期(7 天后
	// 的重富化失败),它必须重新进入待分析队列,否则失败就无法自愈。
	if err := d.SetIntelAnalysisError(id, "模型超时"); err != nil {
		t.Fatalf("SetIntelAnalysisError: %v", err)
	}
	entry, _ = d.GetVulnIntel(id)
	if entry.AnalysisError != "模型超时" {
		t.Fatalf("analysis_error 未写入: %q", entry.AnalysisError)
	}
	if containsIntel(mustPending(t, d), id) {
		t.Fatalf("刚分析完的行不该立即重试")
	}
	if _, err := d.Exec(`UPDATE vuln_intel SET analyzed_at = now() - interval '30 days' WHERE id=$1`, id); err != nil {
		t.Fatalf("拨旧 analyzed_at: %v", err)
	}
	if !containsIntel(mustPending(t, d), id) {
		t.Fatalf("分析产物过期且上次失败的条目必须重新进入待分析队列")
	}
	if err := d.SaveIntelAnalysisStage(VulnIntelAnalysisStage{VulnIntelID: id, Analyzed: true}); err != nil {
		t.Fatalf("SaveIntelAnalysisStage(重试): %v", err)
	}
	entry, _ = d.GetVulnIntel(id)
	if entry.AnalysisError != "" {
		t.Fatalf("成功阶段应清除 analysis_error,得到 %q", entry.AnalysisError)
	}
}

// TestPendingIntelAnalysisGate 锁定「内容够不够分析」的门槛:裸 CVE 列表项
// (无描述、标题就是编号)不该进分析队列,否则每轮白烧 LLM 调用。
func TestPendingIntelAnalysisGate(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	stamp := time.Now().UnixNano()
	bareKey := fmt.Sprintf("db-test:gate:bare:%d", stamp)
	goodKey := fmt.Sprintf("db-test:gate:good:%d", stamp)
	defer func() {
		_, _ = d.Exec(`DELETE FROM vuln_intel WHERE unique_key = ANY($1)`, []string{bareKey, goodKey})
	}()

	for _, v := range []VulnIntel{
		// 裸条目:只有编号 + 等级,无描述。
		{UniqueKey: bareKey, Title: "CVE-2026-99999", CVE: "CVE-2026-99999", Severity: "高危", Tags: "[]", Refs: "[]"},
		// 有实质描述:应进分析队列。
		{UniqueKey: goodKey, Title: "CVE-2026-88888", CVE: "CVE-2026-88888",
			Description: "该漏洞允许未授权攻击者通过构造恶意请求在目标服务器上执行任意代码。",
			Severity:    "高危", Tags: "[]", Refs: "[]"},
		// 标题本身信息量足够(产品+组件+类型),无描述也应可分析。
	} {
		if _, err := d.UpsertVulnIntel(v); err != nil {
			t.Fatalf("upsert %s: %v", v.UniqueKey, err)
		}
	}
	// 长标题无描述的样本。
	longTitleKey := fmt.Sprintf("db-test:gate:longtitle:%d", stamp)
	if _, err := d.UpsertVulnIntel(VulnIntel{
		UniqueKey: longTitleKey,
		Title:     "NGINX Plus 与 NGINX Open Source ngx_http_core_module 远程代码执行漏洞",
		Severity:  "高危", Tags: "[]", Refs: "[]",
	}); err != nil {
		t.Fatalf("upsert long title: %v", err)
	}
	defer func() { _, _ = d.Exec(`DELETE FROM vuln_intel WHERE unique_key=$1`, longTitleKey) }()

	idOf := func(key string) int64 {
		var id int64
		if err := d.QueryRow(`SELECT id FROM vuln_intel WHERE unique_key=$1`, key).Scan(&id); err != nil {
			t.Fatalf("查 id %s: %v", key, err)
		}
		return id
	}
	bareID, goodID, longID := idOf(bareKey), idOf(goodKey), idOf(longTitleKey)
	pending := mustPending(t, d)

	if containsIntel(pending, bareID) {
		t.Fatalf("裸 CVE 条目不该进分析队列")
	}
	if !containsIntel(pending, goodID) {
		t.Fatalf("有描述的情报应进分析队列")
	}
	if !containsIntel(pending, longID) {
		t.Fatalf("长标题情报应进分析队列")
	}
}

// TestVulnIntelAnalysisCounts 校验待分析/已分析计数接口不报错且单调。
func TestVulnIntelAnalysisCounts(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	if _, err := d.IntelAnalysisPendingCount(); err != nil {
		t.Fatalf("IntelAnalysisPendingCount: %v", err)
	}
	if _, err := d.IntelAnalyzedCount(); err != nil {
		t.Fatalf("IntelAnalyzedCount: %v", err)
	}
}

func containsIntel(list []EnrichedVulnIntel, id int64) bool {
	for _, v := range list {
		if v.ID == id {
			return true
		}
	}
	return false
}

func mustPending(t *testing.T, d *DB) []EnrichedVulnIntel {
	t.Helper()
	p, err := d.PendingIntelAnalysis(50)
	if err != nil {
		t.Fatalf("PendingIntelAnalysis: %v", err)
	}
	return p
}
