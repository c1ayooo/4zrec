package server

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capability/recon/fingerprint"
	"github.com/c1ayooo/4zrec/internal/capability/vuln/nuclei"
	"github.com/c1ayooo/4zrec/internal/orchestration/agent"
)

const (
	// maxFingerprintScanTargets 限制一次指纹驱动扫描的目标数，避免误把大网段塞进来。
	maxFingerprintScanTargets = 200
	// maxFingerprintScanTemplates 限制显式传入的模板数。
	maxFingerprintScanTemplates = 50
	// maxAutoFingerprintTemplates 限制按产品/CVE 自动挑选的模板数。
	maxAutoFingerprintTemplates = 20
)

var cveShapeRE = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

// validateFingerprintScanInput 是 nuclei_scan 的模板级门禁：必须有识别依据，
// 禁止 automatic 和纯 tags/severity 的宽范围选择。
func validateFingerprintScanInput(basedOnProduct, basedOnCVE string, technologies []string, automatic bool, targetCount, explicitTemplateCount int) error {
	if automatic {
		return fmt.Errorf("指纹驱动流程禁用 automatic 全量扫描；请用 based_on_product 或 based_on_cve 加 templates")
	}
	if targetCount > maxFingerprintScanTargets {
		return fmt.Errorf("单次扫描目标数 %d 超过上限 %d", targetCount, maxFingerprintScanTargets)
	}
	if explicitTemplateCount > maxFingerprintScanTemplates {
		return fmt.Errorf("显式模板数 %d 超过上限 %d", explicitTemplateCount, maxFingerprintScanTemplates)
	}
	if basedOnProduct == "" && basedOnCVE == "" {
		return fmt.Errorf("必须提供 based_on_product 或 based_on_cve；禁止纯 tags/severity 宽范围扫描")
	}
	if basedOnCVE != "" && !cveShapeRE.MatchString(strings.TrimSpace(basedOnCVE)) {
		return fmt.Errorf("based_on_cve 格式不合法: %s", basedOnCVE)
	}
	if basedOnProduct != "" && !fingerprint.QueryMatches(technologies, basedOnProduct) {
		return fmt.Errorf("产品「%s」不在本次目标的已识别指纹中；当前已识别: %s", basedOnProduct, strings.Join(technologies, ", "))
	}
	return nil
}

// validateProductOnTargets 确保每个目标都识别出了指定产品，防止拿 A 目标的
// 指纹结果去扫 B 目标。
func validateProductOnTargets(evidence map[string][]string, product string) error {
	product = strings.TrimSpace(product)
	if product == "" {
		return nil
	}
	var missing []string
	for target, techs := range evidence {
		if !fingerprint.QueryMatches(techs, product) {
			missing = append(missing, target)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("以下目标没有识别出产品「%s」: %s；禁止用其他目标的识别结果扫它们", product, strings.Join(missing, ", "))
}

// fingerprintTechnologies 汇总本次目标命中的技术，去重排序。
func fingerprintTechnologies(evidence map[string][]string) []string {
	var all []string
	for _, techs := range evidence {
		all = append(all, techs...)
	}
	return fingerprint.UniqueTechnologies(all)
}

// selectFingerprintTemplates 只保留与识别结果（产品或 CVE）明确相关、且不
// 属于破坏性类别的模板。显式 templates 也走同一套校验，防止“识别了 A 却
// 拿 B 的模板乱扫”。
func selectFingerprintTemplates(
	idx *nuclei.Index,
	explicit []string,
	basedOnProduct, basedOnCVE string,
	technologies []string,
	filters nuclei.Filters,
	excludeTags []string,
	max int,
) ([]nuclei.TemplateMeta, error) {
	if max <= 0 {
		max = maxAutoFingerprintTemplates
	}
	if len(explicit) > maxFingerprintScanTemplates {
		return nil, fmt.Errorf("显式模板数 %d 超过上限 %d", len(explicit), maxFingerprintScanTemplates)
	}

	var candidates []nuclei.TemplateMeta
	if len(explicit) > 0 {
		for _, raw := range explicit {
			id := strings.TrimSpace(raw)
			if id == "" {
				continue
			}
			meta, ok := idx.Get(id)
			if !ok {
				return nil, fmt.Errorf("模板 ID 未找到: %s（请使用 nuclei_template_search 返回的 ID，不要传路径）", id)
			}
			candidates = append(candidates, meta)
		}
	} else {
		query := basedOnCVE
		if query == "" {
			query = basedOnProduct
		}
		found, _, err := idx.Search(query, filters, 200)
		if err != nil {
			return nil, err
		}
		candidates = found
	}

	out := make([]nuclei.TemplateMeta, 0, len(candidates))
	seen := map[string]bool{}
	for _, meta := range candidates {
		if seen[meta.ID] || isDestructiveTemplate(meta) || templateHasExcludedTag(meta, excludeTags) {
			continue
		}
		if !templateMatchesSelection(meta, basedOnProduct, basedOnCVE, technologies) {
			continue
		}
		seen[meta.ID] = true
		out = append(out, meta)
		if len(out) >= max {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有找到与识别结果相关的安全模板；不要扩大范围乱扫")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func templateMatchesSelection(meta nuclei.TemplateMeta, product, cve string, technologies []string) bool {
	if cve != "" {
		return templateMatchesCVE(meta, cve)
	}
	return templateMatchesProduct(meta, product, technologies)
}

func templateMatchesCVE(meta nuclei.TemplateMeta, cve string) bool {
	target := strings.ToUpper(strings.TrimSpace(cve))
	for _, c := range meta.CVE {
		if strings.EqualFold(strings.TrimSpace(c), target) {
			return true
		}
	}
	hay := strings.ToUpper(meta.ID + "\n" + meta.Name + "\n" + strings.Join(meta.Tags, " ") + "\n" + meta.Description)
	return strings.Contains(hay, target)
}

func templateMatchesProduct(meta nuclei.TemplateMeta, product string, technologies []string) bool {
	hay := strings.ToLower(meta.ID + "\n" + meta.Name + "\n" + strings.Join(meta.Tags, " ") +
		"\n" + strings.Join(meta.CVE, " ") + "\n" + meta.Description)
	terms := []string{product}
	for _, tech := range technologies {
		// 只把与目标产品相关的技术别名纳入匹配，避免目标上同时装了 Nginx
		// 就把所有提到 Nginx 的模板都放进来。
		if fingerprint.QueryMatches([]string{tech}, product) || fingerprint.QueryMatches([]string{product}, tech) {
			terms = append(terms, tech)
		}
	}
	for _, raw := range terms {
		term := strings.ToLower(strings.TrimSpace(raw))
		if term == "" {
			continue
		}
		if strings.Contains(hay, term) {
			return true
		}
	}
	return false
}

func isDestructiveTemplate(meta nuclei.TemplateMeta) bool {
	hay := strings.ToLower(meta.ID + " " + meta.Name + " " + strings.Join(meta.Tags, " "))
	for _, kw := range []string{
		"dos", "fuzz", "bruteforce", "brute-force", "default-login", "default_login",
		"file-upload", "file_upload", "webshell", "backdoor",
	} {
		if strings.Contains(hay, kw) {
			return true
		}
	}
	return false
}

func templateHasExcludedTag(meta nuclei.TemplateMeta, exclude []string) bool {
	for _, raw := range exclude {
		tag := strings.ToLower(strings.TrimSpace(raw))
		if tag == "" {
			continue
		}
		for _, got := range meta.Tags {
			if strings.ToLower(got) == tag {
				return true
			}
		}
	}
	return false
}

// refreshFingerprintToolSchemas 把三个安全相关工具的描述/schema 刷成代码默认，
// 因为 tools 表是首插入 only：旧库看不到新增的 based_on_*/product/target 参数。
// 一次性 flag 守卫，避免覆盖用户后续的编辑。
func (s *Server) refreshFingerprintToolSchemas() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	const flag = "fingerprint_tool_schema_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, name := range []string{"nuclei_scan", "fingerprint_verify", "nuclei_template_search"} {
		for _, t := range s.nucleiTools() {
			if t.Name() != name {
				continue
			}
			schema, _ := json.Marshal(t.InputSchema())
			if err := s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema); err != nil {
				log.Printf("[tools] refresh %s schema failed: %v", name, err)
			}
		}
	}
	for _, sd := range agent.BuiltinToolSeeds() {
		if sd.Key != "search_vuln_kb" {
			continue
		}
		schema, _ := json.Marshal(sd.Schema)
		if err := s.m.pg.RefreshToolDefaults(sd.Key, sd.Desc, schema); err != nil {
			log.Printf("[tools] refresh search_vuln_kb schema failed: %v", err)
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[tools] 已刷新 nuclei_scan/fingerprint_verify/nuclei_template_search/search_vuln_kb schema 到指纹门禁/POC 版本(一次性)")
}

// fingerprintPlanLine 是 nuclei_scan 输出和调用历史里的“为什么选这些模板”。
func fingerprintPlanLine(product, cve string, technologies, templates []string) string {
	parts := []string{}
	if product != "" {
		parts = append(parts, "product="+product)
	}
	if cve != "" {
		parts = append(parts, "cve="+cve)
	}
	if len(technologies) > 0 {
		parts = append(parts, "识别="+strings.Join(technologies, ", "))
	}
	shown := templates
	if len(shown) > 10 {
		shown = shown[:10]
	}
	line := fmt.Sprintf("基于指纹定向验证: %s; 选用模板 %d 个", strings.Join(parts, " "), len(templates))
	if len(shown) > 0 {
		line += ": " + strings.Join(shown, ", ")
		if len(templates) > len(shown) {
			line += " …"
		}
	}
	return line
}
