package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capability/recon/fingerprint"
	"github.com/c1ayooo/4zrec/internal/orchestration/agent"
)

// targetFingerprintEvidence reads technologies recorded on HTTP assets for the
// given targets. The fingerprint_scan/enrich pipelines write these values; no
// evidence means the target was not actually recognized.
func (s *Server) targetFingerprintEvidence(targets []string) (map[string][]string, error) {
	if s == nil || s.m == nil {
		return nil, fmt.Errorf("资产库不可用，无法校验指纹证据")
	}
	as := s.m.Assets()
	if as == nil {
		return nil, fmt.Errorf("资产库不可用，无法校验指纹证据")
	}
	return as.TechnologiesForTargets(targets)
}

// requireTargetFingerprints is the hard gate for active scans: every target must
// already carry at least one technology from a real fingerprint match.
func (s *Server) requireTargetFingerprints(targets []string) (map[string][]string, error) {
	evidence, err := s.targetFingerprintEvidence(targets)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, target := range targets {
		if len(evidence[target]) == 0 {
			missing = append(missing, target)
		}
	}
	if len(missing) > 0 {
		return evidence, fmt.Errorf("拒绝无指纹识别的扫描：目标 %s 在资产库中没有 technologies 证据。请先调用 fingerprint_scan（或 enrich）完成识别后再扫描", strings.Join(missing, ", "))
	}
	return evidence, nil
}

// requireSearchFingerprint gates template/vuln-kb lookups. A caller must either
// pass already-recognized targets, or rely on recognition recorded for the
// current task/project. The query must be grounded in one of those technologies
// (CVE lookups are allowed once recognition exists).
func (s *Server) requireSearchFingerprint(ctx context.Context, projectID int64, targets []string, product, query string) ([]string, error) {
	product = strings.TrimSpace(product)
	query = strings.TrimSpace(query)
	if product == "" && query == "" {
		return nil, fmt.Errorf("必须提供已识别的 product 或 q，不能无识别浏览模板/漏洞库")
	}

	var techs []string
	if len(targets) > 0 {
		evidence, err := s.targetFingerprintEvidence(targets)
		if err != nil {
			return nil, err
		}
		var missing []string
		for _, target := range targets {
			if len(evidence[target]) == 0 {
				missing = append(missing, target)
			} else {
				techs = append(techs, evidence[target]...)
			}
		}
		if len(techs) == 0 {
			return nil, fmt.Errorf("拒绝无指纹识别的检索：目标 %s 在资产库中没有 technologies 证据。请先调用 fingerprint_scan（或 enrich）完成识别", strings.Join(missing, ", "))
		}
		techs = fingerprint.UniqueTechnologies(techs)
	} else {
		if s == nil || s.m == nil {
			return nil, fmt.Errorf("资产库不可用，无法校验指纹证据")
		}
		as := s.m.Assets()
		if as == nil {
			return nil, fmt.Errorf("资产库不可用，无法校验指纹证据")
		}
		ri := agent.RunInfoFrom(ctx)
		scopeTechs, err := as.TechnologiesForScope(ri.TaskID, projectID)
		if err != nil {
			return nil, fmt.Errorf("读取指纹证据失败: %w", err)
		}
		if len(scopeTechs) == 0 {
			return nil, fmt.Errorf("拒绝无指纹识别的检索：当前任务/项目没有 technologies 证据。请先调用 fingerprint_scan（或 enrich），或传入已识别的 targets")
		}
		techs = fingerprint.UniqueTechnologies(scopeTechs)
	}

	if product != "" && !fingerprint.QueryMatches(techs, product) {
		return nil, fmt.Errorf("产品「%s」不在已识别指纹中；当前已识别: %s", product, strings.Join(techs, ", "))
	}
	if product == "" && !fingerprint.QueryMatches(techs, query) && !strings.Contains(strings.ToUpper(query), "CVE-") {
		return nil, fmt.Errorf("关键词「%s」不在已识别指纹中；当前已识别: %s。请用识别出的产品名重试", query, strings.Join(techs, ", "))
	}
	return techs, nil
}
