package intel

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Severity levels, normalized to English. Sources publish Chinese ("严重")
// or English ("critical") labels; the kit maps both onto this scale so the
// host never has to special-case a source.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityUnknown  = "unknown"
)

// severityRank maps a severity label onto a comparable rank. Both English and
// Chinese labels are accepted: sources are not consistent about which they
// publish, and a mis-mapped severity silently drops advisories.
var severityRank = map[string]int{
	"critical": 4, "严重": 4, "极危": 4,
	"high": 3, "高危": 3, "高风险": 3,
	"medium": 2, "中危": 2, "中风险": 2, "中等": 2,
	"low": 1, "低危": 1, "低风险": 1, "低": 1,
}

// SeverityRank returns the comparable rank of a severity label (0 = unknown).
func SeverityRank(severity string) int {
	return severityRank[strings.ToLower(strings.TrimSpace(severity))]
}

// NormalizeSeverity maps a source severity label onto the kit's scale.
// Unrecognized labels become "unknown" rather than being guessed.
//
// The Chinese forms are deliberately generous about the "-风险" suffix: the
// threat-intel feeds write 高风险/中风险/低风险 while vendor advisory feeds
// write 高危/中危/低危, and treating the first set as unknown would silently
// drop every advisory from those sources out of the severity gate.
func NormalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "严重", "极危":
		return SeverityCritical
	case "high", "高危", "高风险":
		return SeverityHigh
	case "medium", "中危", "中风险", "中等":
		return SeverityMedium
	case "low", "低危", "低风险", "低":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// Info describes one intel source. Name is the stable slug used by tools and
// settings; DisplayName is what a human sees.
type Info struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Link        string `json:"link,omitempty"`
}

// Source is one public vulnerability-intel source.
//
// Fetch returns the most recent advisories, newest first, capped at limit.
// A source that fails returns an error: the poller isolates it and keeps the
// other sources running. Sources must not invent advisories — an advisory
// that cannot be parsed is dropped, not guessed at.
type Source interface {
	Info() Info
	Fetch(ctx context.Context, limit int) ([]core.IntelItem, error)
}

// ContainsHan reports whether s contains a Chinese character. Several sources
// publish bilingual feeds; the Chinese title is the one worth keeping.
func ContainsHan(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// uniqueKey builds the per-source dedup key: "<key>_<source>".
//
// The order matters and is not cosmetic: 4zrec's existing corpus uses the
// source-local id first and the source suffix last ("CVE-2021-44228_KEV",
// "CT-2026-86467_chaitin"), and the host converts these keys into a unique
// constraint. Emitting "chaitin_CT-..." instead would file every advisory under
// a new row on the first poll after a switch.
//
// Every source calls it as uniqueKey(id, sourceSlug); the parameters are named
// to make that the obvious order.
func uniqueKey(key, source string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	return key + "_" + source
}

// errUpstream is the kit's internal marker for a failed upstream call.
var errUpstream = core.NewError(core.CodeUpstreamError, "upstream request failed")

// upstreamError wraps a fetch failure with the source name attached.
func upstreamError(source string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", source, err)
}
