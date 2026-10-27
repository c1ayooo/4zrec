package server

import (
	"context"
	"fmt"
	"strings"

	capkit "github.com/c1ayooo/4zrec/internal/capkit/core"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/vulnintel/grab"
)

// avdIntelSource exposes the host's existing 阿里云漏洞库 grabber to capkit's
// poll loop.
//
// Why this is host-side rather than a capkit source: avd.aliyun.com answers
// every path — list, detail and the guessed API endpoints — with an obfuscated
// JavaScript page whose script computes a signed ?timestamp__NNNN= parameter.
// The real content never appears in the HTTP response, so reading it needs a
// JavaScript engine. The host already ships one (dop251/goja) and the working
// implementation, so the source stays here and capkit polls it through
// core.IntelSource; the library keeps its dependency surface, and the
// advisory still lands in the same table through the same dedup key.
type avdIntelSource struct{ g grab.Grabber }

func newAVDIntelSource() capkit.IntelSource {
	return &avdIntelSource{g: grab.NewAVDCrawler()}
}

func (s *avdIntelSource) Name() string { return "aliyun-avd" }

func (s *avdIntelSource) Fetch(ctx context.Context, limit int) ([]capkit.IntelItem, error) {
	if s == nil || s.g == nil {
		return nil, capkit.Unavailable("AVD 抓取器未初始化")
	}
	// GetUpdate takes a page count, not an item count. One page is ~30
	// advisories and costs one list request plus one request per detail, so
	// asking for more than one page per poll multiplies the detail fan-out
	// without adding much (the list is newest-first).
	pages := 1
	infos, err := s.g.GetUpdate(ctx, pages)
	if err != nil {
		return nil, fmt.Errorf("AVD 抓取失败: %w", err)
	}
	out := make([]capkit.IntelItem, 0, len(infos))
	for _, v := range infos {
		if v == nil || strings.TrimSpace(v.Title) == "" {
			continue
		}
		item := capkit.IntelItem{
			Source:      s.Name(),
			UniqueKey:   avdUniqueKey(v),
			Title:       strings.TrimSpace(v.Title),
			Description: strings.TrimSpace(v.Description),
			Severity:    strings.TrimSpace(string(v.Severity)),
			CVE:         strings.TrimSpace(v.CVE),
			Disclosure:  strings.TrimSpace(v.Disclosure),
			Solutions:   strings.TrimSpace(v.Solutions),
			SourceURL:   avdSourceURL(v),
			Tags:        v.Tags,
			References:  v.References,
		}
		if limit > 0 && len(out) >= limit {
			break
		}
		out = append(out, item)
	}
	return out, nil
}

// avdUniqueKey keeps the corpus's existing key shape. Existing rows use the
// source-local AVD id with the "_aliyun-avd" suffix; reusing anything else
// would file every advisory under a new row on the first switched poll.
func avdUniqueKey(v *grab.VulnInfo) string {
	key := strings.TrimSpace(v.UniqueKey)
	if key == "" {
		// Older items may carry only the CVE. The suffix keeps it distinct
		// from the same CVE collected from another source.
		key = strings.TrimSpace(v.CVE)
	}
	if key == "" {
		return ""
	}
	if strings.HasSuffix(key, "_aliyun-avd") {
		return key
	}
	return key + "_aliyun-avd"
}

// avdSourceURL prefers the advisory's own link. VulnInfo.From is documented as
// the provider link plus the id for this grabber, so it is the best available
// detail URL without another request.
func avdSourceURL(v *grab.VulnInfo) string {
	if u := strings.TrimSpace(v.From); u != "" && strings.HasPrefix(u, "http") {
		return u
	}
	return "https://avd.aliyun.com/detail?id=" + strings.TrimSpace(v.UniqueKey)
}

var _ capkit.IntelSource = (*avdIntelSource)(nil)
