package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// OSCS (oscs1024.com) publishes open-source component advisories through a
// JSON API. The list endpoint is cheap but carries only a pointer (mps); the
// detail endpoint carries severity, CVE and description. A list entry whose
// detail cannot be read is dropped rather than stored half-populated.
const (
	oscsListURL   = "https://www.oscs1024.com/oscs/v1/intelligence/list"
	oscsDetailURL = "https://www.oscs1024.com/oscs/v1/vdb/info"
	oscsPageSize  = 20
	oscsDetailMax = 20 // bound the N+1 detail fan-out per poll
)

type oscsSource struct{ c *client }

func newOSCSSource(c *client) Source { return &oscsSource{c: c} }

func (s *oscsSource) Info() Info {
	return Info{
		Name:        "oscs",
		DisplayName: "OSCS 开源安全情报预警",
		Link:        "https://www.oscs1024.com/cm",
	}
}

func (s *oscsSource) Fetch(ctx context.Context, limit int) ([]core.IntelItem, error) {
	if limit <= 0 || limit > oscsDetailMax {
		limit = oscsDetailMax
	}
	raw, err := s.c.postJSON(ctx, oscsListURL, map[string]string{
		"Content-Type": "application/json",
		"Referer":      "https://www.oscs1024.com/cm",
		"Origin":       "https://www.oscs1024.com",
	}, map[string]any{"page": 1, "per_page": oscsPageSize})
	if err != nil {
		return nil, upstreamError("oscs", err)
	}
	var list oscsListResponse
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, upstreamError("oscs", err)
	}
	if list.Code != 200 || !list.Success {
		return nil, upstreamError("oscs", fmt.Errorf("上游返回 code=%d info=%s", list.Code, list.Info))
	}

	out := make([]core.IntelItem, 0, limit)
	for _, entry := range list.Data.Data {
		if len(out) >= limit {
			break
		}
		item, err := s.detail(ctx, entry.Mps)
		if err != nil {
			// One unreadable advisory must not sink the source.
			continue
		}
		var tags []string
		if entry.IsPush == 1 {
			tags = append(tags, "发布预警")
		}
		switch entry.IntelligenceType {
		case 1:
			tags = append(tags, "公开漏洞")
		case 2:
			tags = append(tags, "独家情报")
		case 3:
			tags = append(tags, "投毒情报")
		}
		item.Tags = append(item.Tags, tags...)
		out = append(out, item)
	}
	return out, nil
}

func (s *oscsSource) detail(ctx context.Context, vulnNo string) (core.IntelItem, error) {
	var item core.IntelItem
	if strings.TrimSpace(vulnNo) == "" {
		return item, fmt.Errorf("empty vuln_no")
	}
	raw, err := s.c.postJSON(ctx, oscsDetailURL, map[string]string{
		"Content-Type": "application/json",
		"Referer":      "https://www.oscs1024.com/cm",
		"Origin":       "https://www.oscs1024.com",
	}, map[string]any{"vuln_no": vulnNo})
	if err != nil {
		return item, err
	}
	var resp oscsDetailResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return item, err
	}
	if resp.Code != 200 || !resp.Success || len(resp.Data) == 0 {
		return item, fmt.Errorf("detail unavailable (code=%d)", resp.Code)
	}
	d := resp.Data[0]
	var refs []string
	for _, ref := range d.References {
		if ref.URL != "" {
			refs = append(refs, ref.URL)
		}
	}
	return core.IntelItem{
		Source:      s.Info().Name,
		UniqueKey:   uniqueKey(d.VulnNo, "oscs"),
		Title:       strings.TrimSpace(d.VulnTitle),
		Description: strings.TrimSpace(d.Description),
		Severity:    NormalizeSeverity(d.Level),
		CVE:         strings.TrimSpace(firstNonEmpty(d.CveID, d.VulnCveID)),
		Disclosure:  unixMilliDay(d.PublishTime),
		Solutions:   strings.Join(d.SolutionData, "\n"),
		SourceURL:   "https://www.oscs1024.com/hd/" + d.VulnNo,
		References:  refs,
	}, nil
}

func unixMilliDay(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).Format("2006-01-02")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

type oscsListResponse struct {
	Data struct {
		Total int `json:"total"`
		Data  []struct {
			Mps              string `json:"mps"`
			Url              string `json:"url"`
			IntelligenceType int    `json:"intelligence_type"`
			IsPush           int    `json:"is_push"`
		} `json:"data"`
	} `json:"data"`
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Info    string `json:"info"`
}

type oscsDetailResponse struct {
	Data []struct {
		VulnNo       string   `json:"vuln_no"`
		VulnTitle    string   `json:"vuln_title"`
		Description  string   `json:"description"`
		Level        string   `json:"level"`
		CveID        string   `json:"cve_id"`
		VulnCveID    string   `json:"vuln_cve_id"`
		PublishTime  int64    `json:"publish_time"`
		SolutionData []string `json:"soulution_data"`
		References   []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"data"`
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Info    string `json:"info"`
}
