package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	capkit "github.com/c1ayooo/4zrec/internal/capkit/core"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// capkitIntelStore adapts the host's vuln_intel table to capkit's IntelStore
// port. Schema, dedup key and severity vocabulary stay here: the kit only
// knows it hands the host normalized advisories.
type capkitIntelStore struct{ pg *db.DB }

func (s capkitIntelStore) Upsert(ctx context.Context, item capkit.IntelItem) (string, bool, error) {
	tags, err := marshalJSONList(item.Tags)
	if err != nil {
		return "", false, err
	}
	refs, err := marshalJSONList(item.References)
	if err != nil {
		return "", false, err
	}
	id, created, err := s.pg.UpsertVulnIntelID(db.VulnIntel{
		UniqueKey:   item.UniqueKey,
		Title:       item.Title,
		Description: item.Description,
		Severity:    item.Severity,
		CVE:         item.CVE,
		Disclosure:  item.Disclosure,
		Solutions:   item.Solutions,
		Source:      item.Source,
		SourceURL:   item.SourceURL,
		Tags:        tags,
		Refs:        refs,
	})
	if err != nil {
		return "", false, err
	}
	return strconv.FormatInt(id, 10), created, nil
}

func (s capkitIntelStore) Query(ctx context.Context, q capkit.IntelQuery) ([]capkit.IntelItem, error) {
	// The host's list query pages by (page,size) and returns a total; the port
	// wants a flat list, so the limit maps onto one page of that size.
	size := q.Limit
	if size <= 0 {
		size = 20
	}
	// The text filter covers title/CVE/source; a CVE-specific query narrows it
	// further without relying on the text matcher's exact semantics.
	text := q.Text
	if strings.TrimSpace(q.CVE) != "" && text == "" {
		text = q.CVE
	}
	enriched, _, err := s.pg.ListVulnIntel(text, q.Severity, 0, size)
	if err != nil {
		return nil, err
	}
	out := make([]capkit.IntelItem, 0, len(enriched))
	for _, e := range enriched {
		if q.CVE != "" && !strings.EqualFold(e.CVE, q.CVE) {
			continue
		}
		if q.Source != "" && !strings.EqualFold(e.Source, q.Source) {
			continue
		}
		out = append(out, intelItemFromEnriched(e))
	}
	return out, nil
}

func (s capkitIntelStore) Get(ctx context.Context, id string) (*capkit.IntelItem, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(id), 10, 64)
	if err != nil {
		return nil, capkit.InvalidInput("intel id 必须是数字: " + id)
	}
	e, err := s.pg.GetVulnIntel(n)
	if err != nil {
		return nil, capkit.NotFound("漏洞情报不存在: " + id)
	}
	item := intelItemFromEnriched(*e)
	return &item, nil
}

func intelItemFromEnriched(e db.EnrichedVulnIntel) capkit.IntelItem {
	return capkit.IntelItem{
		ID:          strconv.FormatInt(e.ID, 10),
		Source:      e.Source,
		UniqueKey:   e.UniqueKey,
		Title:       firstNonEmptyStr(e.TitleZh, e.Title),
		Description: e.Description,
		Severity:    e.Severity,
		CVE:         e.CVE,
		Disclosure:  e.Disclosure,
		Solutions:   e.Solutions,
		SourceURL:   e.SourceURL,
		Tags:        parseJSONList(e.Tags),
		References:  parseJSONList(e.Refs),
	}
}

// marshalJSONList renders a string slice for the host's JSONB-as-TEXT columns.
func marshalJSONList(in []string) (string, error) {
	if in == nil {
		return "[]", nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseJSONList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
