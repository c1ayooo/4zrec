package intel

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// kevCatalogURL is the CISA Known Exploited Vulnerabilities full feed. It is
// a static JSON document (no paging, no auth, no rate limit), which is why it
// is a good default source: a deployment with no other config still gets
// advisories that are confirmed exploited in the wild.
const kevCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type kevSource struct{ c *client }

func newKEVSource(c *client) Source { return &kevSource{c: c} }

func (s *kevSource) Info() Info {
	return Info{
		Name:        "kev",
		DisplayName: "CISA Known Exploited Vulnerabilities",
		Link:        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
	}
}

func (s *kevSource) Fetch(ctx context.Context, limit int) ([]core.IntelItem, error) {
	raw, err := s.c.get(ctx, kevCatalogURL, map[string]string{
		"Accept":  "application/json",
		"Referer": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
	})
	if err != nil {
		return nil, upstreamError("kev", err)
	}
	var feed kevFeed
	if err := json.Unmarshal(raw, &feed); err != nil {
		return nil, upstreamError("kev", err)
	}
	// The feed is the whole catalog: newest first is the only useful order.
	sort.SliceStable(feed.Vulnerabilities, func(i, j int) bool {
		return feed.Vulnerabilities[i].DateAdded > feed.Vulnerabilities[j].DateAdded
	})
	if limit <= 0 {
		limit = 20
	}
	out := make([]core.IntelItem, 0, limit)
	for _, v := range feed.Vulnerabilities {
		if v.CveID == "" {
			continue
		}
		var refs []string
		for _, note := range strings.Split(v.Notes, ";") {
			if note = strings.TrimSpace(note); note != "" {
				refs = append(refs, note)
			}
		}
		tags := []string{"known-exploited"}
		if v.VendorProject != "" {
			tags = append(tags, strings.TrimSpace(v.VendorProject))
		}
		if v.Product != "" {
			tags = append(tags, strings.TrimSpace(v.Product))
		}
		out = append(out, core.IntelItem{
			Source:      s.Info().Name,
			UniqueKey:   uniqueKey(v.CveID, "KEV"),
			Title:       strings.TrimSpace(v.VulnerabilityName),
			Description: strings.TrimSpace(v.ShortDescription),
			// KEV has no severity field. Presence in the catalog means the
			// vulnerability is exploited in the wild, which is critical by
			// definition; grading it lower would hide the one signal the
			// feed actually carries.
			Severity:   SeverityCritical,
			CVE:        strings.TrimSpace(v.CveID),
			Disclosure: strings.TrimSpace(v.DateAdded),
			Solutions:  strings.TrimSpace(v.RequiredAction),
			SourceURL:  "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
			Tags:       tags,
			References: refs,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

type kevFeed struct {
	Title           string    `json:"title"`
	CatalogVersion  string    `json:"catalogVersion"`
	DateReleased    time.Time `json:"dateReleased"`
	Count           int       `json:"count"`
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		ShortDescription           string `json:"shortDescription"`
		RequiredAction             string `json:"requiredAction"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		Notes                      string `json:"notes"`
	} `json:"vulnerabilities"`
}
