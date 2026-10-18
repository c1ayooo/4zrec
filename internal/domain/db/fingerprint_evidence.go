package db

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// TechnologiesForTargets returns the technologies recorded on HTTP assets that
// match each target's host and port. Keys are the exact input target strings;
// targets with no matching asset (or no technologies) are absent.
//
// Matching is deliberately conservative: an explicit port must match exactly.
// A target without an explicit port may fall back to any asset on that host,
// because http/https fingerprinting often records the default port only.
func (s *AssetStore) TechnologiesForTargets(targets []string) (map[string][]string, error) {
	type targetInfo struct {
		raw          string
		host         string
		port         int
		explicitPort bool
	}
	infos := make([]targetInfo, 0, len(targets))
	hostSet := map[string]bool{}
	var hosts []string
	for _, raw := range targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		candidate := raw
		if !strings.Contains(candidate, "://") {
			candidate = "http://" + candidate
		}
		u, err := url.Parse(candidate)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		port := 0
		explicitPort := u.Port() != ""
		if explicitPort {
			if _, err := fmt.Sscanf(u.Port(), "%d", &port); err != nil {
				port = 0
			}
		}
		if port == 0 {
			if strings.EqualFold(u.Scheme, "https") {
				port = 443
			} else {
				port = 80
			}
		}
		infos = append(infos, targetInfo{raw: raw, host: host, port: port, explicitPort: explicitPort})
		if !hostSet[host] {
			hostSet[host] = true
			hosts = append(hosts, host)
		}
	}
	out := map[string][]string{}
	if len(hosts) == 0 {
		return out, nil
	}

	rows, err := s.db.Query(`
SELECT domain, port, array_to_json(technologies)::text
FROM assets
WHERE type = 'service' AND service_type = 'http'
  AND domain = ANY($1)
  AND cardinality(technologies) > 0`, hosts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byHostPort := map[string][]string{}
	byHost := map[string][]string{}
	for rows.Next() {
		var domain string
		var port int
		var raw []byte
		if err := rows.Scan(&domain, &port, &raw); err != nil {
			return nil, err
		}
		var techs []string
		if err := json.Unmarshal(raw, &techs); err != nil || len(techs) == 0 {
			continue
		}
		host := strings.ToLower(domain)
		key := fmt.Sprintf("%s:%d", host, port)
		byHostPort[key] = mergeTechStrings(byHostPort[key], techs)
		byHost[host] = mergeTechStrings(byHost[host], techs)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, info := range infos {
		key := fmt.Sprintf("%s:%d", info.host, info.port)
		techs := byHostPort[key]
		if len(techs) == 0 && !info.explicitPort {
			techs = byHost[info.host]
		}
		if len(techs) > 0 {
			out[info.raw] = techs
		}
	}
	return out, nil
}

// TechnologiesForScope returns distinct technologies recorded on HTTP assets
// linked to the task or project. Both IDs zero means no scope and no evidence.
func (s *AssetStore) TechnologiesForScope(taskID, projectID int64) ([]string, error) {
	if taskID <= 0 && projectID <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`
SELECT DISTINCT unnest(technologies) AS tech
FROM assets
WHERE type = 'service' AND service_type = 'http'
  AND cardinality(technologies) > 0
  AND (($1 > 0 AND $1 = ANY(task_ids)) OR ($2 > 0 AND project_id = $2))
ORDER BY tech`, taskID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var tech string
		if err := rows.Scan(&tech); err != nil {
			return nil, err
		}
		if strings.TrimSpace(tech) != "" {
			out = append(out, tech)
		}
	}
	return out, rows.Err()
}

func mergeTechStrings(dst, src []string) []string {
	seen := make(map[string]bool, len(dst)+len(src))
	out := make([]string, 0, len(dst)+len(src))
	for _, list := range [][]string{dst, src} {
		for _, raw := range list {
			tech := strings.TrimSpace(raw)
			if tech == "" || seen[tech] {
				continue
			}
			seen[tech] = true
			out = append(out, tech)
		}
	}
	sort.Strings(out)
	return out
}
