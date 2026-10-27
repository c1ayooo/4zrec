package toolparse

import (
	"encoding/json"
	"strings"
)

// nucleiParser parses nuclei -jsonl/-json output.
// A match with matcher-status=false is a non-match (tech-detect negative) and
// is filtered out. Deduplication is per template ID.
type nucleiParser struct{}

type nucleiMatch struct {
	TemplateID   string
	TemplateName string
	Severity     string
	MatchedAt    string
	Host         string
	IP           string
	Extracted    []string
}

func (nucleiParser) Tools() []string { return []string{"nuclei"} }

func (nucleiParser) Match(tool string, argv []string) bool {
	return tool == "nuclei" && (hasFlag(argv, "-jsonl") || hasFlag(argv, "-json") || hasFlag(argv, "-j"))
}

func (p nucleiParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	matches := parseNucleiJSONL(stdout)
	res := &Result{Tool: "nuclei", OK: true, Fields: map[string]any{}, RawRef: rawRef, Facts: make([]FactCandidate, 0, len(matches))}
	for _, m := range matches {
		host := Sluggify(m.Host)
		if host == "" && m.IP != "" {
			host = Sluggify(m.IP)
		}
		if host == "" {
			continue
		}
		key := "finding/" + strings.ToLower(m.TemplateID) + "-" + host
		if port := portOf(m.MatchedAt); port != "" {
			key += "-" + port
		}
		res.Facts = append(res.Facts, FactCandidate{
			FactKey:    key,
			Category:   "finding",
			Summary:    "nuclei 模板命中 [" + m.Severity + "] " + m.TemplateName + " @ " + m.Host,
			Body:       "Template: " + m.TemplateID + "｜Severity: " + m.Severity + "｜Matched: " + m.MatchedAt + "｜Evidence: " + strings.Join(m.Extracted, ", "),
			Confidence: "tentative",
			Links:      []FactLink{{From: "target/" + host, Type: "discovered_on"}},
		})
	}
	res.Fields["matches"] = len(matches)
	return res, nil
}

func parseNucleiJSONL(stdout string) []nucleiMatch {
	var out []nucleiMatch
	seen := map[string]bool{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var payload struct {
			TemplateID    string `json:"template-id"`
			MatchedAt     string `json:"matched-at"`
			Host          string `json:"host"`
			IP            string `json:"ip"`
			MatcherStatus bool   `json:"matcher-status"`
			Info          struct {
				Severity string `json:"severity"`
				Name     string `json:"name"`
			} `json:"info"`
			ExtractedResults []string `json:"extracted-results"`
		}
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			continue
		}
		if !payload.MatcherStatus || payload.TemplateID == "" || seen[payload.TemplateID] {
			continue
		}
		seen[payload.TemplateID] = true
		out = append(out, nucleiMatch{
			TemplateID: payload.TemplateID, TemplateName: payload.Info.Name,
			Severity:  strings.ToLower(payload.Info.Severity),
			MatchedAt: payload.MatchedAt, Host: payload.Host, IP: payload.IP,
			Extracted: payload.ExtractedResults,
		})
	}
	return out
}

func portOf(matchedAt string) string {
	s := strings.TrimSpace(matchedAt)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	idx := strings.LastIndexByte(s, ':')
	if idx < 0 || idx == len(s)-1 {
		return ""
	}
	port := s[idx+1:]
	for _, r := range port {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return port
}
