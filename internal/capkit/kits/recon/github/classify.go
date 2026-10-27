package github

import (
	"regexp"
	"strings"
)

var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"aws_access_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"aliyun_access_key", regexp.MustCompile(`\bLTAI[0-9A-Za-z]{12,}\b`)},
	{"tencent_secret_id", regexp.MustCompile(`\bAKID[0-9A-Za-z]{13,}\b`)},
	{"github_token", regexp.MustCompile(`\b(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{40,})\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
	{"private_key", regexp.MustCompile(`BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b`)},
	{"db_connection", regexp.MustCompile(`(?i)\b(postgres|mysql|mongodb|redis|amqp)://[^\s"']+`)},
}

var genericSecret = regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|token)\s*[:=]\s*["']?[^\s"']{6,}`)

// Classify returns the most specific secret type found in the fragments.
func Classify(fragments []string) string {
	joined := strings.Join(fragments, "\n")
	for _, p := range secretPatterns {
		if p.re.MatchString(joined) {
			return p.name
		}
	}
	if genericSecret.MatchString(joined) {
		return "generic_secret"
	}
	return "unknown"
}

var lowCredRepoMarkers = []string{
	"leaked", "leaks", "keys", "passwords", "secrets",
	"collection", "collections", "awesome", "tutorial", "tutorials", "cheatsheet",
}

var highValueFiles = []string{
	".env", "application.yml", "application.yaml", "application.properties",
	"config.py", "settings.py", "local.py", ".npmrc", ".netrc",
	"credentials", "secrets.json", "secrets.yml", "secrets.yaml", "id_rsa",
}

// Credibility is a lightweight static score for a code-search hit. It only
// produces a hint; the host/agent must validate before reporting.
type Credibility struct {
	Score int    `json:"score"`
	Level string `json:"level"` // high | medium | low
}

func ScoreCredibility(repo string, stars int, fork bool, path string) Credibility {
	score := 0
	repoLower := strings.ToLower(repo)
	for _, marker := range lowCredRepoMarkers {
		if strings.Contains(repoLower, marker) {
			score -= 2
			break
		}
	}
	if stars == 0 {
		score--
	}
	if fork {
		score--
	}
	pathLower := strings.ToLower(path)
	for _, marker := range highValueFiles {
		if strings.Contains(pathLower, marker) {
			score++
			break
		}
	}
	level := "medium"
	switch {
	case score >= 0:
		level = "high"
	case score <= -3:
		level = "low"
	}
	return Credibility{Score: score, Level: level}
}
