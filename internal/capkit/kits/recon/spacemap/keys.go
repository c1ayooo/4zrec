package spacemap

import (
	"fmt"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"strings"
)

// SettingsKey is the settings-table key for an engine API key.
func SettingsKey(provider string) string {
	return "spacemap.key." + normalizeProvider(provider)
}

// BaseURLSettingsKey is the settings-table key for a custom engine endpoint.
func BaseURLSettingsKey(provider string) string {
	return "spacemap.baseurl." + normalizeProvider(provider)
}

// Mask keeps the first 4 and last 2 characters; short keys are fully masked.
func Mask(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", 6) + key[len(key)-2:]
}

// ValidProvider reports whether provider is a supported engine name.
func ValidProvider(provider string) bool { return normalizeProvider(provider) != "" }

// DomainQuery builds the engine-specific query for a domain.
func DomainQuery(provider, domain string) string {
	switch normalizeProvider(provider) {
	case "quake":
		return fmt.Sprintf("domain:%q", domain)
	case "shodan":
		return "hostname:" + domain
	case "hunter":
		return fmt.Sprintf("domain.suffix=%q", domain)
	default:
		return fmt.Sprintf("domain=%q", domain)
	}
}

// DomainQueryTemplate returns the domain query with a {d} placeholder.
func DomainQueryTemplate(provider string) string {
	return DomainQuery(provider, "{d}")
}

// SummarizeRow compresses one engine row into a single line for tool output.
func SummarizeRow(row map[string]interface{}) string {
	host := core.FirstNonEmpty(
		rowStringValue(row, "host"),
		rowStringValue(row, "domain"),
		rowStringValue(row, "ip"), rowStringValue(row, "ip_str"),
	)
	port := rowIntValue(row, "port")
	title := rowStringValue(row, "title", "web_title", "service.http.title", "http.title")
	parts := make([]string, 0, 3)
	if host != "" {
		parts = append(parts, host)
	}
	if port > 0 {
		parts = append(parts, fmt.Sprintf("port %d", port))
	}
	if title != "" {
		if len([]rune(title)) > 60 {
			title = string([]rune(title)[:60]) + "…"
		}
		parts = append(parts, title)
	}
	if len(parts) == 0 {
		return "(空行)"
	}
	return strings.Join(parts, " | ")
}
