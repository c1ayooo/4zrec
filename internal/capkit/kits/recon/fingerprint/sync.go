package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"gopkg.in/yaml.v3"
)

// Fetcher downloads rule sources. It is deliberately separate from
// core.HTTPDoer: rule sources are external infrastructure, not in-scope
// targets, so the host supplies a download client/proxy.
type Fetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

type Format string

const (
	FormatWappalyzer Format = "wappalyzer"
	FormatWebanalyze Format = "webanalyze"
	FormatDDDD       Format = "dddd"
)

type Source struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Format Format `json:"format"`
}

type Syncer struct {
	Fetcher Fetcher
}

func (s *Syncer) Fetch(ctx context.Context, src Source) ([]Rule, error) {
	if s.Fetcher == nil {
		return nil, fmt.Errorf("fingerprintkit: fetcher is not configured")
	}
	data, err := s.Fetcher.Fetch(ctx, src.URL)
	if err != nil {
		return nil, err
	}
	switch src.Format {
	case FormatWappalyzer, FormatWebanalyze, "":
		return parseWappalyzer(data, src.Name)
	case FormatDDDD:
		return parseDDDD(data, src.Name)
	default:
		return nil, fmt.Errorf("fingerprintkit: unsupported format %q", src.Format)
	}
}

func (s *Syncer) FetchAll(ctx context.Context, sources []Source) ([]Rule, error) {
	var out []Rule
	for _, src := range sources {
		rules, err := s.Fetch(ctx, src)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, err)
		}
		out = append(out, rules...)
	}
	return out, nil
}

// ---- Wappalyzer / webanalyze ----

type wappalyzerFile struct {
	Technologies map[string]wappalyzerTech `json:"technologies"`
	Apps         map[string]wappalyzerTech `json:"apps"`
}

type wappalyzerTech struct {
	Cats    []int          `json:"cats"`
	HTML    any            `json:"html"`
	Headers map[string]any `json:"headers"`
	Cookies map[string]any `json:"cookies"`
	Scripts any            `json:"scripts"`
	Meta    map[string]any `json:"meta"`
	URL     any            `json:"url"`
}

func parseWappalyzer(data []byte, source string) ([]Rule, error) {
	var file wappalyzerFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	techs := file.Technologies
	if len(techs) == 0 {
		techs = file.Apps
	}
	if len(techs) == 0 {
		return nil, fmt.Errorf("no technologies found")
	}
	out := make([]Rule, 0, len(techs))
	for name, tech := range techs {
		r := Rule{ID: source + "/" + name, Name: name, Product: name, Source: source}
		if len(tech.Cats) > 0 {
			r.Category = fmt.Sprintf("cat:%d", tech.Cats[0])
		}
		for _, v := range stringList(tech.HTML) {
			r.Patterns = append(r.Patterns, Pattern{Type: "body", Value: v})
		}
		for _, v := range stringList(tech.Scripts) {
			r.Patterns = append(r.Patterns, Pattern{Type: "body", Value: v})
		}
		for _, v := range stringList(tech.URL) {
			r.Patterns = append(r.Patterns, Pattern{Type: "url", Value: v})
		}
		for key, raw := range tech.Headers {
			for _, v := range stringList(raw) {
				r.Patterns = append(r.Patterns, Pattern{Type: "header", Part: key, Value: v})
			}
		}
		for key, raw := range tech.Cookies {
			for _, v := range stringList(raw) {
				r.Patterns = append(r.Patterns, Pattern{Type: "cookie", Part: key, Value: v})
			}
		}
		for key, raw := range tech.Meta {
			for _, v := range stringList(raw) {
				r.Patterns = append(r.Patterns, Pattern{Type: "meta", Part: key, Value: v})
			}
		}
		if len(r.Patterns) > 0 {
			out = append(out, r)
		}
	}
	return out, nil
}

// ---- dddd ----

// parseDDDD is best-effort: dddd rule files have evolved over time, so the
// parser accepts the common name/product + keyword/body/headers/favicon shapes
// and ignores unknown fields.
func parseDDDD(data []byte, source string) ([]Rule, error) {
	var root any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	items := ddddItems(root)
	out := make([]Rule, 0, len(items))
	for _, item := range items {
		name := stringValue(item["name"])
		if name == "" {
			name = stringValue(item["product"])
		}
		if name == "" {
			continue
		}
		r := Rule{ID: source + "/" + name, Name: name, Product: core.FirstNonEmpty(stringValue(item["product"]), name), Source: source}
		for _, key := range []string{"keyword", "body", "html", "rule"} {
			for _, v := range stringList(item[key]) {
				r.Patterns = append(r.Patterns, Pattern{Type: "body", Value: v})
			}
		}
		if headers, ok := item["headers"].(map[string]any); ok {
			for key, raw := range headers {
				for _, v := range stringList(raw) {
					r.Patterns = append(r.Patterns, Pattern{Type: "header", Part: key, Value: v})
				}
			}
		}
		for _, key := range []string{"favicon", "icon_hash", "iconhash"} {
			for _, v := range stringList(item[key]) {
				r.Patterns = append(r.Patterns, Pattern{Type: "favicon", Value: v})
			}
		}
		if len(r.Patterns) > 0 {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no dddd rules parsed")
	}
	return out, nil
}

func ddddItems(root any) []map[string]any {
	switch v := root.(type) {
	case []any:
		return mapsOf(v)
	case map[string]any:
		for _, key := range []string{"finger", "fingers", "rules", "data"} {
			if arr, ok := v[key].([]any); ok {
				return mapsOf(arr)
			}
		}
	}
	return nil
}

func mapsOf(items []any) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func stringList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	default:
		return nil
	}
}

func stringValue(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}
