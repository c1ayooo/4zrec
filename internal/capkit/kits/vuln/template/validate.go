package template

import (
	"fmt"
	"strings"
)

var validSeverity = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

// ValidateTemplate checks the authoring contract.
func ValidateTemplate(t Template) error {
	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("template id is required")
	}
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("%s: name is required", t.ID)
	}
	if !t.Kind.Valid() {
		return fmt.Errorf("%s: invalid kind %q", t.ID, t.Kind)
	}
	if !validSeverity[strings.ToLower(strings.TrimSpace(t.Severity))] {
		return fmt.Errorf("%s: invalid severity %q", t.ID, t.Severity)
	}
	switch t.Kind {
	case KindHTTP:
		if t.Request == nil {
			return fmt.Errorf("%s: http template requires request", t.ID)
		}
		if strings.TrimSpace(t.Request.Path) == "" {
			return fmt.Errorf("%s: http request path is required", t.ID)
		}
		if strings.TrimSpace(t.Request.Method) == "" {
			return fmt.Errorf("%s: http request method is required", t.ID)
		}
		for i, m := range t.Matchers {
			if strings.TrimSpace(m.Type) == "" {
				return fmt.Errorf("%s: matcher %d has no type", t.ID, i)
			}
			switch strings.ToLower(m.Type) {
			case "status":
				if len(m.Status) == 0 {
					return fmt.Errorf("%s: status matcher %d has no status", t.ID, i)
				}
			case "word":
				if len(m.Words) == 0 {
					return fmt.Errorf("%s: word matcher %d has no words", t.ID, i)
				}
			case "regex":
				if len(m.Regex) == 0 {
					return fmt.Errorf("%s: regex matcher %d has no regex", t.ID, i)
				}
			case "dsl":
				if strings.TrimSpace(m.DSL) == "" {
					return fmt.Errorf("%s: dsl matcher %d has no expression", t.ID, i)
				}
			default:
				return fmt.Errorf("%s: unsupported matcher type %q", t.ID, m.Type)
			}
		}
	case KindNuclei, KindShell:
		if strings.TrimSpace(t.Engine) == "" && len(t.Artifact) == 0 && strings.TrimSpace(t.Path) == "" {
			return fmt.Errorf("%s: %s template requires engine or artifact", t.ID, t.Kind)
		}
	case KindChain:
		if len(t.Artifact) == 0 && strings.TrimSpace(t.Path) == "" && len(t.Metadata) == 0 {
			return fmt.Errorf("%s: chain template requires artifact or metadata", t.ID)
		}
	}
	return nil
}

// ValidatePack validates all templates and enforces unique IDs.
func ValidatePack(p *Pack) error {
	if p == nil {
		return fmt.Errorf("pack is nil")
	}
	if strings.TrimSpace(p.Manifest.Name) == "" {
		return fmt.Errorf("pack name is required")
	}
	if strings.TrimSpace(p.Manifest.Version) == "" {
		return fmt.Errorf("pack version is required")
	}
	seen := map[string]bool{}
	for _, t := range p.Templates {
		if err := ValidateTemplate(t); err != nil {
			return err
		}
		if seen[t.ID] {
			return fmt.Errorf("duplicate template id %q", t.ID)
		}
		seen[t.ID] = true
	}
	return nil
}
