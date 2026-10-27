package core

import "context"

// Fingerprint is one detected technology. Kits return it; the host decides
// whether/how to write it into its asset graph.
type Fingerprint struct {
	Product    string `json:"product"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category,omitempty"`
	Source     string `json:"source,omitempty"`
	Confidence int    `json:"confidence,omitempty"`
}

// FingerprintProvider is implemented by the host or fingerprint. verifykit
// depends only on this interface.
type FingerprintProvider interface {
	Fingerprint(ctx context.Context, target Target) ([]Fingerprint, error)
}

// TemplateRef is an engine-neutral reference to one predefined template.
type TemplateRef struct {
	ID       string            `json:"id"`
	Name     string            `json:"name,omitempty"`
	Kind     string            `json:"kind"`             // http | nuclei | shell | chain
	Engine   string            `json:"engine,omitempty"` // optional engine hint
	Artifact []byte            `json:"artifact,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// TemplateQuery filters a catalog. Empty fields do not filter.
type TemplateQuery struct {
	Text        string   `json:"text,omitempty"`
	Products    []string `json:"products,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Severity    []string `json:"severity,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	Limit       int      `json:"limit,omitempty"`
}

// TemplateCatalog is the engine-neutral template index. It never executes.
type TemplateCatalog interface {
	Search(ctx context.Context, q TemplateQuery) ([]TemplateRef, error)
	Get(ctx context.Context, id string) (TemplateRef, bool, error)
}

// TemplateEngine executes one kind of template (http, nuclei, shell, chain).
// Execution scheduling/concurrency belongs to the engine implementation.
type TemplateEngine interface {
	Kind() string
	Execute(ctx context.Context, refs []TemplateRef, target Target, opts map[string]any) (Result, error)
}
