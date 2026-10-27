package template

import (
	"encoding/json"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Kind identifies which engine executes a template.
type Kind string

const (
	KindHTTP   Kind = "http"
	KindNuclei Kind = "nuclei"
	KindShell  Kind = "shell"
	KindChain  Kind = "chain"
)

func (k Kind) Valid() bool {
	switch k {
	case KindHTTP, KindNuclei, KindShell, KindChain:
		return true
	default:
		return false
	}
}

// RequestSpec is the engine-neutral HTTP request description for kind=http.
type RequestSpec struct {
	Method  string            `yaml:"method" json:"method"`
	Path    string            `yaml:"path" json:"path"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty" json:"body,omitempty"`
}

// Matcher is a minimal, engine-neutral match rule. Engines may add their own
// richer matching; this covers the common status/word/regex/dsl cases.
type Matcher struct {
	Type   string   `yaml:"type" json:"type"` // status | word | regex | dsl
	Part   string   `yaml:"part,omitempty" json:"part,omitempty"`
	Status []int    `yaml:"status,omitempty" json:"status,omitempty"`
	Words  []string `yaml:"words,omitempty" json:"words,omitempty"`
	Regex  []string `yaml:"regex,omitempty" json:"regex,omitempty"`
	DSL    string   `yaml:"dsl,omitempty" json:"dsl,omitempty"`
}

// Extract pulls a value out of a matched response.
type Extract struct {
	Name  string `yaml:"name" json:"name"`
	Regex string `yaml:"regex" json:"regex"`
	Group int    `yaml:"group,omitempty" json:"group,omitempty"`
}

// Template is one predefined verification/exploitation recipe. It is engine
// neutral; the Artifact holds the original engine payload (nuclei YAML, shell
// spec, ...) while Request/Matchers describe the normalized http form.
type Template struct {
	ID          string            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	Kind        Kind              `yaml:"kind" json:"kind"`
	Product     []string          `yaml:"product,omitempty" json:"product,omitempty"`
	Fingerprint string            `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	Severity    string            `yaml:"severity,omitempty" json:"severity,omitempty"`
	Tags        []string          `yaml:"tags,omitempty" json:"tags,omitempty"`
	CVE         string            `yaml:"cve,omitempty" json:"cve,omitempty"`
	Engine      string            `yaml:"engine,omitempty" json:"engine,omitempty"`
	Request     *RequestSpec      `yaml:"request,omitempty" json:"request,omitempty"`
	Matchers    []Matcher         `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extract     []Extract         `yaml:"extract,omitempty" json:"extract,omitempty"`
	References  []string          `yaml:"references,omitempty" json:"references,omitempty"`
	Metadata    map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`

	// Runtime/provenance fields (not part of the authored template).
	Path     string `yaml:"-" json:"-"`
	Pack     string `yaml:"-" json:"-"`
	Source   string `yaml:"-" json:"-"`
	Artifact []byte `yaml:"-" json:"-"`
}

// Ref converts a template into the engine-neutral reference consumed by
// TemplateEngine implementations.
func (t Template) Ref() (core.TemplateRef, error) {
	artifact := t.Artifact
	if len(artifact) == 0 {
		b, err := json.Marshal(t)
		if err != nil {
			return core.TemplateRef{}, err
		}
		artifact = b
	}
	meta := map[string]string{
		"severity": t.Severity,
		"cve":      t.CVE,
		"path":     t.Path,
		"pack":     t.Pack,
		"source":   t.Source,
	}
	if len(t.Product) > 0 {
		meta["products"] = strings.Join(t.Product, ",")
	}
	return core.TemplateRef{
		ID: t.ID, Name: t.Name, Kind: string(t.Kind), Engine: t.Engine,
		Artifact: artifact, Meta: meta,
	}, nil
}
