package core

import (
	"fmt"
	"strings"
)

// Deps is the full set of host-provided ports. Runtime fills defaults for
// Logger/Clock/IDs; everything else is intentionally explicit.
type Deps struct {
	Scope     ScopeChecker
	Approval  Approver
	Evidence  EvidenceSink
	HTTP      HTTPDoer
	Fetcher   Fetcher
	Limiter   Limiter
	Audit     AuditSink
	Settings  Settings
	Sealer    Sealer
	Logger    Logger
	Clock     Clock
	IDs       IDGenerator
	Processes ProcessRunner
	Artifacts ArtifactStore
	Binaries  BinaryManager

	Fingerprints    FingerprintProvider
	Templates       TemplateCatalog
	TemplateEngines map[string]TemplateEngine
	Sessions        SessionManager

	Intel     IntelStore
	Completer Completer

	// ExtraIntel are advisory sources the host fetches itself and wants polled
	// through the same store and dedup path as the kit's own sources. See
	// IntelSource: this is the seam for sources that need host-specific
	// machinery (a JS engine, an authenticated API, a private feed).
	ExtraIntel []IntelSource
}

// Spec is a static capability declaration: manifest + constructor. It holds no
// instances and no mutable state.
type Spec struct {
	Manifest Manifest
	New      func(Deps) (Capability, error)
}

// Registry is the single source of truth for capability declarations. It only
// validates and stores specs; the runtime instantiates them.
type Registry struct {
	specs []Spec
	caps  map[string]bool
	tools map[string]string // tool -> capability
}

func NewRegistry() *Registry {
	return &Registry{caps: map[string]bool{}, tools: map[string]string{}}
}

// Add validates and registers one capability spec.
func (r *Registry) Add(spec Spec) error {
	if spec.New == nil {
		return fmt.Errorf("%s: constructor is required", spec.Manifest.Name)
	}
	if err := spec.Manifest.Validate(); err != nil {
		return err
	}
	if r.caps[spec.Manifest.Name] {
		return fmt.Errorf("capability %q already registered", spec.Manifest.Name)
	}
	for _, tool := range spec.Manifest.Tools {
		if owner, ok := r.tools[tool.Name]; ok {
			return fmt.Errorf("tool %q already registered by %q", tool.Name, owner)
		}
	}
	r.specs = append(r.specs, spec)
	r.caps[spec.Manifest.Name] = true
	for _, tool := range spec.Manifest.Tools {
		r.tools[tool.Name] = spec.Manifest.Name
	}
	return nil
}

// Specs returns a copy of the registered specs.
func (r *Registry) Specs() []Spec {
	out := make([]Spec, len(r.specs))
	copy(out, r.specs)
	return out
}

// Validate checks that every declared port is available.
func (r *Registry) Validate(deps Deps) error {
	available := map[string]bool{
		"scope":    deps.Scope != nil,
		"approval": deps.Approval != nil,
		"evidence": deps.Evidence != nil,
		"http":     deps.HTTP != nil,
		"fetcher":  deps.Fetcher != nil,
		"limiter":  deps.Limiter != nil,
		"audit":    deps.Audit != nil,
		"settings": deps.Settings != nil,
		"sealer":   deps.Sealer != nil,
		"process":  deps.Processes != nil,
		"artifact": deps.Artifacts != nil,
		"binary":   deps.Binaries != nil,
		"logger":   deps.Logger != nil,
		"clock":    deps.Clock != nil,
		"ids":      deps.IDs != nil,

		"fingerprints":     deps.Fingerprints != nil,
		"templates":        deps.Templates != nil,
		"template_engines": len(deps.TemplateEngines) > 0,
		"sessions":         deps.Sessions != nil,
		"intel":            deps.Intel != nil,
		"completer":        deps.Completer != nil,
	}
	var missing []string
	for _, spec := range r.specs {
		for _, req := range spec.Manifest.Requires {
			key := strings.ToLower(strings.TrimSpace(req))
			if !available[key] {
				missing = append(missing, spec.Manifest.Name+" requires "+req)
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing ports: %s", strings.Join(missing, "; "))
	}
	return nil
}
