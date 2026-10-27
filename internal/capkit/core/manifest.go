package core

import (
	"encoding/json"
	"fmt"
)

// RateLimitSpec is the declared per-key rate budget for a tool.
type RateLimitSpec struct {
	PerSecond   float64 `json:"per_second,omitempty"`
	Burst       int     `json:"burst,omitempty"`
	Concurrency int     `json:"concurrency,omitempty"`
}

// Normalized fills safe defaults. PerSecond<=0 means "use host default".
func (s RateLimitSpec) Normalized() RateLimitSpec {
	if s.PerSecond < 0 {
		s.PerSecond = 0
	}
	if s.Burst < 0 {
		s.Burst = 0
	}
	if s.Concurrency < 0 {
		s.Concurrency = 0
	}
	return s
}

// SettingSpec lets the host render a settings form without kit-specific UI.
type SettingSpec struct {
	Key         string `json:"key"`
	Type        string `json:"type"` // string | bool | int
	Default     any    `json:"default,omitempty"`
	Description string `json:"description,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
}

// EventSpec declares an event the host may map to notifications/SSE/webhooks.
type EventSpec struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ToolSpec is the stable tool contract. InputSchema is JSON Schema; the host
// exposes it to the agent framework verbatim. OutputSchema describes the shape
// of this tool's Result.Data so agents know the return before calling.
type ToolSpec struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	InputSchema  json.RawMessage `json:"input_schema"`
	OutputSchema json.RawMessage `json:"output_schema,omitempty"`
	Risk         Risk            `json:"risk"`
	RateLimit    RateLimitSpec   `json:"rate_limit,omitempty"`
	// ExtractTargets is mandatory for tools that act on a target. It is a Go
	// function (not serialized); the runtime uses it to enforce scope before
	// the kit is called. Tools without a target return nil.
	ExtractTargets func(json.RawMessage) ([]Target, error) `json:"-"`
}

// Manifest describes a capability. Requires lists port names the host must
// provide; Registry.Validate enforces them.
type Manifest struct {
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	APIVersion string        `json:"api_version"`
	Requires   []string      `json:"requires,omitempty"`
	Tools      []ToolSpec    `json:"tools"`
	Settings   []SettingSpec `json:"settings,omitempty"`
	Events     []EventSpec   `json:"events,omitempty"`
}

// Validate checks the static contract.
func (m *Manifest) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("manifest name is required")
	}
	if m.Version == "" {
		return fmt.Errorf("%s: version is required", m.Name)
	}
	if m.APIVersion == "" {
		return fmt.Errorf("%s: api_version is required", m.Name)
	}
	if len(m.Tools) == 0 {
		return fmt.Errorf("%s: at least one tool is required", m.Name)
	}
	seen := map[string]bool{}
	for i := range m.Tools {
		if err := m.Tools[i].Validate(); err != nil {
			return fmt.Errorf("%s: %w", m.Name, err)
		}
		if seen[m.Tools[i].Name] {
			return fmt.Errorf("%s: duplicate tool %q", m.Name, m.Tools[i].Name)
		}
		seen[m.Tools[i].Name] = true
	}
	return nil
}

// Validate checks one tool contract.
func (t *ToolSpec) Validate() error {
	if t.Name == "" {
		return fmt.Errorf("tool name is required")
	}
	if t.Description == "" {
		return fmt.Errorf("%s: description is required", t.Name)
	}
	if !t.Risk.Valid() {
		return fmt.Errorf("%s: invalid risk %q", t.Name, t.Risk)
	}
	if len(t.InputSchema) == 0 {
		t.InputSchema = json.RawMessage(`{"type":"object"}`)
	}
	var v any
	if err := json.Unmarshal(t.InputSchema, &v); err != nil {
		return fmt.Errorf("%s: input_schema is not valid JSON: %w", t.Name, err)
	}
	return nil
}
