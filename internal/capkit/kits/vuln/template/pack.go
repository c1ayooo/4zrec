package template

import (
	"context"
	"time"
)

// Provenance records where a pack came from and under what license.
type Provenance struct {
	Source    string    `json:"source,omitempty"`
	Upstream  string    `json:"upstream,omitempty"`
	License   string    `json:"license,omitempty"`
	Commit    string    `json:"commit,omitempty"`
	FetchedAt time.Time `json:"fetched_at,omitempty"`
}

// PackManifest is the pack.yaml/pack.json contract. Templates may be glob
// patterns; when empty the loader walks the "templates" directory recursively.
type PackManifest struct {
	Name      string   `yaml:"name" json:"name"`
	Version   string   `yaml:"version" json:"version"`
	Source    string   `yaml:"source,omitempty" json:"source,omitempty"`
	License   string   `yaml:"license,omitempty" json:"license,omitempty"`
	Checksum  string   `yaml:"checksum,omitempty" json:"checksum,omitempty"` // sha256:<hex>
	Templates []string `yaml:"templates,omitempty" json:"templates,omitempty"`
}

// Pack is a versioned, provenance-bearing set of templates.
type Pack struct {
	Manifest   PackManifest `json:"manifest"`
	Templates  []Template   `json:"templates"`
	Provenance Provenance   `json:"provenance"`
	Checksum   string       `json:"checksum,omitempty"`
}

// PackSource loads one pack. Implementations may read fs.FS, a directory, an
// artifact store or a remote URL. They must not execute templates.
type PackSource interface {
	Load(ctx context.Context) (*Pack, error)
}
