package template

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Catalog is an in-memory, engine-neutral template index. It does not execute
// anything; engines consume TemplateRef values.
type Catalog struct {
	mu    sync.RWMutex
	byID  map[string]Template
	owner map[string]string // template id -> pack name
	packs map[string]Pack
}

func NewCatalog() *Catalog {
	return &Catalog{
		byID:  map[string]Template{},
		owner: map[string]string{},
		packs: map[string]Pack{},
	}
}

// AddPack validates and adds/replaces one pack. Replacing a pack removes only
// that pack's prior templates, so hot reload is atomic per pack.
func (c *Catalog) AddPack(p *Pack) error {
	if err := ValidatePack(p); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check cross-pack collisions before mutating anything.
	for _, t := range p.Templates {
		if owner, exists := c.owner[t.ID]; exists && owner != p.Manifest.Name {
			return fmt.Errorf("template %q already belongs to pack %q", t.ID, owner)
		}
	}
	// Remove the previous version of this pack.
	for id, owner := range c.owner {
		if owner == p.Manifest.Name {
			delete(c.byID, id)
			delete(c.owner, id)
		}
	}
	for _, t := range p.Templates {
		t.Pack = p.Manifest.Name
		t.Source = p.Provenance.Source
		c.byID[t.ID] = t
		c.owner[t.ID] = p.Manifest.Name
	}
	c.packs[p.Manifest.Name] = *p
	return nil
}

// Reload loads every source and adds its pack. Any error leaves already-loaded
// packs in place; callers can treat this as best-effort.
func (c *Catalog) Reload(ctx context.Context, sources ...PackSource) error {
	for _, source := range sources {
		p, err := source.Load(ctx)
		if err != nil {
			return err
		}
		if err := c.AddPack(p); err != nil {
			return err
		}
	}
	return nil
}

func (c *Catalog) Get(_ context.Context, id string) (core.TemplateRef, bool, error) {
	c.mu.RLock()
	t, ok := c.byID[id]
	c.mu.RUnlock()
	if !ok {
		return core.TemplateRef{}, false, nil
	}
	ref, err := t.Ref()
	return ref, err == nil, err
}

func (c *Catalog) Search(_ context.Context, q core.TemplateQuery) ([]core.TemplateRef, error) {
	c.mu.RLock()
	all := make([]Template, 0, len(c.byID))
	for _, t := range c.byID {
		all = append(all, t)
	}
	c.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	out := make([]core.TemplateRef, 0, limit)
	for _, t := range all {
		if !matchQuery(t, q) {
			continue
		}
		ref, err := t.Ref()
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (c *Catalog) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.byID)
}

func (c *Catalog) PackNames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.packs))
	for name := range c.packs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func matchQuery(t Template, q core.TemplateQuery) bool {
	if q.Kind != "" && !strings.EqualFold(string(t.Kind), q.Kind) {
		return false
	}
	if q.CVE != "" && !strings.EqualFold(t.CVE, q.CVE) {
		return false
	}
	if len(q.Severity) > 0 {
		ok := false
		for _, s := range q.Severity {
			if strings.EqualFold(t.Severity, s) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(q.Products) > 0 {
		ok := false
		for _, want := range q.Products {
			for _, have := range t.Product {
				if strings.EqualFold(have, want) || strings.Contains(strings.ToLower(have), strings.ToLower(want)) {
					ok = true
					break
				}
			}
			if ok {
				break
			}
		}
		if !ok {
			return false
		}
	}
	if q.Fingerprint != "" {
		needle := strings.ToLower(q.Fingerprint)
		hay := strings.ToLower(t.Fingerprint + " " + strings.Join(t.Product, " ") + " " + t.Name)
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	if len(q.Tags) > 0 {
		ok := false
		for _, want := range q.Tags {
			for _, have := range t.Tags {
				if strings.EqualFold(have, want) {
					ok = true
					break
				}
			}
			if ok {
				break
			}
		}
		if !ok {
			return false
		}
	}
	if q.Text != "" {
		needle := strings.ToLower(q.Text)
		hay := strings.ToLower(strings.Join([]string{
			t.ID, t.Name, t.CVE, t.Fingerprint, strings.Join(t.Product, " "), strings.Join(t.Tags, " "),
		}, " "))
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	return true
}
