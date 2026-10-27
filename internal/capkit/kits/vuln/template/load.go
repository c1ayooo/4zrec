package template

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DirSource loads a pack from an fs.FS rooted at Root. It supports pack.yaml,
// pack.yml and pack.json manifests, plus YAML/JSON template files.
type DirSource struct {
	FS         fs.FS
	Root       string
	SourceName string
}

func (s DirSource) Load(_ context.Context) (*Pack, error) {
	if s.FS == nil {
		return nil, fmt.Errorf("templatekit: fs is required")
	}
	root := strings.Trim(strings.TrimSpace(s.Root), "/")
	if root == "" {
		root = "."
	}
	manifest, base, err := loadManifest(s.FS, root)
	if err != nil {
		return nil, err
	}
	paths, err := collectTemplatePaths(s.FS, root, manifest.Templates)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("templatekit: pack %q matched no templates", manifest.Name)
	}
	source := strings.TrimSpace(s.SourceName)
	if source == "" {
		source = manifest.Source
	}
	var templates []Template
	var hashes []string
	for _, p := range paths {
		data, err := fs.ReadFile(s.FS, p)
		if err != nil {
			return nil, err
		}
		var t Template
		if err := yaml.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if t.Request != nil && strings.TrimSpace(t.Request.Method) == "" {
			t.Request.Method = "GET"
		}
		t.Path = strings.TrimPrefix(strings.TrimPrefix(p, base), "/")
		t.Pack = manifest.Name
		t.Source = source
		t.Artifact = data
		templates = append(templates, t)
		hashes = append(hashes, p+"\x00"+string(data))
	}
	sort.Strings(hashes)
	sum := sha256.Sum256([]byte(strings.Join(hashes, "\x01")))
	checksum := "sha256:" + hex.EncodeToString(sum[:])
	if strings.TrimSpace(manifest.Checksum) != "" && !strings.EqualFold(strings.TrimSpace(manifest.Checksum), checksum) {
		return nil, fmt.Errorf("templatekit: pack %q checksum mismatch: want %s got %s", manifest.Name, manifest.Checksum, checksum)
	}
	pack := &Pack{
		Manifest: manifest, Templates: templates, Checksum: checksum,
		Provenance: Provenance{
			Source: source, Upstream: manifest.Source, License: manifest.License,
			FetchedAt: time.Now(),
		},
	}
	if err := ValidatePack(pack); err != nil {
		return nil, err
	}
	return pack, nil
}

func loadManifest(fsys fs.FS, root string) (PackManifest, string, error) {
	for _, name := range []string{"pack.yaml", "pack.yml", "pack.json"} {
		p := path.Join(root, name)
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			continue
		}
		var m PackManifest
		if err := yaml.Unmarshal(data, &m); err != nil {
			return PackManifest{}, "", fmt.Errorf("%s: %w", p, err)
		}
		return m, root, nil
	}
	return PackManifest{}, "", fmt.Errorf("templatekit: no pack.yaml/pack.json under %q", root)
}

func collectTemplatePaths(fsys fs.FS, root string, patterns []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(patterns) == 0 {
		patterns = []string{"templates/**/*.yaml", "templates/**/*.yml", "templates/**/*.json"}
	}
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := strings.TrimPrefix(p, root)
		rel = strings.TrimPrefix(rel, "/")
		if !isTemplateFile(rel) {
			return nil
		}
		for _, pattern := range patterns {
			if matchPattern(pattern, rel) {
				add(p)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func isTemplateFile(name string) bool {
	ext := strings.ToLower(path.Ext(name))
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}

func matchPattern(pattern, name string) bool {
	pattern = strings.TrimPrefix(strings.TrimSpace(pattern), "/")
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, "**") {
		base := pattern[:strings.Index(pattern, "**")]
		if !strings.HasPrefix(name, base) {
			return false
		}
		suffix := strings.TrimPrefix(pattern[strings.Index(pattern, "**")+2:], "/")
		if suffix == "" {
			return true
		}
		if !strings.Contains(suffix, "/") {
			ok, _ := path.Match(suffix, path.Base(name))
			return ok
		}
		return strings.HasSuffix(name, suffix)
	}
	ok, _ := path.Match(pattern, name)
	return ok
}
