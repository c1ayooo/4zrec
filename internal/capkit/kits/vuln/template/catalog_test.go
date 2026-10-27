package template

import (
	"context"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

func loadTestPack(t *testing.T) *Pack {
	t.Helper()
	p, err := (DirSource{FS: os.DirFS("testdata"), Root: ".", SourceName: "test"}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadPack(t *testing.T) {
	p := loadTestPack(t)
	if p.Manifest.Name != "test-pack" || len(p.Templates) != 2 {
		t.Fatalf("pack = %+v", p.Manifest)
	}
	if !strings.HasPrefix(p.Checksum, "sha256:") {
		t.Fatalf("checksum = %q", p.Checksum)
	}
	if p.Provenance.License != "Apache-2.0" || p.Provenance.Source != "test" {
		t.Fatalf("provenance = %+v", p.Provenance)
	}
	for _, tpl := range p.Templates {
		if len(tpl.Artifact) == 0 {
			t.Fatalf("%s: artifact missing", tpl.ID)
		}
		if tpl.Path == "" {
			t.Fatalf("%s: path missing", tpl.ID)
		}
	}
}

func TestCatalogSearchAndGet(t *testing.T) {
	cat := NewCatalog()
	if err := cat.AddPack(loadTestPack(t)); err != nil {
		t.Fatal(err)
	}
	if cat.Count() != 2 {
		t.Fatalf("count = %d", cat.Count())
	}
	refs, err := cat.Search(context.Background(), core.TemplateQuery{Products: []string{"weaver"}})
	if err != nil || len(refs) != 1 || refs[0].ID != "weaver/eoffice-sqli" {
		t.Fatalf("products search = %+v, %v", refs, err)
	}
	refs, _ = cat.Search(context.Background(), core.TemplateQuery{CVE: "CVE-2021-44228"})
	if len(refs) != 1 || refs[0].Kind != "nuclei" {
		t.Fatalf("cve search = %+v", refs)
	}
	refs, _ = cat.Search(context.Background(), core.TemplateQuery{Tags: []string{"sqli"}})
	if len(refs) != 1 || refs[0].ID != "weaver/eoffice-sqli" {
		t.Fatalf("tag search = %+v", refs)
	}
	refs, _ = cat.Search(context.Background(), core.TemplateQuery{Text: "log4j"})
	if len(refs) != 1 || refs[0].ID != "CVE-2021-44228" {
		t.Fatalf("text search = %+v", refs)
	}
	ref, ok, err := cat.Get(context.Background(), "weaver/eoffice-sqli")
	if err != nil || !ok || ref.Kind != "http" || len(ref.Artifact) == 0 {
		t.Fatalf("get = %+v, %v, %v", ref, ok, err)
	}
	if names := cat.PackNames(); len(names) != 1 || names[0] != "test-pack" {
		t.Fatalf("packs = %v", names)
	}
}

func TestChecksumMismatch(t *testing.T) {
	fsys := fstest.MapFS{
		"pack.yaml":        {Data: []byte("name: bad\nversion: \"1\"\nchecksum: sha256:bad\ntemplates: [\"templates/*.yaml\"]\n")},
		"templates/a.yaml": {Data: []byte("id: a\nname: A\nkind: http\nseverity: low\nrequest: {method: GET, path: /}\n")},
	}
	_, err := (DirSource{FS: fsys}).Load(context.Background())
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v", err)
	}
}

func TestDuplicateTemplateID(t *testing.T) {
	fsys := fstest.MapFS{
		"pack.yaml":        {Data: []byte("name: dup\nversion: \"1\"\ntemplates: [\"templates/*.yaml\"]\n")},
		"templates/a.yaml": {Data: []byte("id: same\nname: A\nkind: http\nseverity: low\nrequest: {method: GET, path: /}\n")},
		"templates/b.yaml": {Data: []byte("id: same\nname: B\nkind: http\nseverity: low\nrequest: {method: GET, path: /}\n")},
	}
	_, err := (DirSource{FS: fsys}).Load(context.Background())
	if err == nil || !strings.Contains(err.Error(), "duplicate template id") {
		t.Fatalf("err = %v", err)
	}
}

func TestAddPackRejectsCrossPackDuplicate(t *testing.T) {
	cat := NewCatalog()
	if err := cat.AddPack(loadTestPack(t)); err != nil {
		t.Fatal(err)
	}
	dup := &Pack{
		Manifest: PackManifest{Name: "other", Version: "1"},
		Templates: []Template{{
			ID: "weaver/eoffice-sqli", Name: "dup", Kind: KindHTTP, Severity: "low",
			Request: &RequestSpec{Method: "GET", Path: "/"},
		}},
	}
	if err := cat.AddPack(dup); err == nil {
		t.Fatal("expected cross-pack duplicate error")
	}
	// The original pack must remain intact.
	if cat.Count() != 2 {
		t.Fatalf("count = %d", cat.Count())
	}
}
