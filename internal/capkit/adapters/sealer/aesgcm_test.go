package sealer

import "testing"

func TestAESGCMRoundTrip(t *testing.T) {
	s, err := New([]byte("short-key"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal("p@ss-中文")
	if err != nil {
		t.Fatal(err)
	}
	if sealed == "" || sealed == "p@ss-中文" {
		t.Fatalf("sealed = %q", sealed)
	}
	plain, err := s.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "p@ss-中文" {
		t.Fatalf("plain = %q", plain)
	}
}

func TestAESGCMEmptyAndLegacy(t *testing.T) {
	s, _ := New([]byte("k"))
	if v, err := s.Seal(""); err != nil || v != "" {
		t.Fatalf("seal empty = %q, %v", v, err)
	}
	if v, err := s.Open(""); err != nil || v != "" {
		t.Fatalf("open empty = %q, %v", v, err)
	}
	if v, err := s.Open("legacy-plain"); err != nil || v != "legacy-plain" {
		t.Fatalf("open legacy = %q, %v", v, err)
	}
}
