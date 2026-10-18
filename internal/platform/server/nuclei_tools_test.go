package server

import "testing"

func TestNucleiToolNames(t *testing.T) {
	s := &Server{}
	want := map[string]bool{
		"nuclei_scan":            true,
		"fingerprint_verify":     true,
		"nuclei_template_search": true,
		"nuclei_update":          true,
		"nuclei_status":          true,
	}
	tools := s.nucleiTools()
	if len(tools) != len(want) {
		t.Fatalf("nucleiTools() = %d, want %d", len(tools), len(want))
	}
	for _, tool := range tools {
		if !want[tool.Name()] {
			t.Fatalf("unexpected tool %q", tool.Name())
		}
		delete(want, tool.Name())
	}
	if len(want) != 0 {
		t.Fatalf("missing tools: %v", want)
	}
}

func TestNucleiTargetURL(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"example.com", "http://example.com", false},
		{"example.com:8443", "http://example.com:8443", false},
		{"https://example.com/x", "https://example.com/x", false},
		{"1.2.3.4:8080", "http://1.2.3.4:8080", false},
		{"::1", "http://[::1]", false},
		{"[::1]:8080", "http://[::1]:8080", false},
		{"", "", true},
		{"has space", "", true},
	}
	for _, c := range cases {
		got, err := nucleiTargetURL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: got %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}
