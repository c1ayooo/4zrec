package session

import "testing"

// TestDefaultPorts pins the well-known ports per transport. SMB regression:
// it must be 445, not 5985 (which belongs to WinRM).
func TestDefaultPorts(t *testing.T) {
	cases := map[string]int{
		"ssh":   22,
		"winrm": 5985,
		"smb":   445,
		"cli":   0,
		"other": 0,
	}
	for kind, want := range cases {
		if got := defaultPort(kind); got != want {
			t.Errorf("defaultPort(%q) = %d, want %d", kind, got, want)
		}
	}
}
