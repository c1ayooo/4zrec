package fingerprint

import "testing"

func seqBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 256)
	}
	return b
}

func TestMMH3KnownVector(t *testing.T) {
	if got := int32(mmh3([]byte("foo"), 0)); got != -156908512 {
		t.Fatalf("mmh3(foo) = %d", got)
	}
}

func TestFaviconHashGolden(t *testing.T) {
	samples := []struct {
		name string
		data []byte
		want string
	}{
		{"tiny_png_28B", append([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, make([]byte, 20)...), "724282810"},
		{"exact_57B", seqBytes(57), "329978790"},
		{"exact_114B", seqBytes(114), "162474401"},
		{"multi_line_200B", seqBytes(200), "-1874651529"},
		{"real_ico_256B", append([]byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x20}, seqBytes(248)...), "1902522198"},
	}
	for _, s := range samples {
		if got := FaviconHash(s.data); got != s.want {
			t.Errorf("%s: got %s want %s", s.name, got, s.want)
		}
	}
}
