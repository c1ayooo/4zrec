package fingerprint

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

// FaviconHash returns the FOFA/EHole/dddd-compatible icon hash:
// signed int32 of mmh3(encodebytes(favicon)).
func FaviconHash(icon []byte) string {
	return fmt.Sprint(int32(mmh3([]byte(stdBase64MIME(icon)), 0)))
}

func stdBase64MIME(data []byte) string {
	raw := base64.StdEncoding.EncodeToString(data)
	var buf bytes.Buffer
	for i := 0; i < len(raw); i++ {
		buf.WriteByte(raw[i])
		if (i+1)%76 == 0 {
			buf.WriteByte('\n')
		}
	}
	buf.WriteByte('\n')
	return buf.String()
}

// mmh3 is MurmurHash3 x86 32-bit.
func mmh3(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h1 := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		j := i * 4
		k1 := uint32(data[j]) | uint32(data[j+1])<<8 | uint32(data[j+2])<<16 | uint32(data[j+3])<<24
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	var k1 uint32
	tail := data[nblocks*4:]
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}
