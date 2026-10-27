package memshell

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// randHex 生成 nBytes 字节 crypto/rand 随机数的十六进制串。
func randHex(nBytes int) (string, error) {
	if nBytes <= 0 {
		return "", nil
	}
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randBytes 生成 nBytes 字节 crypto/rand 随机数。
func randBytes(nBytes int) ([]byte, error) {
	if nBytes <= 0 {
		return nil, nil
	}
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// sanitizeWatermark 水印清洗：仅保留字母/数字/-/_，上限 64 字节。
func sanitizeWatermark(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() > 64 {
		return b.String()[:64]
	}
	return b.String()
}
