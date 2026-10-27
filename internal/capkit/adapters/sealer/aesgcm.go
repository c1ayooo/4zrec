package sealer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// AESGCM seals secrets with AES-256-GCM. The key may be any length; it is
// normalized to 32 bytes via SHA-256 when needed.
type AESGCM struct {
	key []byte
}

func New(key []byte) (*AESGCM, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		sum := sha256.Sum256(key)
		key = sum[:]
	}
	return &AESGCM{key: append([]byte(nil), key...)}, nil
}

func (s *AESGCM) Seal(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return "enc:v1:" + base64.StdEncoding.EncodeToString(ct), nil
}

func (s *AESGCM) Open(sealed string) (string, error) {
	sealed = strings.TrimSpace(sealed)
	if sealed == "" {
		return "", nil
	}
	if !strings.HasPrefix(sealed, "enc:v1:") {
		return sealed, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, "enc:v1:"))
	if err != nil {
		return "", fmt.Errorf("decode sealed value: %w", err)
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("sealed value is too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("open sealed value: %w", err)
	}
	return string(plain), nil
}
