package gates

import (
	"encoding/json"
	"strings"
)

// Redactor removes secret-looking fields before input hashing/audit.
type Redactor interface {
	Redact(input json.RawMessage) json.RawMessage
}

// JSONRedactor redacts well-known secret keys recursively. Unknown shapes are
// replaced with a marker rather than hashed raw.
type JSONRedactor struct{}

var secretKeys = map[string]bool{
	"password": true, "passwd": true, "pass": true, "secret": true,
	"token": true, "authorization": true, "cookie": true, "set-cookie": true,
	"api_key": true, "apikey": true, "access_key": true, "secret_key": true,
	"private_key": true, "credential": true, "credentials": true,
}

func (JSONRedactor) Redact(input json.RawMessage) json.RawMessage {
	if len(input) == 0 {
		return json.RawMessage(`{}`)
	}
	var v any
	if err := json.Unmarshal(input, &v); err != nil {
		return json.RawMessage(`{"redacted":true}`)
	}
	redactValue(v)
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{"redacted":true}`)
	}
	return b
}

func redactValue(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if secretKeys[strings.ToLower(k)] {
				x[k] = "[redacted]"
				continue
			}
			redactValue(val)
		}
	case []any:
		for _, item := range x {
			redactValue(item)
		}
	}
}
