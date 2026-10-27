package gates

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONRedactorRemovesSecrets(t *testing.T) {
	in := json.RawMessage(`{"url":"http://x","password":"p","nested":{"token":"t","safe":1},"list":[{"pass":"p2"}]}`)
	out := string((JSONRedactor{}).Redact(in))
	if strings.Contains(out, `"p"`) || strings.Contains(out, `"t"`) || strings.Contains(out, `"p2"`) {
		t.Fatalf("secret leaked: %s", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Fatalf("missing marker: %s", out)
	}
}

func TestJSONRedactorHandlesInvalidInput(t *testing.T) {
	out := string((JSONRedactor{}).Redact(json.RawMessage(`not-json`)))
	if out != `{"redacted":true}` {
		t.Fatalf("out = %s", out)
	}
}
