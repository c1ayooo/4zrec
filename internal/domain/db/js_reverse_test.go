package db

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestJSReverseMCPArgs(t *testing.T) {
	var args []string
	if err := json.Unmarshal([]byte(jsReverseMCPArgs()), &args); err != nil {
		t.Fatalf("jsReverseMCPArgs() is not valid JSON: %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("args = %v, want [script, --isolated]", args)
	}
	if got := filepath.Base(args[0]); got != "js-reverse-mcp-4zrec.mjs" {
		t.Fatalf("script = %q, want js-reverse-mcp-4zrec.mjs", args[0])
	}
	if args[1] != "--isolated" {
		t.Fatalf("flag = %q, want --isolated", args[1])
	}
}
