package mcpstdio

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestNewStdioClientSpawnsWithEnvAndArgs exercises the real stdio spawn path of
// NewStdioClient: it re-invokes this test binary as a child process running the
// in-package fakeServer on stdin/stdout, passing the helper mode flag through
// the env map and the -test.run selector through args. No external MCP server
// is involved.
func TestNewStdioClientSpawnsWithEnvAndArgs(t *testing.T) {
	if os.Getenv("MCPSTDIO_FAKE_SERVER") == "1" {
		fakeServer(os.Stdin, os.Stdout)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	child := os.Args[0]
	client, err := NewStdioClient(ctx, "spawned", child,
		map[string]string{"MCPSTDIO_FAKE_SERVER": "1"},
		"-test.run=TestNewStdioClientSpawnsWithEnvAndArgs")
	if err != nil {
		t.Fatalf("NewStdioClient: %v", err)
	}
	defer client.Close()

	tools, err := client.Tools(ctx)
	if err != nil {
		t.Fatalf("tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name() != "mcp__spawned__echo" {
		t.Fatalf("tool naming: %+v", tools)
	}
	res, err := tools[0].Call(ctx, []byte(`{"msg":"hi"}`), nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if res.Flatten() != "echoed!" {
		t.Fatalf("call result: %q", res.Flatten())
	}
}

// TestNewStdioClientBadCommand verifies construction fails cleanly (and closes
// nothing dangling) when the configured command does not exist.
func TestNewStdioClientBadCommand(t *testing.T) {
	_, err := NewStdioClient(context.Background(), "srv", "mcpstdio-definitely-not-a-real-binary-9x7",
		nil, "--flag")
	if err == nil {
		t.Fatal("expected error spawning a nonexistent command, got nil")
	}
}
