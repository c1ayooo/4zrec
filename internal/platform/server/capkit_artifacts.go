package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	capkit "github.com/c1ayooo/4zrec/internal/capkit/core"
)

// capkitCompleter adapts the host's model profile to capkit's Completer port.
// The same low-temperature, bounded call the report and intel pipelines use is
// what the generation tools get, so a kit cannot pick a different profile or
// spend outside the host's budget.
type capkitCompleter struct {
	fn func(ctx context.Context, system, user string, maxTokens int) (string, error)
}

func (c capkitCompleter) Complete(ctx context.Context, system, user string, maxTokens int) (string, error) {
	if c.fn == nil {
		return "", capkit.Unavailable("宿主未配置模型补全实现")
	}
	return c.fn(ctx, system, user, maxTokens)
}

// capkitArtifacts is the host's ArtifactStore for published drafts. It writes
// under one root and refuses any name that escapes it: the toolkit hands the
// store a caller-influenced id, so path traversal has to be rejected here
// rather than assumed away at the call site.
type capkitArtifacts struct{ root string }

func newCapkitArtifacts(root string) *capkitArtifacts {
	if strings.TrimSpace(root) == "" {
		root = filepath.Join("data", "intel-drafts")
	}
	return &capkitArtifacts{root: root}
}

// resolve maps an artifact name onto an absolute path inside the root.
func (a *capkitArtifacts) resolve(name string) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(name))
	if clean == "" || clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return "", capkit.InvalidInput("非法的产物名: " + name)
	}
	root, err := filepath.Abs(a.root)
	if err != nil {
		return "", err
	}
	full := filepath.Join(root, clean)
	if full != root && !strings.HasPrefix(full, root+string(os.PathSeparator)) {
		return "", capkit.InvalidInput("产物名越出产物目录: " + name)
	}
	return full, nil
}

func (a *capkitArtifacts) Put(ctx context.Context, name string, data []byte) (string, error) {
	full, err := a.resolve(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "", fmt.Errorf("创建产物目录失败: %w", err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		return "", fmt.Errorf("写入产物失败: %w", err)
	}
	return full, nil
}

func (a *capkitArtifacts) Get(ctx context.Context, path string) ([]byte, error) {
	full, err := a.resolve(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, capkit.NotFound("产物不存在: " + path)
	}
	return data, nil
}

func (a *capkitArtifacts) Delete(ctx context.Context, path string) error {
	full, err := a.resolve(path)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil {
		return capkit.NotFound("产物不存在: " + path)
	}
	return nil
}
