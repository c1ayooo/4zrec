package server

import (
	"os"
	"path/filepath"
	"strings"
)

// resolveExisting makes p absolute and resolves symlinks on the longest
// existing prefix, so a symlinked ancestor cannot be used to escape a root
// check for a path that does not exist yet.
func resolveExisting(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return abs
	}
	return filepath.Join(resolveExisting(parent), filepath.Base(abs))
}

// pathWithin reports whether candidate is root or lives under root. Both sides
// are made absolute and symlinks are resolved when the path exists, so a symlink
// inside root cannot point at a file outside it.
func pathWithin(root, candidate string) bool {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(candidate) == "" {
		return false
	}
	rootAbs := resolveExisting(root)
	candAbs := resolveExisting(candidate)
	return candAbs == rootAbs || strings.HasPrefix(candAbs, rootAbs+string(os.PathSeparator))
}

// localFileAllowed confines agent-supplied local file paths (currently the
// http_probe upload_file source) to the task working directory or the agent's
// temp directory. Without this, target-side prompt injection can read the JWT
// signing key / DB DSN / LLM keys and exfiltrate them in one multipart request.
func (s *Server) localFileAllowed(path, workDir string) bool {
	if strings.TrimSpace(path) == "" {
		return true
	}
	if workDir != "" && pathWithin(workDir, path) {
		return true
	}
	if pathWithin(filepath.Join(os.TempDir(), "4zrec"), path) {
		return true
	}
	// Chat/main-agent calls without a task workspace still need a sane root.
	if workDir == "" && s != nil && s.m != nil {
		return pathWithin(s.m.dir, path)
	}
	return false
}
