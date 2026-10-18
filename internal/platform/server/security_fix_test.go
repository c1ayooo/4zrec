package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testServerWithDir(dir string) *Server {
	return &Server{m: &Manager{dir: dir}}
}

func TestWSResolveDeniesSecretsAndSymlinkEscapes(t *testing.T) {
	dataDir := t.TempDir()
	outside := t.TempDir()
	s := testServerWithDir(dataDir)

	if _, ok := s.wsResolve("tasks/1/artifact.txt"); !ok {
		t.Fatal("normal workspace path should resolve")
	}
	for _, denied := range []string{
		"datasource.key",
		"jwt.key",
		"traffic/_ca/mitmproxy-ca.pem",
		"traffic/_index/index.sqlite",
		"archives/tasks/.staging/1/journal.json",
	} {
		if _, ok := s.wsResolve(denied); ok {
			t.Fatalf("workspace must not expose %q", denied)
		}
	}

	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dataDir, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, ok := s.wsResolve("link/secret.txt"); ok {
		t.Fatal("symlink pointing outside the data dir must not resolve")
	}
}

func TestRenderTemplateDoesNotReexpandValues(t *testing.T) {
	got := renderTemplate("echo {a} {b}", map[string]any{
		"a": "{b}",      // must stay literal: no second expansion pass
		"b": "'; id; #", // shell-quoted as a single argument
	}, shellQuote)
	want := `echo '{b}' ''\''; id; #'`
	if got != want {
		t.Fatalf("renderTemplate=%q want %q", got, want)
	}
	if strings.Count(got, "{b}") != 1 {
		t.Fatalf("param value was expanded twice: %q", got)
	}
}

func TestArchiveJournalPathsStayInsideDataDir(t *testing.T) {
	dataDir := t.TempDir()
	if err := validArchiveStageMove(dataDir, archiveFileMove{
		Source: "/etc/passwd", Relative: "files/passwd",
	}); err == nil {
		t.Fatal("staging journal source outside data dir must be rejected")
	}
	if err := validArchiveStageMove(dataDir, archiveFileMove{
		Source: filepath.Join(dataDir, "tasks", "1"), Relative: "../../etc/passwd",
	}); err == nil {
		t.Fatal("staging journal relative traversal must be rejected")
	}
	if err := validRestoreMove(dataDir, restoredArchivePath{
		Source: "/etc/passwd", Destination: filepath.Join(dataDir, "tasks", "1"),
	}); err == nil {
		t.Fatal("restore journal path outside data dir must be rejected")
	}
	if err := validRestoreMove(dataDir, restoredArchivePath{
		Source:      filepath.Join(dataDir, "archives", "x"),
		Destination: filepath.Join(dataDir, "tasks", "1"),
	}); err != nil {
		t.Fatalf("in-data-dir restore move rejected: %v", err)
	}
}

func TestAuthRateLimiterLocksAndResets(t *testing.T) {
	key := "test:" + t.Name()
	for i := 0; i < authMaxFailures; i++ {
		if retry := authRetryAfter(key); retry > 0 {
			t.Fatalf("locked after %d failures, wanted %d", i, authMaxFailures)
		}
		authRecordFailure(key)
	}
	if authRetryAfter(key) <= 0 {
		t.Fatal("limiter should lock after repeated failures")
	}
	authReset(key)
	if authRetryAfter(key) != 0 {
		t.Fatal("reset should clear the lock")
	}
}

func TestLocalFileAllowedConfinesUploads(t *testing.T) {
	dataDir := t.TempDir()
	workDir := filepath.Join(dataDir, "tasks", "1")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(workDir, "payload.bin")
	if err := os.WriteFile(payload, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := testServerWithDir(dataDir)
	if !s.localFileAllowed(payload, workDir) {
		t.Fatal("file inside the task workdir should be allowed")
	}
	if s.localFileAllowed("/etc/passwd", workDir) {
		t.Fatal("host file outside the workdir must be rejected")
	}
	if s.localFileAllowed(filepath.Join(dataDir, "datasource.key"), workDir) {
		t.Fatal("data-dir secret outside the task workdir must be rejected")
	}
}
