package session_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/session"
)

type fakeExec struct {
	last  string
	lastF session.FileOp
}

func (f *fakeExec) Exec(_ context.Context, _ session.Session, cmd string) (*session.ExecResult, error) {
	f.last = cmd
	return &session.ExecResult{Output: "R:" + cmd, HTTPStatus: 200, TrafficID: "ev"}, nil
}

func (f *fakeExec) File(_ context.Context, _ session.Session, op session.FileOp) (*session.ExecResult, error) {
	f.lastF = op
	if op.Action == "read" {
		// Declaring the encoding is what makes the decode unambiguous.
		return &session.ExecResult{Output: "aGVsbG8=", HTTPStatus: 200, Encoding: "base64"}, nil // "hello"
	}
	return &session.ExecResult{Output: "ok", HTTPStatus: 200}, nil
}

var _ core.Session = (*session.CapabilitySession)(nil)
var _ core.Uploader = (*session.CapabilitySession)(nil)
var _ core.Downloader = (*session.CapabilitySession)(nil)

func newSession(exec session.Executor) *session.CapabilitySession {
	return &session.CapabilitySession{
		Shell:    session.Session{ID: 7, URL: "http://h/s.php", ShellType: "godzilla", Protocol: "http"},
		Executor: exec,
	}
}

func TestAdapterExec(t *testing.T) {
	f := &fakeExec{}
	s := newSession(f)
	out, err := s.Exec(context.Background(), "id", core.ExecOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Stdout != "R:id" || out.ExitCode != 0 {
		t.Fatalf("out = %+v", out)
	}
	if out.EvidenceID != "ev" {
		t.Fatalf("evidence = %q", out.EvidenceID)
	}
	// dir is prepended
	_, _ = s.Exec(context.Background(), "ls", core.ExecOpts{Dir: "/tmp"})
	if !strings.HasPrefix(f.last, "cd /tmp &&") {
		t.Fatalf("dir not applied: %q", f.last)
	}
	// empty command rejected
	if _, err := s.Exec(context.Background(), "  ", core.ExecOpts{}); err == nil {
		t.Fatal("expected empty-command error")
	}
}

func TestAdapterInfo(t *testing.T) {
	info := newSession(&fakeExec{}).Info()
	if info.Kind != "webshell" {
		t.Fatalf("kind = %q", info.Kind)
	}
	if info.ID != "webshell-7" || info.Host != "h" {
		t.Fatalf("info = %+v", info)
	}
	if info.Meta["shell_type"] != "godzilla" {
		t.Fatalf("meta = %v", info.Meta)
	}
	if err := newSession(&fakeExec{}).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterUpload(t *testing.T) {
	f := &fakeExec{}
	s := newSession(f)
	if err := s.Upload(context.Background(), strings.NewReader("payload"), "/tmp/x"); err != nil {
		t.Fatal(err)
	}
	if f.lastF.Action != "write" || f.lastF.Path != "/tmp/x" || string(f.lastF.Content) != "payload" {
		t.Fatalf("file op = %+v", f.lastF)
	}
	if err := s.Upload(context.Background(), strings.NewReader("x"), ""); err == nil {
		t.Fatal("expected empty-path error")
	}
}

func TestAdapterDownload(t *testing.T) {
	s := newSession(&fakeExec{})
	rc, err := s.Download(context.Background(), "/tmp/x")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	body, _ := io.ReadAll(rc)
	if string(body) != "hello" {
		t.Fatalf("body = %q (base64 should be decoded)", body)
	}
}

func TestAdapterNilExecutor(t *testing.T) {
	s := &session.CapabilitySession{}
	if _, err := s.Exec(context.Background(), "id", core.ExecOpts{}); err == nil {
		t.Fatal("expected executor-missing error")
	}
	if err := s.Upload(context.Background(), strings.NewReader("x"), "/y"); err == nil {
		t.Fatal("expected executor-missing error")
	}
	if _, err := s.Download(context.Background(), "/y"); err == nil {
		t.Fatal("expected executor-missing error")
	}
}

// fileExec returns one fixed File result, so the encoding contract can be
// pinned without a protocol implementation.
type fileExec struct{ res session.ExecResult }

func (f fileExec) Exec(context.Context, session.Session, string) (*session.ExecResult, error) {
	return &session.ExecResult{Output: "ok"}, nil
}

func (f fileExec) File(context.Context, session.Session, session.FileOp) (*session.ExecResult, error) {
	r := f.res
	return &r, nil
}

func downloadBytes(t *testing.T, res session.ExecResult) ([]byte, error) {
	t.Helper()
	s := &session.CapabilitySession{
		Shell:    session.Session{ID: 7, URL: "http://h/s.php"},
		Executor: fileExec{res: res},
	}
	rc, err := s.Download(context.Background(), "/tmp/f")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(rc)
}

// TestAdapterDownloadDoesNotGuessEncoding pins the fix for a silent-corruption
// bug: "payloadbytes" consists of 12 base64-alphabet characters, so the old
// sniffing heuristic decoded it to 9 garbage bytes. An undeclared body is the
// file itself.
func TestAdapterDownloadDoesNotGuessEncoding(t *testing.T) {
	got, err := downloadBytes(t, session.ExecResult{Output: "payloadbytes", HTTPStatus: 200})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payloadbytes" {
		t.Fatalf("undeclared body was altered: %q", got)
	}
	// The same holds for shorter base64-shaped words: eight alphabet characters
	// are a legal base64 string too.
	got, err = downloadBytes(t, session.ExecResult{Output: "abcdefgh", HTTPStatus: 200})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcdefgh" {
		t.Fatalf("eight-char plain text was altered: %q", got)
	}
}

func TestAdapterDownloadHonorsDeclaredBase64(t *testing.T) {
	got, err := downloadBytes(t, session.ExecResult{Output: "aGVsbG8=", HTTPStatus: 200, Encoding: "base64"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("declared base64 was not decoded: %q", got)
	}
}

func TestAdapterDownloadRejectsInvalidDeclaredBase64(t *testing.T) {
	if _, err := downloadBytes(t, session.ExecResult{Output: "not base64!", Encoding: "base64"}); err == nil {
		t.Fatal("a declared base64 body that does not decode must be an error, not silent garbage")
	}
}
