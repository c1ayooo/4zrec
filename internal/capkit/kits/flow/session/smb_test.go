package session_test

import (
	"context"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/flow/session"
)

// fakeRunner records process specs and replays canned output, so the SMB
// transport can be exercised without smbclient or a share.
type fakeRunner struct {
	specs  []core.ProcessSpec
	stdout string
	stderr string
	exit   int
	err    error
}

func (f *fakeRunner) Run(_ context.Context, spec core.ProcessSpec) (*core.ProcessResult, error) {
	f.specs = append(f.specs, spec)
	if f.err != nil {
		return nil, f.err
	}
	return &core.ProcessResult{ExitCode: f.exit, Stdout: []byte(f.stdout), Stderr: []byte(f.stderr)}, nil
}

type fakeArtifacts struct {
	put      []byte
	putPath  string
	putCalls int
}

func (a *fakeArtifacts) Put(_ context.Context, _ string, data []byte) (string, error) {
	a.putCalls++
	a.put = data
	if a.putPath == "" {
		a.putPath = "/tmp/stage.bin"
	}
	return a.putPath, nil
}
func (a *fakeArtifacts) Get(context.Context, string) ([]byte, error) { return a.put, nil }
func (a *fakeArtifacts) Delete(context.Context, string) error        { return nil }

func TestSMBSessionExec(t *testing.T) {
	r := &fakeRunner{stdout: "share-listing"}
	o := &session.SMBOpener{Runner: r, Share: "ADMIN$"}
	s, err := o.Open(context.Background(), core.SessionSpec{
		Kind: "smb", Host: "10.0.0.5", User: "admin", Secret: "pw", Domain: "CORP",
	})
	if err != nil {
		t.Fatal(err)
	}
	if info := s.Info(); info.Kind != "smb" || info.Meta["unc"] != "//10.0.0.5/ADMIN$" {
		t.Fatalf("info = %+v", info)
	}
	out, err := s.Exec(context.Background(), "ls", core.ExecOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Stdout, "share-listing") {
		t.Fatalf("stdout = %q", out.Stdout)
	}
	spec := r.specs[0]
	if spec.Path != "smbclient" {
		t.Fatalf("path = %q", spec.Path)
	}
	if !containsArg(spec.Args, "//10.0.0.5/ADMIN$") || !containsArg(spec.Args, `CORP\admin`) {
		t.Fatalf("args = %v", spec.Args)
	}
	// The password must not be in argv, and the target must be scoped.
	for _, a := range spec.Args {
		if strings.Contains(a, "pw") {
			t.Fatalf("password leaked into argv: %v", spec.Args)
		}
	}
	if !containsArg(spec.Env, "PASSWD=pw") {
		t.Fatalf("env = %v", spec.Env)
	}
	if len(spec.Targets) != 1 || spec.Targets[0].Host != "10.0.0.5" {
		t.Fatalf("targets = %+v", spec.Targets)
	}
}

func TestSMBSessionDownloadUsesCat(t *testing.T) {
	r := &fakeRunner{stdout: "remote-file-content"}
	o := &session.SMBOpener{Runner: r}
	s, _ := o.Open(context.Background(), core.SessionSpec{Kind: "smb", Host: "10.0.0.5", User: "u", Secret: "p"})
	rc, err := s.(core.Downloader).Download(context.Background(), "secrets.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	got := make([]byte, 64)
	n, _ := rc.Read(got)
	if !strings.Contains(string(got[:n]), "remote-file-content") {
		t.Fatalf("content = %q", got[:n])
	}
	if !containsArg(r.specs[0].Args, "cat secrets.txt") {
		t.Fatalf("args = %v", r.specs[0].Args)
	}
}

func TestSMBSessionUploadStagesThroughArtifacts(t *testing.T) {
	r := &fakeRunner{}
	art := &fakeArtifacts{}
	o := &session.SMBOpener{Runner: r, Artifacts: art}
	s, _ := o.Open(context.Background(), core.SessionSpec{Kind: "smb", Host: "10.0.0.5", User: "u", Secret: "p"})
	if err := s.(core.Uploader).Upload(context.Background(), strings.NewReader("payload"), "/tmp/x"); err != nil {
		t.Fatal(err)
	}
	if string(art.put) != "payload" {
		t.Fatalf("staged = %q", art.put)
	}
	if !containsArg(r.specs[0].Args, "put /tmp/stage.bin /tmp/x") {
		t.Fatalf("args = %v", r.specs[0].Args)
	}
}

func TestSMBOpenerRequiresRunner(t *testing.T) {
	o := &session.SMBOpener{}
	if _, err := o.Open(context.Background(), core.SessionSpec{Kind: "smb", Host: "10.0.0.5"}); err == nil {
		t.Fatal("SMB opener without ProcessRunner must fail closed")
	}
}

func TestSMBDownloadSurfacesNonZeroExit(t *testing.T) {
	r := &fakeRunner{stderr: "NT_STATUS_OBJECT_NAME_NOT_FOUND", exit: 1}
	o := &session.SMBOpener{Runner: r}
	s, _ := o.Open(context.Background(), core.SessionSpec{Kind: "smb", Host: "10.0.0.5", User: "u", Secret: "p"})
	if _, err := s.(core.Downloader).Download(context.Background(), "missing.txt"); err == nil {
		t.Fatal("a failed smbclient read must return an error")
	}
}

func containsArg(list []string, want string) bool {
	for _, v := range list {
		if v == want || strings.Contains(v, want) {
			return true
		}
	}
	return false
}
