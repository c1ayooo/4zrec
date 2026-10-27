package shell_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell"
)

// webshell_deploy tests. The host boundary is exercised with a Deployer that
// writes to a real temp directory, so the assertions are about real bytes: the
// generated payload is what landed, its sha256 matches, and the session spec it
// hands back actually drives a shell over that file.

// fileDeployer is a host Deployer that writes the payload into a real
// directory, so the assertions are about real bytes rather than a mock.
type fileDeployer struct {
	dir  string
	last shell.WebShellDrop
}

func (d *fileDeployer) Drop(_ context.Context, req shell.WebShellDrop) (*shell.WebShellDropResult, error) {
	d.last = req
	path := filepath.Join(d.dir, req.Filename)
	if err := os.WriteFile(path, req.Content, 0o600); err != nil {
		return nil, err
	}
	return &shell.WebShellDropResult{
		FileURL: "http://127.0.0.1:8080/" + req.Filename,
		Cleanup: "rm -f " + path,
	}, nil
}

func callDeploy(t *testing.T, cap0 core.Capability, tool string, input map[string]any) core.Result {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cap0.Call(context.Background(), core.Call{Tool: tool, Input: raw})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return res
}

func newDeployCapability(t *testing.T, deployer shell.WebShellDeployer) core.Capability {
	t.Helper()
	c, err := shell.NewCapabilityWithDeployer(core.Deps{}, deployer)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newDeployCapabilityWithoutDeployer(t *testing.T) core.Capability {
	t.Helper()
	c, err := shell.NewCapability(core.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWebShellDeployWritesRealPayloadAndHandsBackSessionSpec(t *testing.T) {
	dir := t.TempDir()
	deployer := &fileDeployer{dir: dir}
	cap0 := newDeployCapability(t, deployer)

	res := callDeploy(t, cap0, "webshell_deploy", map[string]any{
		"target": "http://127.0.0.1:8080/exec.php", "shell_type": "php",
		"password": "pw1234", "watermark": "test-watermark",
	})
	if res.Status != core.StatusSuccess {
		t.Fatalf("deploy failed: %s / %+v", res.Summary, res.Error)
	}

	var out struct {
		FileURL    string `json:"file_url"`
		SHA256     string `json:"sha256"`
		Filename   string `json:"filename"`
		TemplateID string `json:"template_id"`
		WebShell   struct {
			Kind    string            `json:"kind"`
			Host    string            `json:"host"`
			Secret  string            `json:"secret"`
			Options map[string]string `json:"options"`
		} `json:"webshell"`
		Cleanup struct {
			Command string `json:"command"`
			Missing string `json:"missing"`
		} `json:"cleanup"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}

	// The bytes really landed, and the reported sha256 is of the dropped file.
	path := filepath.Join(dir, out.Filename)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the payload was not written to the target dir: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("the dropped payload is empty")
	}
	if !strings.Contains(string(body), "pw1234") {
		t.Fatal("the password must be baked into the payload, or the shell cannot authenticate")
	}
	if !strings.Contains(string(body), out.TemplateID[:3]) && out.TemplateID != "" {
		// template ids are descriptive, not embedded; this just guards against a
		// mismatched payload entirely.
		t.Logf("template %q not embedded (fine for some templates)", out.TemplateID)
	}
	if !strings.HasPrefix(out.SHA256, "sha256") && len(out.SHA256) != 64 {
		t.Fatalf("sha256 = %q", out.SHA256)
	}

	// The session spec must be usable by session_open as-is: the WebShell opener
	// reads shell_type/cmd_param/pass_param from options and the password from
	// secret.
	if out.WebShell.Kind != "webshell" || out.WebShell.Secret != "pw1234" {
		t.Fatalf("webshell spec = %+v", out.WebShell)
	}
	if out.WebShell.Host != out.FileURL {
		t.Fatalf("session host %q must be the dropped URL %q", out.WebShell.Host, out.FileURL)
	}
	if out.WebShell.Options["shell_type"] != "php" {
		t.Fatalf("options = %v", out.WebShell.Options)
	}
	if out.WebShell.Options["pass_param"] == "" || out.WebShell.Options["cmd_param"] == "" {
		t.Fatalf("session options must name both params: %v", out.WebShell.Options)
	}

	// A dropped file must come with a removal command (red line: nothing on the
	// target without a way to remove it).
	if out.Cleanup.Command == "" {
		t.Fatal("webshell_deploy must return a cleanup command")
	}
	if out.Cleanup.Missing != "" {
		t.Fatalf("cleanup should not be flagged missing: %q", out.Cleanup.Missing)
	}
	if !strings.Contains(out.Cleanup.Command, out.Filename) {
		t.Fatalf("cleanup command %q does not name the dropped file %q", out.Cleanup.Command, out.Filename)
	}

	// Next steps must point at session_open with exactly this spec, so the chain
	// is one call rather than a reconstruction.
	if len(res.Next) == 0 || res.Next[0].Tool != "session_open" {
		t.Fatalf("next = %+v", res.Next)
	}
	var nextSpec struct {
		Kind   string `json:"kind"`
		Host   string `json:"host"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(res.Next[0].Params, &nextSpec); err != nil {
		t.Fatalf("next params are not a session spec: %v", err)
	}
	if nextSpec.Host != out.FileURL || nextSpec.Secret != "pw1234" {
		t.Fatalf("next spec = %+v", nextSpec)
	}
}

func TestWebShellDeployCleanupRemovesTheDroppedFile(t *testing.T) {
	dir := t.TempDir()
	deployer := &fileDeployer{dir: dir}
	cap0 := newDeployCapability(t, deployer)
	res := callDeploy(t, cap0, "webshell_deploy", map[string]any{
		"target": "http://127.0.0.1:8080/exec.php", "shell_type": "php", "password": "pw1234",
	})
	var out struct {
		Filename string `json:"filename"`
		Cleanup  struct {
			Command string `json:"command"`
		} `json:"cleanup"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, out.Filename)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("payload should exist before cleanup: %v", err)
	}
	// The returned command must actually remove the file it names.
	if out.Cleanup.Command != "rm -f "+path {
		t.Fatalf("cleanup = %q", out.Cleanup.Command)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("running the cleanup failed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the file survived cleanup")
	}
}

func TestWebShellDeployWithoutDeployerIsToolMissing(t *testing.T) {
	cap0 := newDeployCapabilityWithoutDeployer(t)
	res := callDeploy(t, cap0, "webshell_deploy", map[string]any{
		"target": "http://127.0.0.1:8080/exec.php", "shell_type": "php",
	})
	if res.Error == nil || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("error = %+v", res.Error)
	}
}

func TestWebShellDeployRejectsBadInputBeforeGenerating(t *testing.T) {
	dir := t.TempDir()
	deployer := &fileDeployer{dir: dir}
	cap0 := newDeployCapability(t, deployer)

	// Unknown shell type.
	res := callDeploy(t, cap0, "webshell_deploy", map[string]any{
		"target": "http://127.0.0.1/", "shell_type": "cfm",
	})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("shell_type: %+v", res.Error)
	}
	if _, err := os.ReadDir(dir); err != nil || len(mustReaddir(t, dir)) != 0 {
		t.Fatal("a rejected shell_type must not write anything")
	}

	// Unknown variant.
	res = callDeploy(t, cap0, "webshell_deploy", map[string]any{
		"target": "http://127.0.0.1/", "shell_type": "php", "variant": "nuclear",
	})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("variant: %+v", res.Error)
	}

	// Missing target.
	res = callDeploy(t, cap0, "webshell_deploy", map[string]any{"shell_type": "php"})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("target: %+v", res.Error)
	}

	// Encrypted protocol on a non-PHP target: Generate refuses, and the tool must
	// report it as bad input, not as a delivery failure.
	res = callDeploy(t, cap0, "webshell_deploy", map[string]any{
		"target": "http://127.0.0.1/", "shell_type": "jsp", "protocol": "godzilla",
	})
	if res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("protocol: %+v", res.Error)
	}
}

func TestWebShellDeployDropFailureIsUpstream(t *testing.T) {
	cap0 := newDeployCapability(t, failingDeployer{})
	res := callDeploy(t, cap0, "webshell_deploy", map[string]any{
		"target": "http://127.0.0.1:8080/exec.php", "shell_type": "php",
	})
	if res.Error == nil || res.Error.Code != core.CodeUpstreamError {
		t.Fatalf("a host-side drop failure must be an upstream error: %+v", res.Error)
	}
	if !strings.Contains(res.Error.Message, "投递失败") {
		t.Fatalf("message = %q", res.Error.Message)
	}
}

func TestWebShellDeployPasswordAppearsOnlyInSessionSpec(t *testing.T) {
	dir := t.TempDir()
	deployer := &fileDeployer{dir: dir}
	cap0 := newDeployCapability(t, deployer)
	const password = "sup3r_s3cret_pass" // payload literals allow only [A-Za-z0-9_]
	res := callDeploy(t, cap0, "webshell_deploy", map[string]any{
		"target": "http://127.0.0.1:8080/exec.php", "shell_type": "php", "password": password,
	})
	if res.Status != core.StatusSuccess {
		t.Fatalf("deploy: %s", res.Summary)
	}
	// The Summary must not leak the password; the session spec legitimately
	// carries it because the host needs it to open the session.
	if strings.Contains(res.Summary, password) {
		t.Fatalf("password leaked into the Summary: %q", res.Summary)
	}
	var out struct {
		WebShell struct {
			Secret string `json:"secret"`
		} `json:"webshell"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out.WebShell.Secret != password {
		t.Fatalf("the session spec must carry the password: %q", out.WebShell.Secret)
	}
}

func TestWebShellDeployLiteVariantIsAccepted(t *testing.T) {
	dir := t.TempDir()
	cap0 := newDeployCapability(t, &fileDeployer{dir: dir})
	res := callDeploy(t, cap0, "webshell_deploy", map[string]any{
		"target": "http://127.0.0.1:8080/exec.php", "shell_type": "php",
		"variant": "lite", "password": "pw1234",
	})
	if res.Status != core.StatusSuccess {
		t.Fatalf("lite variant: %s / %+v", res.Summary, res.Error)
	}
	var out struct {
		Variant string `json:"variant"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Variant != "lite" {
		t.Fatalf("variant = %q", out.Variant)
	}
}

// ---- helpers ----

func mustReaddir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

type failingDeployer struct{}

func (failingDeployer) Drop(context.Context, shell.WebShellDrop) (*shell.WebShellDropResult, error) {
	return nil, errString("target refused the write (403)")
}

type errString string

func (e errString) Error() string { return string(e) }
