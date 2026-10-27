package runtime_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/auditlog"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/sealer"
	"github.com/c1ayooo/4zrec/internal/capkit/adapters/settings"
	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/flow/session"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
)

// The stubs below satisfy the ports a full registry declares. They are never
// reached: every call carries invalid input, so the point is the envelope, not
// the outcome.
type stubFetcher struct{}

func (stubFetcher) Fetch(context.Context, core.Request) (*core.Response, error) {
	return &core.Response{Status: 200}, nil
}

type stubRunner struct{}

func (stubRunner) Run(context.Context, core.ProcessSpec) (*core.ProcessResult, error) {
	return &core.ProcessResult{ExitCode: 0}, nil
}

type stubBinaries struct{}

func (stubBinaries) Ensure(context.Context, string, string) (string, core.BinaryStatus, error) {
	return "", core.BinaryStatus{}, nil
}
func (stubBinaries) Update(context.Context, string, string) (core.BinaryStatus, error) {
	return core.BinaryStatus{}, nil
}
func (stubBinaries) Status(context.Context, string) (core.BinaryStatus, error) {
	return core.BinaryStatus{}, nil
}

type stubFingerprints struct{}

func (stubFingerprints) Fingerprint(context.Context, core.Target) ([]core.Fingerprint, error) {
	return nil, nil
}

// stubIntel and stubCompleter let the intel/generation kits reach their own
// envelope paths instead of failing registry validation.
type stubIntel struct{}

func (stubIntel) Upsert(context.Context, core.IntelItem) (string, bool, error) {
	return "intel-1", true, nil
}
func (stubIntel) Query(context.Context, core.IntelQuery) ([]core.IntelItem, error) { return nil, nil }
func (stubIntel) Get(context.Context, string) (*core.IntelItem, error) {
	return nil, core.NotFound("not found")
}

type stubCompleter struct{}

func (stubCompleter) Complete(context.Context, string, string, int) (string, error) {
	return "{}", nil
}

type stubArtifacts struct{}

func (stubArtifacts) Put(context.Context, string, []byte) (string, error) { return "/tmp/x", nil }
func (stubArtifacts) Get(context.Context, string) ([]byte, error)         { return nil, core.NotFound("x") }
func (stubArtifacts) Delete(context.Context, string) error                { return nil }

type stubCatalog struct{}

func (stubCatalog) Search(context.Context, core.TemplateQuery) ([]core.TemplateRef, error) {
	return nil, nil
}
func (stubCatalog) Get(context.Context, string) (core.TemplateRef, bool, error) {
	return core.TemplateRef{}, false, nil
}

type stubEngine struct{}

func (stubEngine) Kind() string { return "http" }
func (stubEngine) Execute(context.Context, []core.TemplateRef, core.Target, map[string]any) (core.Result, error) {
	return core.NewResult(core.StatusSuccess, "stub"), nil
}

// TestEveryRegisteredToolReturnsAValidEnvelope is the §8.4/§8.5 gate applied to
// the whole surface rather than one tool: every tool in RegisterFull is called
// through the runtime with minimal (usually invalid) input, and whatever it
// returns — success, blocked, unavailable, need_human, failed — must satisfy
// the envelope contract.
func TestEveryRegisteredToolReturnsAValidEnvelope(t *testing.T) {
	reg := core.NewRegistry()
	if err := all.RegisterFull(reg); err != nil {
		t.Fatal(err)
	}
	mgr := session.NewManager(nil, nil)
	scope := gates.StaticScope("local")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	seal, err := sealer.New([]byte("envelope-gate-key"))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		HTTP: httpx.New(scope, lim, audit), Fetcher: stubFetcher{},
		Settings: settings.New(nil), Sealer: seal, Processes: stubRunner{},
		Binaries: stubBinaries{}, Fingerprints: stubFingerprints{},
		Templates: stubCatalog{}, TemplateEngines: map[string]core.TemplateEngine{"http": stubEngine{}},
		Sessions: mgr, Intel: stubIntel{}, Completer: stubCompleter{}, Artifacts: stubArtifacts{},
	}, reg)
	if err != nil {
		t.Fatal(err)
	}

	// A closed session id is enough to reach every session tool's not-found
	// path; the point is the envelope, not the outcome.
	in := json.RawMessage(`{"session_id":"nonexistent"}`)
	cc := core.CallContext{ProjectID: 1, Actor: "envelope-gate"}
	for _, tool := range rt.Tools() {
		res, err := rt.Call(context.Background(), tool.Name, in, cc)
		if err != nil {
			// The runtime surfaces gate failures as a returned Result plus a
			// typed error; both must be coherent.
			if res.Status == "" {
				t.Fatalf("%s: transport error without a result envelope", tool.Name)
			}
		}
		// §8.4: Status is one of the six states.
		if !res.Status.Valid() {
			t.Errorf("%s: status %q is not in the six-state enum", tool.Name, res.Status)
			continue
		}
		// §8.4: Summary non-empty and ≤200 runes.
		if res.Summary == "" {
			t.Errorf("%s: empty summary", tool.Name)
		}
		if n := len([]rune(res.Summary)); n > core.MaxSummaryRunes {
			t.Errorf("%s: summary = %d runes > %d", tool.Name, n, core.MaxSummaryRunes)
		}
		// §8.4: Meta.Tool non-empty, DurationMS > 0.
		if res.Meta.Tool == "" {
			t.Errorf("%s: meta.tool empty", tool.Name)
		}
		if res.Meta.DurationMS <= 0 {
			t.Errorf("%s: meta.duration_ms = %d", tool.Name, res.Meta.DurationMS)
		}
		// §8.5: error codes live in the fixed enum and Retryable matches
		// semantics (scope_denied must be false).
		if res.Error != nil {
			if !codeKnown(res.Error.Code) {
				t.Errorf("%s: error code %q outside the fixed enum", tool.Name, res.Error.Code)
			}
			if res.Error.Code == core.CodeScopeDenied && res.Error.Retryable {
				t.Errorf("%s: scope_denied must not be retryable", tool.Name)
			}
		}
		// §8.5: Data respects the ceiling.
		if len(res.Data) > core.MaxDataBytes {
			t.Errorf("%s: data = %d bytes > %d", tool.Name, len(res.Data), core.MaxDataBytes)
		}
		// Status must agree with the presence of an error atom.
		if res.Error != nil && res.Status == core.StatusSuccess {
			t.Errorf("%s: success status with an error atom %+v", tool.Name, res.Error)
		}
	}
}

func codeKnown(code string) bool {
	switch code {
	case core.CodeInvalidInput, core.CodeScopeDenied, core.CodeApprovalRequired,
		core.CodeNotFound, core.CodeConflict, core.CodeRateLimited,
		core.CodeUnavailable, core.CodeInternal, core.CodeNeedHuman,
		core.CodeToolMissing, core.CodeTargetUnreachable, core.CodeTimeout,
		core.CodeUpstreamError, core.CodeEvidenceWriteFailed:
		return true
	}
	return false
}
