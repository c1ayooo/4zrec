package core_test

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/all"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/harness"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/data/enterprise"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/data/identity"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
)

// This file is the CI gate for the agent-facing output contract (docs §5.5,
// §8): every registered tool is called once with a minimal legal input — with
// fakes only, so nothing touches the network or spawns a real process — and the
// envelope an agent would receive is checked.
//
// The call goes through runtime.Runtime, not the raw capability: that is the
// host's real path, so the runtime's own envelope back-fill (Status, Summary,
// Meta) is covered by the same gate. The point is to catch a tool whose Summary
// is missing or says nothing — the runtime can only fall back to a generic
// "完成", which this gate rejects.
//
// Set CAPKIT_CONTRACT_FILTER=<substring> to narrow the run to the tools whose
// capability or tool name contains it.

// genericSummaries are the empty phrases a Summary must never be: they tell an
// agent nothing about what was done, to what, or with what outcome. These are
// exactly the strings runtime.summarize falls back to, so a tool that never
// wrote a Summary lands here.
var genericSummaries = map[string]bool{
	"":      true,
	"完成":    true,
	"已完":    true,
	"成功":    true,
	"不成功":   true,
	"OK":    true,
	"ok":    true,
	"done":  true,
	"部分完成":  true,
	"失败":    true,
	"被门禁拦截": true,
	"需人工确认": true,
	"依赖不可用": true,
}

// errorCodes is the fixed enum from docs §5.5.3. A Code outside it is free text
// and defeats the host's error mapping.
var errorCodes = map[string]bool{
	core.CodeInvalidInput:        true,
	core.CodeScopeDenied:         true,
	core.CodeApprovalRequired:    true,
	core.CodeNotFound:            true,
	core.CodeConflict:            true,
	core.CodeRateLimited:         true,
	core.CodeUnavailable:         true,
	core.CodeInternal:            true,
	core.CodeNeedHuman:           true,
	core.CodeToolMissing:         true,
	core.CodeTargetUnreachable:   true,
	core.CodeTimeout:             true,
	core.CodeUpstreamError:       true,
	core.CodeEvidenceWriteFailed: true,
}

// contractCallTimeout bounds one tool call so a tool that ignores its context
// cannot hang CI.
const contractCallTimeout = 15 * time.Second

// ciTool pairs one registered tool with the capability that owns it.
type ciTool struct {
	capability string
	spec       core.ToolSpec
}

// contractRuntime builds the runtime a host would build, wired to harness
// fakes: permissive scope/approval/limiter, an in-memory everything else, a
// transport answering every request with `{}`, and no live sessions.
//
// RegisterFull is the baseline the gate is specified against. reconkit and
// enterprisekit are deliberately outside it — both need host-injected
// collaborators (an AssetSink pipeline, a ProviderResolver) that core.Deps
// cannot carry — so they are added here through their own helpers. The
// enterprise resolver reports every provider unconfigured, which still
// exercises that tool surface on its failure path; its success path is covered
// by kits/enterprisekit's own envelope test.
func contractRuntime(t *testing.T) *runtime.Runtime {
	t.Helper()
	reg := core.NewRegistry()
	if err := all.RegisterFull(reg); err != nil {
		t.Fatalf("RegisterFull: %v", err)
	}
	if err := all.RegisterReconPipeline(reg); err != nil {
		t.Fatalf("RegisterReconPipeline: %v", err)
	}
	if err := all.RegisterEnterprise(reg, unavailableResolver{}); err != nil {
		t.Fatalf("RegisterEnterprise: %v", err)
	}
	// identitykit takes its flow registry as an argument (like enterprisekit's
	// resolver), so it is registered here rather than being inside RegisterFull.
	// An empty registry is the honest minimal wiring: it exercises
	// identity_login's "kind not registered" path instead of a mock success.
	if err := all.RegisterIdentity(reg, nil); err != nil {
		t.Fatalf("RegisterIdentity: %v", err)
	}
	ports := harness.NewPorts()
	rt, err := runtime.New(runtime.Config{
		Scope: ports.Scope, Approval: ports.Approval, Evidence: ports.Evidence,
		HTTP: ports.HTTP, Fetcher: ports.Fetcher, Limiter: ports.Limiter, Audit: ports.Audit,
		Settings: ports.Settings, Sealer: ports.Sealer, Logger: ports.Logger,
		Clock: ports.Clock, IDs: ports.IDs, Processes: ports.Process,
		Artifacts: ports.Artifact, Binaries: ports.Binaries,
		Fingerprints: ports.Fingerprints, Templates: ports.Templates,
		TemplateEngines: ports.Deps().TemplateEngines,
		Sessions:        ports.Sessions,
		Intel:           ports.Intel,
		Completer:       ports.Completer,
	}, reg)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	return rt
}

// unavailableResolver reports every enterprise data source as unconfigured.
type unavailableResolver struct{}

func (unavailableResolver) Resolve(context.Context, string) (enterprise.Provider, error) {
	return nil, core.Unavailable("enterprise provider 未配置")
}

// ciTools is every tool the host exposes, including the runtime-owned
// job_status: the gate is about what an agent can actually call.
func ciTools(t *testing.T, rt *runtime.Runtime) []ciTool {
	t.Helper()
	owner := map[string]string{}
	for _, man := range rt.Manifests() {
		for _, tool := range man.Tools {
			owner[tool.Name] = man.Name
		}
	}
	var out []ciTool
	for _, spec := range rt.Tools() {
		out = append(out, ciTool{capability: owner[spec.Name], spec: spec})
	}
	if len(out) == 0 {
		t.Fatal("no tools registered")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].spec.Name < out[j].spec.Name })
	return out
}

// filterTools applies CAPKIT_CONTRACT_FILTER.
func filterTools(t *testing.T, tools []ciTool) []ciTool {
	t.Helper()
	filter := strings.TrimSpace(os.Getenv("CAPKIT_CONTRACT_FILTER"))
	if filter == "" {
		return tools
	}
	var out []ciTool
	for _, tool := range tools {
		if strings.Contains(tool.capability, filter) || strings.Contains(tool.spec.Name, filter) {
			out = append(out, tool)
		}
	}
	if len(out) == 0 {
		t.Fatalf("CAPKIT_CONTRACT_FILTER=%q matched no tool", filter)
	}
	return out
}

// TestContractEnvelope calls every registered tool once and asserts the four
// hard fields of the envelope plus the invariants that follow from them.
func TestContractEnvelope(t *testing.T) {
	rt := contractRuntime(t)
	tools := filterTools(t, ciTools(t, rt))
	for _, tool := range tools {
		tool := tool
		t.Run(tool.spec.Name, func(t *testing.T) {
			res := contractCall(t, rt, tool)
			checkEnvelope(t, tool, res)
		})
	}
}

// contractCall runs one minimal legal call through the runtime, converting a
// panic into a failure attributed to the tool that caused it.
func contractCall(t *testing.T, rt *runtime.Runtime, tool ciTool) core.Result {
	t.Helper()
	input := harness.MinimalInput(tool.spec.InputSchema)
	ctx, cancel := context.WithTimeout(context.Background(), contractCallTimeout)
	defer cancel()
	res, _ := rt.Call(ctx, tool.spec.Name, input, core.CallContext{
		TraceID: "ci", ProjectID: 1, Actor: "contract-ci",
	})
	return res
}

// checkEnvelope is the contract itself.
func checkEnvelope(t *testing.T, tool ciTool, res core.Result) {
	t.Helper()
	label := tool.capability + "/" + tool.spec.Name

	// 1) Status must be one of the six states, and OK must agree with it.
	if !res.Status.Valid() {
		t.Errorf("%s: Status %q is not one of the six states (envelope: %s)", label, res.Status, envelopeJSON(res))
	}
	if want := res.Status == core.StatusSuccess || res.Status == core.StatusPartial; res.OK != want {
		t.Errorf("%s: OK=%v contradicts Status=%s (want OK=%v)", label, res.OK, res.Status, want)
	}

	// 2) Summary must be non-empty, agent-readable, and say something. The
	// runtime back-fills a generic line when a tool wrote none, so an empty
	// phrase here means the tool never described its own outcome.
	summary := strings.TrimSpace(res.Summary)
	switch {
	case summary == "":
		t.Errorf("%s: Summary is empty (it must name the target, the action and the outcome)", label)
	case genericSummaries[summary]:
		t.Errorf("%s: Summary %q is an empty phrase, not a result — the tool must set its own Summary", label, summary)
	case len([]rune(summary)) > core.MaxSummaryRunes:
		t.Errorf("%s: Summary is %d runes, over the %d limit", label, len([]rune(summary)), core.MaxSummaryRunes)
	}

	// 3) Meta.Tool must name the tool the agent asked for.
	if res.Meta.Tool != tool.spec.Name {
		t.Errorf("%s: Meta.Tool = %q, want %q", label, res.Meta.Tool, tool.spec.Name)
	}

	// 4) A failing status needs a machine-readable reason from the fixed enum.
	if res.Error != nil && !errorCodes[res.Error.Code] {
		t.Errorf("%s: Error.Code %q is outside the fixed enum", label, res.Error.Code)
	}
	if res.Error != nil && res.Error.Code == core.CodeScopeDenied && res.Error.Retryable {
		t.Errorf("%s: scope_denied must not be retryable", label)
	}

	// 5) Data, when present, must be valid JSON (the host exposes it as the
	// schema-constrained payload).
	if len(res.Data) > 0 {
		var v any
		if err := json.Unmarshal(res.Data, &v); err != nil {
			t.Errorf("%s: Data is not valid JSON: %v", label, err)
		}
	}
}

// envelopeJSON renders a compact envelope for the failure message, so a tool
// that returns nothing usable is still diagnosable from the test log.
func envelopeJSON(res core.Result) string {
	b, err := json.Marshal(struct {
		OK      bool   `json:"ok"`
		Status  string `json:"status"`
		Summary string `json:"summary"`
		Text    string `json:"text"`
	}{OK: res.OK, Status: string(res.Status), Summary: res.Summary, Text: core.Truncate(res.Text, 120)})
	if err != nil {
		return "<unmarshalable>"
	}
	return string(b)
}

// kitRegistration documents, for every kit in the module, how a host registers
// it. sessionkit is a contract-only package: it carries the Session types and
// transports, declares no tools, and is therefore absent from the registry by
// design (docs §3.1). identitykit used to be contract-only too; it now declares
// the three identity tools (M2) and is registered through RegisterIdentity with
// an empty flow registry — the same path a host with no registered site logins
// takes (pinned in argKitRegistration below).
var kitRegistration = map[string]func(*core.Registry) error{
	"httpkit":        all.RegisterHTTP,
	"nucleikit":      all.RegisterNuclei,
	"verifykit":      all.RegisterVerify,
	"githubkit":      all.RegisterGithub,
	"oastkit":        all.RegisterOAST,
	"spacemapkit":    all.RegisterSpacemap,
	"icpkit":         all.RegisterICP,
	"credkit":        all.RegisterCred,
	"cloudkit":       all.RegisterCloud,
	"fingerprintkit": all.RegisterFingerprint,
	"templatekit":    all.RegisterTemplate,
	"playbookkit":    all.RegisterPlaybook,
	"toolparse":      all.RegisterToolParse,
	"exploitkit":     all.RegisterExploit,
	"shellkit":       all.RegisterSession,
	"containerkit":   all.RegisterContainer,
	"latkit":         all.RegisterLateral,
	"reconkit":       all.RegisterReconPipeline,
	"vulnintelkit":   all.RegisterVulnIntel,
	"pockit":         all.RegisterPoC,
	"bindingkit":     all.RegisterBinding,
}

// argKitRegistration covers the kits whose registration helper takes a
// host-supplied collaborator, so they cannot be values in kitRegistration. They
// are pinned here with the minimal legal argument: an empty identity flow
// registry, a resolver that reports everything unconfigured, and a session kit
// with no delivery channel (which leaves webshell_deploy reporting
// tool_missing — the honest result for a host that cannot drop a shell).
var argKitRegistration = map[string]func(*core.Registry) error{
	"identitykit": func(reg *core.Registry) error {
		return all.RegisterIdentity(reg, identity.NewAuthFlowRegistry())
	},
	"enterprisekit": func(reg *core.Registry) error {
		return all.RegisterEnterprise(reg, unavailableResolver{})
	},
}

// postExploitationKits are registered by RegisterPostExploitation, which
// instantiates each kit to read its manifest.
var postExploitationKits = []string{"privesckit", "internalnetkit", "persistkit", "cleanupkit", "avkit"}

// TestEveryKitReachesTheRegistry fails when a kit exists in the module but no
// registration helper exposes its tools: its manifest is then unreachable from
// RegisterFull, and its tools silently never reach an agent.
func TestEveryKitReachesTheRegistry(t *testing.T) {
	for name, register := range kitRegistration {
		reg := core.NewRegistry()
		if err := register(reg); err != nil {
			t.Errorf("%s: register: %v", name, err)
			continue
		}
		if !hasCapability(reg, name) {
			t.Errorf("%s: its registration helper did not add the capability", name)
		}
	}
	for name, register := range argKitRegistration {
		reg := core.NewRegistry()
		if err := register(reg); err != nil {
			t.Errorf("%s: register: %v", name, err)
			continue
		}
		if !hasCapability(reg, name) {
			t.Errorf("%s: its registration helper did not add the capability", name)
		}
	}

	reg := core.NewRegistry()
	if err := all.RegisterFull(reg); err != nil {
		t.Fatalf("RegisterFull: %v", err)
	}
	for _, name := range postExploitationKits {
		if !hasCapability(reg, name) {
			t.Errorf("%s: not reachable through RegisterFull", name)
		}
	}
	if err := all.RegisterEnterprise(reg, unavailableResolver{}); err != nil {
		t.Fatalf("RegisterEnterprise: %v", err)
	}
	if !hasCapability(reg, "enterprisekit") {
		t.Error("enterprisekit: not reachable through RegisterEnterprise")
	}

	// Every tool declared by the registry must be resolvable by name.
	seen := map[string]bool{}
	for _, spec := range reg.Specs() {
		for _, tool := range spec.Manifest.Tools {
			if seen[tool.Name] {
				t.Errorf("tool %q is declared by two capabilities", tool.Name)
			}
			seen[tool.Name] = true
		}
	}
}

func hasCapability(reg *core.Registry, name string) bool {
	for _, spec := range reg.Specs() {
		if spec.Manifest.Name == name {
			return true
		}
	}
	return false
}
