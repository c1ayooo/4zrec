package container

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// TestManifestToolNames locks the exact tool surface containerkit exports. The
// names are the agent-facing contract, so an accidental rename must fail here.
func TestManifestToolNames(t *testing.T) {
	want := []string{
		"container_escape_check",
		"container_escape_plan",
		"docker_api_probe",
		"k8s_apiserver_probe",
		"k8s_etcd_probe",
		"k8s_kubelet_probe",
	}
	var got []string
	for _, tool := range Manifest().Tools {
		got = append(got, tool.Name)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("tool names = %v, want %v", got, want)
	}
}

// TestManifestSchemaObjects enforces the root package contract
// (TestEveryToolHasValidSchemas): every tool declares a non-empty, valid JSON
// Schema object for both input_schema and output_schema, plus a valid risk.
func TestManifestSchemaObjects(t *testing.T) {
	m := Manifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest invalid: %v", err)
	}
	for _, tool := range m.Tools {
		if !tool.Risk.Valid() {
			t.Errorf("%s: invalid risk %q", tool.Name, tool.Risk)
		}
		for label, raw := range map[string]json.RawMessage{
			"input_schema":  tool.InputSchema,
			"output_schema": tool.OutputSchema,
		} {
			if len(raw) == 0 {
				t.Errorf("%s: empty %s", tool.Name, label)
				continue
			}
			var v map[string]any
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Errorf("%s: %s is not valid JSON: %v", tool.Name, label, err)
				continue
			}
			if v["type"] != "object" {
				t.Errorf("%s: %s type = %v, want object", tool.Name, label, v["type"])
			}
		}
	}
}

// TestManifestRequiresAndRisk sanity-checks the declared ports. Risk is locked
// per tool: the four network probes and container_escape_check (which executes
// commands through a session) are medium or higher; container_escape_plan is
// low because it is pure decision support with no network or command execution.
func TestManifestRequiresAndRisk(t *testing.T) {
	m := Manifest()
	req := map[string]bool{}
	for _, r := range m.Requires {
		req[r] = true
	}
	for _, want := range []string{"scope", "limiter", "audit", "http", "sessions"} {
		if !req[want] {
			t.Errorf("manifest missing required port %q", want)
		}
	}
	for _, tool := range m.Tools {
		if tool.Name == "container_escape_plan" {
			if tool.Risk != core.RiskLow {
				t.Errorf("%s: risk = %q, want low", tool.Name, tool.Risk)
			}
			continue
		}
		if !tool.Risk.AtLeast(core.RiskMedium) {
			t.Errorf("%s: risk %q below medium", tool.Name, tool.Risk)
		}
	}
}
