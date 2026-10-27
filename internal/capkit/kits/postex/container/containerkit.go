// Package containerkit implements Kubernetes/Docker exposure detection and
// container-escape triage as a capkit capability.
//
// It is Phase P2 of docs/究极渗透能力包实现方案.md §4.9. The package exposes two
// kinds of tools:
//
//   - Network probes (k8s_kubelet_probe, k8s_apiserver_probe, k8s_etcd_probe,
//     docker_api_probe) that talk to exposed control-plane and daemon ports
//     through the injected core.HTTPDoer, so scope, rate limiting and audit
//     gates cannot be bypassed.
//   - Foothold triage (container_escape_check, container_escape_plan) that runs
//     bounded read-only checks through an existing core.Session and turns the
//     result into ranked, non-executing next steps.
//
// The package never executes an escape. container_escape_plan is decision
// support only: it returns candidate techniques as core.NextStep items with
// the preconditions each one needs.
package container

import (
	"context"
	"encoding/json"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Version is the capability version reported in the manifest and Meta.
const Version = "0.1.0"

// Capability is the registry/capability adapter. It holds only injected ports
// and no mutable state, so Call is safe for concurrent use.
type Capability struct {
	deps core.Deps
}

// NewCapability builds the capability from injected ports. Missing ports are
// not fatal here: each tool checks the port it needs and returns a precise
// ToolMissing/Unavailable envelope instead of failing construction.
func NewCapability(deps core.Deps) (core.Capability, error) {
	return &Capability{deps: deps}, nil
}

// Manifest declares the six container/k8s tools.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: "containerkit", Version: Version, APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "http", "sessions"},
		Tools: []core.ToolSpec{
			kubeletProbeSpec(), apiserverProbeSpec(), etcdProbeSpec(), dockerProbeSpec(),
			escapeCheckSpec(), escapePlanSpec(),
		},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches by tool name and always returns a Result envelope.
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "k8s_kubelet_probe":
		return c.kubeletProbe(ctx, call)
	case "k8s_apiserver_probe":
		return c.apiserverProbe(ctx, call)
	case "k8s_etcd_probe":
		return c.etcdProbe(ctx, call)
	case "docker_api_probe":
		return c.dockerProbe(ctx, call)
	case "container_escape_check":
		return c.escapeCheck(ctx, call)
	case "container_escape_plan":
		return c.escapePlan(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

// stamp fills the fixed Meta fields every handler must carry.
func stamp(res core.Result, tool string, start time.Time) core.Result {
	res.Meta.Tool = tool
	res.Meta.Version = Version
	if res.Meta.DurationMS == 0 {
		res.Meta.DurationMS = time.Since(start).Milliseconds()
	}
	return res
}

// decodeJSON unmarshals call input, converting failures into the stable
// invalid_input envelope.
func decodeJSON(input json.RawMessage, out any) *core.Error {
	if err := json.Unmarshal(input, out); err != nil {
		return core.InvalidInput(err.Error())
	}
	return nil
}

// dataMap is a small helper mirroring exploitkit's envelope construction.
func dataMap(summary string, v any) core.Result {
	res, _ := core.SuccessResult(summary, v)
	return res
}
