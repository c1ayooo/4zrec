// postex 域：后渗透。全部依赖 sessions（目标解析来自 Deps.Sessions）或
// process（横移 argv 构造）；注册本域前宿主应已具备会话底座。
package all

import (
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/av"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/cleanup"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/container"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/internalnet"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/lat"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/persist"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/privesc"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell"
)

// RegisterSession registers the foothold/session tools (session_open/exec/
// upload/download, tunnel_open, list, close). The runtime must supply a
// core.SessionManager (Deps.Sessions) with at least one opener registered.
//
// shellkit 目录在 postex/，但注册入口归 RegisterFlow 聚合（session 是
// flow 域的编排底座，postex 依赖它而不重复注册它）。
func RegisterSession(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: shell.Manifest(), New: shell.NewCapability})
}

// RegisterSessionWithDeployer registers the session tools plus webshell_deploy,
// which needs a host delivery channel. The deployer is a shell type, so it
// cannot ride in core.Deps — the same reason RegisterEnterprise takes a
// resolver. Use this when the host has a way to drop a shell on a target;
// RegisterSession alone leaves webshell_deploy reporting tool_missing.
func RegisterSessionWithDeployer(reg *core.Registry, deployer shell.WebShellDeployer) error {
	return reg.Add(core.Spec{
		Manifest: shell.Manifest(),
		New: func(deps core.Deps) (core.Capability, error) {
			return shell.NewCapabilityWithDeployer(deps, deployer)
		},
	})
}

// RegisterPostExploitation registers the five session-driven kits: privesc
// (enumeration + advice), internalnet, persist, cleanup and av (AV/EDR
// identification). Every one of them resolves its target from Deps.Sessions,
// so they share the same gate chain (scope → approval → ratelimit → audit)
// as session_open.
//
// cleanup never runs without an explicit preview + plan_id + confirm, and
// persist's apply tool requires confirm=true; both are additionally gated by
// the runtime's approval gate because they are high risk.
func RegisterPostExploitation(reg *core.Registry) error {
	kits := []struct {
		name string
		fn   func(core.Deps) (core.Capability, error)
	}{
		{"privesckit", privesc.NewCapability},
		{"internalnetkit", internalnet.NewCapability},
		{"persistkit", persist.NewCapability},
		{"cleanupkit", cleanup.NewCapability},
		{"avkit", av.NewCapability},
	}
	for _, k := range kits {
		c, err := k.fn(core.Deps{})
		if err != nil {
			return err
		}
		if err := reg.Add(core.Spec{Manifest: c.Manifest(), New: k.fn}); err != nil {
			return err
		}
	}
	return nil
}

// RegisterContainer registers the container/k8s detection and escape-triage
// kit. The runtime must supply an HTTPDoer (for the four network probes) and,
// for container_escape_check, a core.SessionManager.
func RegisterContainer(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: container.Manifest(), New: container.NewCapability})
}

// RegisterLateral registers the lateral-movement argv builders (psexec/wmiexec/
// smbexec, pass-the-hash, WinRM, Kerberoast/AS-REP/DCSync). Every tool is a
// subprocess invocation, so the runtime must supply a ProcessRunner; the
// impacket/NetExec binaries themselves stay outside this module (docs §6.2:
// copyleft code is never imported).
func RegisterLateral(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: lat.Manifest(), New: lat.NewCapability})
}

// RegisterPostex registers the postex domain's own kits: lat / privesc /
// internalnet / persist / cleanup / av / container。session（shellkit）不在
// 本聚合——它是 flow 域的编排底座，本域依赖它（先 RegisterFlow）。
func RegisterPostex(reg *core.Registry) error {
	aggregates := []func(*core.Registry) error{
		RegisterLateral, RegisterPostExploitation, RegisterContainer,
	}
	for _, f := range aggregates {
		if err := f(reg); err != nil {
			return err
		}
	}
	return nil
}
