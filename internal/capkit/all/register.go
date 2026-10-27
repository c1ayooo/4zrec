// Package all is the batteries-included registration entry point for the
// reusable kits. Registration is organized by offensive phase (域):
//
//	all.RegisterRecon(reg)   // 侦察域：http/fingerprint/spacemap/icp/github
//	all.RegisterVuln(reg)    // 漏洞域：nuclei/template/verify/exploit/oast/intel/poc
//	all.RegisterPostex(reg)  // 后渗透域：lat/privesc/internalnet/persist/cleanup/av/container
//	all.RegisterData(reg)    // 数据域：cred/cloud/binding/toolparse（enterprise/identity 需宿主参数单独注册）
//	all.RegisterFlow(reg)    // 编排域：playbook + session（后渗透依赖 session）
//
// The granular per-kit Register* helpers live in the domain files
// (recon.go/vuln.go/postex.go/data.go/flow.go); RegisterFull is the one-shot
// that registers everything and therefore requires every port (including a
// SessionManager for the session-driven kits).
package all

import (
	"errors"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/flow/session"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell"
	shellsession "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/session"
)

// RegisterWebShellOpener wires the shell kit's WebShellOpener into a session
// Manager under kind "webshell". It exists so a host assembles a WebShell
// foothold in one line: after this, session_open(kind="webshell", host=<shell
// URL>, options={"shell_type":...}, secret=<password>) drives the given
// Executor through the same Session contract SSH and WinRM use.
//
// It lives here rather than in either kit because it needs both: the shell kit
// owns the opener, the session kit owns the Manager, and a kit may not import
// another kit.
func RegisterWebShellOpener(mgr *session.Manager, exec shellsession.Executor) error {
	if mgr == nil {
		return errors.New("session.Manager 不能为空")
	}
	if exec == nil {
		return errors.New("WebShell Executor 不能为空")
	}
	mgr.RegisterOpener("webshell", &shell.WebShellOpener{Executor: exec})
	return nil
}

// Register registers the minimal, port-free baseline: the HTTP probe and the
// nuclei runner. Everything else declares a port and is registered by the more
// specific helpers (or by RegisterFull).
func Register(reg *core.Registry) error {
	if err := RegisterHTTP(reg); err != nil {
		return err
	}
	return RegisterNuclei(reg)
}

// RegisterFull additionally registers verify, github, oast, spacemap, icp,
// exploit, the shell session tools, the post-exploitation kits
// (privesc/internalnet/persist/cleanup/av), container, lat and cloud. Only use
// it when the host supplies fingerprints/templates/template_engines/fetcher/
// settings/a SessionManager/a ProcessRunner/an HTTPDoer and has an approval
// gate configured (the session, lateral-movement, exploit and cloud-assistant
// tools are high risk).
//
// The recon pipeline and enterprise are deliberately NOT here: both need
// host-injected collaborators that core.Deps cannot carry (an AssetSink
// pipeline for recon, a ProviderResolver for enterprise), so hosts register
// them with RegisterReconPipeline / RegisterEnterprise instead. 注册集合与
// 顺序与五域拆分前逐 kit 一致（域聚合入口见各域文件）。
func RegisterFull(reg *core.Registry) error {
	if err := Register(reg); err != nil {
		return err
	}
	if err := RegisterVerify(reg); err != nil {
		return err
	}
	if err := RegisterGithub(reg); err != nil {
		return err
	}
	if err := RegisterOAST(reg); err != nil {
		return err
	}
	if err := RegisterSpacemap(reg); err != nil {
		return err
	}
	if err := RegisterICP(reg); err != nil {
		return err
	}
	if err := RegisterFingerprint(reg); err != nil {
		return err
	}
	if err := RegisterTemplate(reg); err != nil {
		return err
	}
	if err := RegisterVulnIntel(reg); err != nil {
		return err
	}
	if err := RegisterPoC(reg); err != nil {
		return err
	}
	if err := RegisterBinding(reg); err != nil {
		return err
	}
	if err := RegisterToolParse(reg); err != nil {
		return err
	}
	if err := RegisterPlaybook(reg); err != nil {
		return err
	}
	if err := RegisterExploit(reg); err != nil {
		return err
	}
	if err := RegisterSession(reg); err != nil {
		return err
	}
	if err := RegisterContainer(reg); err != nil {
		return err
	}
	if err := RegisterLateral(reg); err != nil {
		return err
	}
	if err := RegisterPostExploitation(reg); err != nil {
		return err
	}
	if err := RegisterCloud(reg); err != nil {
		return err
	}
	return RegisterCred(reg)
}
