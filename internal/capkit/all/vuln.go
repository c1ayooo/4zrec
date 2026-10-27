// vuln 域：漏洞验证与检测生产。依赖 http + process + templates/fingerprints
// （部分 kit 另需 completer/artifact 或 IntelStore 这类宿主端口）。
package all

import (
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/exploit"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/intel"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/nuclei"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/oast"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/poc"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/template"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/vuln/verify"
)

// RegisterNuclei registers the nuclei execution capability.
func RegisterNuclei(reg *core.Registry) error {
	kit := nuclei.New(core.Deps{})
	return reg.Add(core.Spec{Manifest: kit.Manifest(), New: nuclei.NewCapability})
}

// RegisterTemplate registers the read-only template catalog tools. Execution
// stays in the template engines (verify/nuclei).
func RegisterTemplate(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: template.Manifest(), New: template.NewCapability})
}

// RegisterVerify registers verify. The runtime must be given a
// FingerprintProvider, a TemplateCatalog and at least one TemplateEngine.
func RegisterVerify(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: verify.Manifest(), New: verify.NewCapability})
}

// RegisterExploit registers the deterministic web-entry exploit probes
// (cmdi/ssti/lfi/sqli/ssrf + redis/msf/deser helpers). All ten tools are
// exposed to the agent. The runtime must supply an HTTPDoer; a ProcessRunner is
// needed only for msf_execute and deser_generate (otherwise those two return
// unavailable).
func RegisterExploit(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: exploit.Manifest(), New: exploit.NewCapability})
}

// RegisterOAST registers the dnslog.cn OAST kit. The runtime must be given a
// Fetcher.
func RegisterOAST(reg *core.Registry) error {
	kit := oast.New(core.Deps{})
	return reg.Add(core.Spec{Manifest: kit.Manifest(), New: oast.NewCapability})
}

// RegisterVulnIntel registers the vulnerability-intel polling kit. The
// runtime must be given a Fetcher (advisory endpoints are external data) and
// an IntelStore (the kit never opens a database).
func RegisterVulnIntel(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: intel.Manifest(), New: intel.NewCapability})
}

// RegisterPoC registers the advisory-to-artifact generation kit. The runtime
// must be given a Completer and an ArtifactStore; generation tools return
// drafts and only poc_publish writes.
func RegisterPoC(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: poc.Manifest(), New: poc.NewCapability})
}

// RegisterVuln registers the whole vuln domain: nuclei / template / verify /
// exploit / oast / intel / poc。
func RegisterVuln(reg *core.Registry) error {
	aggregates := []func(*core.Registry) error{
		RegisterNuclei, RegisterTemplate, RegisterVerify, RegisterExploit,
		RegisterOAST, RegisterVulnIntel, RegisterPoC,
	}
	for _, f := range aggregates {
		if err := f(reg); err != nil {
			return err
		}
	}
	return nil
}
