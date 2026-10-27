// recon 域：侦察面。五个 kit 只依赖出网/情报端口（fetcher/settings/http），
// 宿主可以只注册本域而不拖入任何后渗透能力。
package all

import (
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/recon/fingerprint"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/recon/github"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/recon/http"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/recon/icp"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/recon/recon"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/recon/spacemap"
)

// RegisterHTTP registers the HTTP capability only.
func RegisterHTTP(reg *core.Registry) error {
	kit := http.New(core.Deps{})
	return reg.Add(core.Spec{Manifest: kit.Manifest(), New: http.NewCapability})
}

// RegisterFingerprint registers the fingerprint detection tool. The runtime
// must supply an HTTPDoer; rules come from Deps.Fingerprints when the host
// already built a *fingerprint.Provider.
func RegisterFingerprint(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: fingerprint.Manifest(), New: fingerprint.NewCapability})
}

// RegisterSpacemap registers the five-engine space-mapping kit. The runtime
// must be given a Fetcher; keys come from resolvers, settings or env.
func RegisterSpacemap(reg *core.Registry) error {
	kit := spacemap.NewClient(core.Deps{})
	return reg.Add(core.Spec{Manifest: kit.Manifest(), New: spacemap.NewCapability})
}

// RegisterICP registers the MIIT (工信部) ICP filing lookup kit. The runtime
// must be given a Fetcher (beian.miit.gov.cn is an external data source).
func RegisterICP(reg *core.Registry) error {
	kit := icp.New(core.Deps{})
	return reg.Add(core.Spec{Manifest: kit.Manifest(), New: icp.NewCapability})
}

// RegisterGithub registers the GitHub secret-search kit. The runtime must be
// given a Fetcher and Settings with github.token.
func RegisterGithub(reg *core.Registry) error {
	kit := github.New(core.Deps{})
	return reg.Add(core.Spec{Manifest: kit.Manifest(), New: github.NewCapability})
}

// RegisterReconPipeline registers the reconnaissance pipeline. The host must
// wire providers and an AssetSink into the capability after construction.
//
// 原名 RegisterRecon：域聚合入口引入后，reconkit 专用注册让名为
// RegisterReconPipeline——pipeline 需要 host 注入 AssetSink，不进
// RegisterRecon 聚合（缺 sink 时注册成功但调用只会 tool_missing）。
func RegisterReconPipeline(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: recon.Manifest(), New: recon.NewCapability})
}

// RegisterRecon registers the whole recon domain: http / fingerprint /
// spacemap / icp / github. 只依赖出网/情报端口；recon pipeline 不在其中
// （见 RegisterReconPipeline）。
func RegisterRecon(reg *core.Registry) error {
	aggregates := []func(*core.Registry) error{
		RegisterHTTP, RegisterFingerprint, RegisterSpacemap, RegisterICP, RegisterGithub,
	}
	for _, f := range aggregates {
		if err := f(reg); err != nil {
			return err
		}
	}
	return nil
}
