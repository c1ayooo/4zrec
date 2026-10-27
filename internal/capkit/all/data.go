// data 域：数据与情报面——凭据核验、云资产、企业关系、登录态、外部 CLI
// 输出结构化。出网全部走 fetcher/http 端口，凭据每调用自带、宿主不留存。
package all

import (
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/data/binding"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/data/cloud"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/data/cred"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/data/enterprise"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/data/identity"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/data/toolparse"
)

// RegisterCred registers the credential-use kit (cloud AK/SK, db, ssh live
// verification). The runtime must be given a Fetcher (for cloud verification;
// proxy/timeout/rate/audit policy applies). db/ssh probes are direct TCP/SSH and
// rely on the host's target authorization gate.
func RegisterCred(reg *core.Registry) error {
	kit := cred.New(nil)
	return reg.Add(core.Spec{Manifest: kit.Manifest(), New: cred.NewCapability})
}

// RegisterCloud registers the five cloud-asset tools (cloud_ak_verify,
// cloud_asset_list, cloud_iam_list, cloud_storage_list, cloud_run_command). The
// runtime must supply an HTTPDoer; credentials arrive per call and are never
// retained, and every vendor request stays behind the host's scope/rate/audit
// gates. cloud_run_command is high risk and therefore approval-gated.
//
// Provider coverage is honest rather than uniform: AWS, Alibaba and Tencent
// implement all five; Huawei implements verify, asset listing and IAM listing,
// and reports cloud_storage_list / cloud_run_command as unsupported because the
// OBS SDK and the ECS cloud-assistant API are outside huaweicloud-sdk-go-v3.
func RegisterCloud(reg *core.Registry) error {
	kit := cloud.New(core.Deps{})
	return reg.Add(core.Spec{Manifest: kit.Manifest(), New: cloud.NewCapability})
}

// RegisterBinding registers the fingerprint-to-template binding kit. It needs
// no port: the binding table travels with the call.
func RegisterBinding(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: binding.Manifest(), New: binding.NewCapability})
}

// RegisterToolParse registers the external-CLI output parsers.
func RegisterToolParse(reg *core.Registry) error {
	return reg.Add(core.Spec{Manifest: toolparse.Manifest(), New: toolparse.NewCapability})
}

// RegisterEnterprise registers the enterprise-data-source tools. The resolver
// is host-supplied (it resolves cookies/keys from the host's session vault), so
// this helper takes it explicitly rather than reading it from core.Deps.
// 带宿主参数，不进 RegisterData 聚合。
func RegisterEnterprise(reg *core.Registry, resolver enterprise.ProviderResolver) error {
	kit := enterprise.NewKit(resolver)
	return reg.Add(core.Spec{
		Manifest: kit.Manifest(),
		New:      func(core.Deps) (core.Capability, error) { return kit, nil },
	})
}

// RegisterIdentity registers the three identity tools (identity_login,
// identity_csrf, identity_token_check). The flow registry is host-supplied, so
// this helper takes it explicitly rather than reading it from core.Deps — the
// same reason RegisterEnterprise takes a resolver.
//
// A host assembles site logins on the registry and hands it here; identity_login
// then resolves the agent's `kind` against it. An empty registry is legal: the
// tools still register, and identity_login reports the kind as unregistered
// instead of pretending to log in. The kit also needs an HTTPDoer
// (Manifest.Requires "http") for identity_csrf.
// 带宿主参数，不进 RegisterData 聚合。
func RegisterIdentity(reg *core.Registry, flows *identity.AuthFlowRegistry) error {
	if flows == nil {
		flows = identity.NewAuthFlowRegistry()
	}
	return reg.Add(core.Spec{
		Manifest: identity.Manifest(),
		New: func(deps core.Deps) (core.Capability, error) {
			return identity.NewCapabilityWithFlows(deps, flows)
		},
	})
}

// RegisterData registers the data domain's host-arg-free kits: cred / cloud /
// binding / toolparse。enterprise 与 identity 需要宿主注入的
// resolver/flows（core.Deps 装不下），保持显式参数签名单独注册。
func RegisterData(reg *core.Registry) error {
	aggregates := []func(*core.Registry) error{
		RegisterCred, RegisterCloud, RegisterBinding, RegisterToolParse,
	}
	for _, f := range aggregates {
		if err := f(reg); err != nil {
			return err
		}
	}
	return nil
}
