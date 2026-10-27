// Deprecated: 迁移到 kits/data/cred，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package credkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/data/cred"

type (
	DBProbeInput   = cred.DBProbeInput
	DBProbeResult  = cred.DBProbeResult
	Kit            = cred.Kit
	SSHProbeInput  = cred.SSHProbeInput
	SSHProbeResult = cred.SSHProbeResult
	VerifyResult   = cred.VerifyResult
)

const (
	ProviderAWS        = cred.ProviderAWS
	ProviderAliyun     = cred.ProviderAliyun
	ProviderHuawei     = cred.ProviderHuawei
	ProviderTencent    = cred.ProviderTencent
	ProviderVolc       = cred.ProviderVolc
	StatusInvalid      = cred.StatusInvalid
	StatusRestricted   = cred.StatusRestricted
	StatusUnverifiable = cred.StatusUnverifiable
	StatusValid        = cred.StatusValid
)

var (
	ErrNotFound          = cred.ErrNotFound
	Providers            = cred.Providers
	CloudEndpoints       = cred.CloudEndpoints
	DefaultDBPort        = cred.DefaultDBPort
	LooksLikePlaceholder = cred.LooksLikePlaceholder
	MaskKey              = cred.MaskKey
	New                  = cred.New
	NewCapability        = cred.NewCapability
	ValidProvider        = cred.ValidProvider
	VerifyDB             = cred.VerifyDB
	VerifySSH            = cred.VerifySSH
)
